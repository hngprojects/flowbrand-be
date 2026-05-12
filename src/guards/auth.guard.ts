import { CanActivate, ExecutionContext, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import appConfig from '@config/auth.config';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { IS_PUBLIC_KEY } from '@shared/helpers/skipAuth';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { RedisService } from '@modules/redis/services/redis.service';
import UserService from '@modules/user/user.service';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);
  constructor(
    private jwtService: JwtService,
    private reflector: Reflector,
    private redisService: RedisService,
    private userService: UserService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    const isPublicRoute = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublicRoute) {
      return true;
    }

    if (!token) {
      throw new CustomHttpException(SYS_MSG.UNAUTHENTICATED_MESSAGE, HttpStatus.UNAUTHORIZED);
    }

    const payload = await this.jwtService
      .verifyAsync(token, {
        secret: appConfig().jwtSecret,
      })
      .catch(err => null);

    if (!payload) throw new CustomHttpException(SYS_MSG.UNAUTHENTICATED_MESSAGE, HttpStatus.UNAUTHORIZED);

    const { sessionId, sub: userId } = payload;

    if (!sessionId) {
      throw new CustomHttpException(SYS_MSG.UNAUTHENTICATED_MESSAGE, HttpStatus.UNAUTHORIZED);
    }

    const sessionKey = `sess:${userId}:${sessionId}`;

    const sessionData = await this.redisService.get(sessionKey);

    if (!sessionData) {
      this.logger.warn('Session not found or Redis unreachable');
      throw new CustomHttpException(SYS_MSG.UNAUTHENTICATED_MESSAGE, HttpStatus.UNAUTHORIZED);
    }

    const user = await this.userService.getUserById(userId).catch(() => null);
    if (!user || user.deleted_at !== null || !user.is_active) {
      throw new CustomHttpException(SYS_MSG.UNAUTHENTICATED_MESSAGE, HttpStatus.UNAUTHORIZED);
    }

    request['user'] = payload;
    request['session'] = JSON.parse(sessionData);
    request['token'] = token;

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
