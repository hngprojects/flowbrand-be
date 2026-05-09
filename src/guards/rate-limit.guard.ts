import { Injectable, CanActivate, ExecutionContext, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { RedisService } from '@modules/redis/services/redis.service';

/**
 * RateLimitGuard
 *
 * - Uses the application Redis (RedisService) for counters and TTLs.
 * - If Redis operations fail, responds with 503 so limits are not silently bypassed.
 * - Env values are read at runtime (via getters) so tests can set `process.env` before use.
 * - Adds standard X-RateLimit headers and `Retry-After` on 429 responses.
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);

  constructor(private readonly redis: RedisService) {}

  private get globalLimit(): number {
    return Number(process.env.RATE_LIMIT_GLOBAL) || 100;
  }

  private get windowSec(): number {
    return Number(process.env.RATE_LIMIT_WINDOW_SEC) || 15 * 60;
  }

  private get sensitiveLimit(): number {
    return Number(process.env.RATE_LIMIT_SENSITIVE) || 5;
  }

  private get sensitiveWindowSec(): number {
    return Number(process.env.RATE_LIMIT_SENSITIVE_WINDOW_SEC) || 15 * 60;
  }

  private async incrementKey(key: string, windowSec: number): Promise<{ count: number; ttl: number }> {
    const count = await this.redis.incr(key);
    if (count === null) {
      this.logger.error(`RateLimitGuard: Redis INCR failed for key ${key}`);
      throw new HttpException('Rate limiting temporarily unavailable', HttpStatus.SERVICE_UNAVAILABLE);
    }
    if (count === 1) {
      const ok = await this.redis.expire(key, windowSec);
      if (!ok) {
        this.logger.error(`RateLimitGuard: Redis EXPIRE failed for key ${key}`);
        throw new HttpException('Rate limiting temporarily unavailable', HttpStatus.SERVICE_UNAVAILABLE);
      }
    }
    const rawTtl = await this.redis.ttl(key);
    const ttl = typeof rawTtl === 'number' && rawTtl >= 0 ? rawTtl : windowSec;
    return { count, ttl };
  }

  private getIpFromRequest(req: any): string {
    const trusted = (process.env.TRUSTED_PROXIES || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    const forwarded = req.headers?.['x-forwarded-for'];
    const remote = req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || '';
    if (forwarded && trusted.length > 0) {
      const forwardedIp = String(forwarded).split(',')[0].trim();
      return forwardedIp || remote;
    }
    return remote;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const ctx = context.switchToHttp();
    const req = ctx.getRequest();
    const res = ctx.getResponse();

    if (!req || !res) return true;

    const path: string = req.path || req.url || '';
    if (!path.startsWith('/auth')) return true;

    const ip = this.getIpFromRequest(req) || 'unknown';

    const ipKey = `ratelimit:ip:${ip}:global`;
    const global = await this.incrementKey(ipKey, this.windowSec);
    const globalRemaining = Math.max(0, this.globalLimit - global.count);
    const nowSec = Math.floor(Date.now() / 1000);
    const globalReset = nowSec + global.ttl;

    try {
      res.setHeader('X-RateLimit-Limit', String(this.globalLimit));
      res.setHeader('X-RateLimit-Remaining', String(globalRemaining));
      res.setHeader('X-RateLimit-Reset', String(globalReset));
    } catch {
      /* ignore header errors */
    }

    if (global.count > this.globalLimit) {
      const retryAfter = global.ttl;
      try {
        res.setHeader('Retry-After', String(retryAfter));
      } catch {
        /* ignore header errors */
      }
      throw new HttpException('Too Many Requests', HttpStatus.TOO_MANY_REQUESTS);
    }

    const isSensitive =
      req.method === 'POST' && ['/auth/login', '/auth/register', '/auth/forgot-password'].includes(path);
    if (isSensitive) {
      const body = req.body || {};
      const email = (body.email || body.username || body.identifier || '').toString().toLowerCase().trim();
      const sensitiveKeyBase = email ? `ratelimit:email:${email}` : `ratelimit:ip:${ip}`;
      const action = path.split('/').pop() || 'login';
      const sensitiveKey = `${sensitiveKeyBase}:${action}`;

      const sensitive = await this.incrementKey(sensitiveKey, this.sensitiveWindowSec);
      const sensitiveRemaining = Math.max(0, this.sensitiveLimit - sensitive.count);
      const sensitiveReset = nowSec + sensitive.ttl;

      try {
        res.setHeader('X-RateLimit-Limit-Email', String(this.sensitiveLimit));
        res.setHeader('X-RateLimit-Remaining-Email', String(sensitiveRemaining));
        res.setHeader('X-RateLimit-Reset-Email', String(sensitiveReset));
      } catch {
        /* ignore header errors */
      }

      if (sensitive.count > this.sensitiveLimit) {
        const retryAfter = sensitive.ttl;
        try {
          res.setHeader('Retry-After', String(retryAfter));
        } catch {
          /* ignore header errors */
        }
        throw new HttpException('Too Many Requests', HttpStatus.TOO_MANY_REQUESTS);
      }
    }

    return true;
  }
}
