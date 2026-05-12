import { ExecutionContext, HttpStatus } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { AuthGuard } from './auth.guard';
import { RedisService } from '@modules/redis/services/redis.service';
import UserService from '@modules/user/user.service';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import * as SYS_MSG from '@shared/constants/SystemMessages';

const mockJwtService = { verifyAsync: jest.fn() };
const mockReflector = { getAllAndOverride: jest.fn() };
const mockRedisService = { get: jest.fn() };
const mockUserService = { getUserById: jest.fn() };

const VALID_PAYLOAD = { sub: 'user-123', sessionId: 'sess-abc' };
const ACTIVE_USER = { id: 'user-123', deleted_at: null, is_active: true };
const SESSION_DATA = JSON.stringify({ ip: '127.0.0.1', ua: 'jest' });

function buildContext(authHeader?: string): {
  ctx: ExecutionContext;
  request: Record<string, unknown>;
} {
  const request: Record<string, unknown> = {
    headers: { authorization: authHeader },
  };

  const ctx = {
    switchToHttp: () => ({ getRequest: () => request }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;

  return { ctx, request };
}

function bearerHeader(token: string) {
  return `Bearer ${token}`;
}

describe('AuthGuard', () => {
  let guard: AuthGuard;

  beforeEach(async () => {
    jest.clearAllMocks();

    // Default: private route
    mockReflector.getAllAndOverride.mockReturnValue(false);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthGuard,
        { provide: JwtService, useValue: mockJwtService },
        { provide: Reflector, useValue: mockReflector },
        { provide: RedisService, useValue: mockRedisService },
        { provide: UserService, useValue: mockUserService },
      ],
    }).compile();

    guard = module.get<AuthGuard>(AuthGuard);
  });

  // Public routes

  describe('public routes', () => {
    it('returns true immediately without inspecting the token', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(true);
      const { ctx } = buildContext(); // no token at all

      await expect(guard.canActivate(ctx)).resolves.toBe(true);
      expect(mockJwtService.verifyAsync).not.toHaveBeenCalled();
    });
  });

  // Token extraction

  describe('token extraction', () => {
    it('throws 401 when Authorization header is absent', async () => {
      const { ctx } = buildContext();

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
      await expect(guard.canActivate(ctx)).rejects.toMatchObject({
        status: HttpStatus.UNAUTHORIZED,
      });
    });

    it('throws 401 when scheme is not Bearer', async () => {
      const { ctx } = buildContext('Basic somebase64value');

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('throws 401 when header is "Bearer" with no token string', async () => {
      const { ctx } = buildContext('Bearer ');

      mockJwtService.verifyAsync.mockResolvedValue(null);

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });
  });

  // JWT validation

  describe('JWT validation', () => {
    it('throws 401 when verifyAsync rejects (tampered / expired token)', async () => {
      mockJwtService.verifyAsync.mockRejectedValue(new Error('jwt expired'));
      const { ctx } = buildContext(bearerHeader('expired.jwt.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('throws 401 when verifyAsync resolves to null (catch returns null)', async () => {
      mockJwtService.verifyAsync.mockResolvedValue(null);
      const { ctx } = buildContext(bearerHeader('bad.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('throws 401 when payload is missing sessionId', async () => {
      mockJwtService.verifyAsync.mockResolvedValue({ sub: 'user-123' }); // no sessionId
      const { ctx } = buildContext(bearerHeader('no-session.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('throws 401 when payload is missing sub (userId)', async () => {
      mockJwtService.verifyAsync.mockResolvedValue({ sessionId: 'sess-abc' }); // no sub
      mockRedisService.get.mockResolvedValue(null); // session won't exist

      const { ctx } = buildContext(bearerHeader('no-sub.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });
  });

  // Redis session validation

  describe('Redis session validation', () => {
    it('throws 401 when session key does not exist in Redis (get returns null)', async () => {
      mockJwtService.verifyAsync.mockResolvedValue(VALID_PAYLOAD);
      mockRedisService.get.mockResolvedValue(null);

      const { ctx } = buildContext(bearerHeader('valid.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('throws 401 when Redis is unreachable (get returns null after error)', async () => {
      mockJwtService.verifyAsync.mockResolvedValue(VALID_PAYLOAD);
      // RedisService.get swallows the error and returns null — guard must fail-closed
      mockRedisService.get.mockResolvedValue(null);

      const { ctx } = buildContext(bearerHeader('valid.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('constructs the session key as sess:{userId}:{sessionId}', async () => {
      mockJwtService.verifyAsync.mockResolvedValue(VALID_PAYLOAD);
      mockRedisService.get.mockResolvedValue(null);

      const { ctx } = buildContext(bearerHeader('valid.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow();
      expect(mockRedisService.get).toHaveBeenCalledWith(
        `sess:${VALID_PAYLOAD.sub}:${VALID_PAYLOAD.sessionId}`,
      );
    });
  });

  // User validation

  describe('user validation', () => {
    beforeEach(() => {
      mockJwtService.verifyAsync.mockResolvedValue(VALID_PAYLOAD);
      mockRedisService.get.mockResolvedValue(SESSION_DATA);
    });

    it('throws 401 when user is not found in DB', async () => {
      mockUserService.getUserById.mockResolvedValue(null);
      const { ctx } = buildContext(bearerHeader('valid.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('throws 401 when getUserById rejects (DB error)', async () => {
      mockUserService.getUserById.mockRejectedValue(new Error('DB down'));
      const { ctx } = buildContext(bearerHeader('valid.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('throws 401 when user is soft-deleted (deleted_at is set)', async () => {
      mockUserService.getUserById.mockResolvedValue({
        ...ACTIVE_USER,
        deleted_at: new Date('2024-01-01'),
      });
      const { ctx } = buildContext(bearerHeader('valid.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('throws 401 when user is deactivated (is_active = false)', async () => {
      mockUserService.getUserById.mockResolvedValue({
        ...ACTIVE_USER,
        is_active: false,
      });
      const { ctx } = buildContext(bearerHeader('valid.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });

    it('throws 401 when user is both soft-deleted and inactive', async () => {
      mockUserService.getUserById.mockResolvedValue({
        ...ACTIVE_USER,
        deleted_at: new Date(),
        is_active: false,
      });
      const { ctx } = buildContext(bearerHeader('valid.token'));

      await expect(guard.canActivate(ctx)).rejects.toThrow(CustomHttpException);
    });
  });

  // Happy path

  describe('successful authentication', () => {
    beforeEach(() => {
      mockJwtService.verifyAsync.mockResolvedValue(VALID_PAYLOAD);
      mockRedisService.get.mockResolvedValue(SESSION_DATA);
      mockUserService.getUserById.mockResolvedValue(ACTIVE_USER);
    });

    it('returns true when all checks pass', async () => {
      const { ctx } = buildContext(bearerHeader('valid.token'));

      await expect(guard.canActivate(ctx)).resolves.toBe(true);
    });

    it('attaches the JWT payload to request.user', async () => {
      const { ctx, request } = buildContext(bearerHeader('valid.token'));

      await guard.canActivate(ctx);

      expect(request['user']).toEqual(VALID_PAYLOAD);
    });

    it('attaches parsed session data to request.session', async () => {
      const { ctx, request } = buildContext(bearerHeader('valid.token'));

      await guard.canActivate(ctx);

      expect(request['session']).toEqual(JSON.parse(SESSION_DATA));
    });

    it('attaches the raw token string to request.token', async () => {
      const { ctx, request } = buildContext(bearerHeader('valid.token'));

      await guard.canActivate(ctx);

      expect(request['token']).toBe('valid.token');
    });

    it('calls getUserById with the sub claim from the JWT', async () => {
      const { ctx } = buildContext(bearerHeader('valid.token'));

      await guard.canActivate(ctx);

      expect(mockUserService.getUserById).toHaveBeenCalledWith(VALID_PAYLOAD.sub);
    });
  });

  // Error shape

  describe('error response shape', () => {
  it('every 401 uses the UNAUTHENTICATED_MESSAGE constant', async () => {
    const { ctx } = buildContext();

    expect.assertions(3); // guarantees the catch block runs

    try {
      await guard.canActivate(ctx);
    } catch (err) {
      expect(err).toBeInstanceOf(CustomHttpException);
      const httpErr = err as CustomHttpException;
      expect(httpErr.message).toBe(SYS_MSG.UNAUTHENTICATED_MESSAGE);
      expect(httpErr.getStatus()).toBe(HttpStatus.UNAUTHORIZED);
    }
  });
});
});