import { ExecutionContext, HttpStatus } from '@nestjs/common';
import { beforeAll, afterAll, beforeEach, afterEach, describe, expect, jest, test } from '@jest/globals';
import type { RedisService } from '@modules/redis/services/redis.service';
import { RateLimitGuard } from './rate-limit.guard';

function makeContext(req: any, res: any): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
    getHandler: () => undefined,
    getClass: () => undefined,
  } as unknown as ExecutionContext;
}

/** In-memory stand-in for Redis INCR/EXPIRE/TTL behavior (tests only). */
function createRedisMock(defaultTtl = 60): RedisService {
  const keys = new Map<string, { count: number; ttl: number }>();
  return {
    incr: jest.fn(async (key: string) => {
      let e = keys.get(key);
      if (!e) {
        e = { count: 0, ttl: defaultTtl };
        keys.set(key, e);
      }
      e.count += 1;
      return e.count;
    }),
    expire: jest.fn(async (key: string, sec: number) => {
      const e = keys.get(key);
      if (e) e.ttl = sec;
      return true;
    }),
    ttl: jest.fn(async (key: string) => {
      const e = keys.get(key);
      return e ? e.ttl : -2;
    }),
  } as unknown as RedisService;
}

describe('RateLimitGuard (Redis)', () => {
  let guard: RateLimitGuard;
  const oldEnv: Record<string, string | undefined> = {};

  beforeAll(() => {
    oldEnv.RATE_LIMIT_GLOBAL = process.env.RATE_LIMIT_GLOBAL;
    oldEnv.RATE_LIMIT_WINDOW_SEC = process.env.RATE_LIMIT_WINDOW_SEC;
    oldEnv.RATE_LIMIT_SENSITIVE = process.env.RATE_LIMIT_SENSITIVE;
    oldEnv.RATE_LIMIT_SENSITIVE_WINDOW_SEC = process.env.RATE_LIMIT_SENSITIVE_WINDOW_SEC;
    oldEnv.TRUSTED_PROXIES = process.env.TRUSTED_PROXIES;

    process.env.RATE_LIMIT_GLOBAL = '2';
    process.env.RATE_LIMIT_WINDOW_SEC = '60';
    process.env.RATE_LIMIT_SENSITIVE = '1';
    process.env.RATE_LIMIT_SENSITIVE_WINDOW_SEC = '60';
    process.env.TRUSTED_PROXIES = '';
  });

  afterAll(() => {
    process.env.RATE_LIMIT_GLOBAL = oldEnv.RATE_LIMIT_GLOBAL;
    process.env.RATE_LIMIT_WINDOW_SEC = oldEnv.RATE_LIMIT_WINDOW_SEC;
    process.env.RATE_LIMIT_SENSITIVE = oldEnv.RATE_LIMIT_SENSITIVE;
    process.env.RATE_LIMIT_SENSITIVE_WINDOW_SEC = oldEnv.RATE_LIMIT_SENSITIVE_WINDOW_SEC;
    process.env.TRUSTED_PROXIES = oldEnv.TRUSTED_PROXIES;
  });

  beforeEach(() => {
    guard = new RateLimitGuard(createRedisMock(60));
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('enforces global per-IP limit and sets headers', async () => {
    const res = { setHeader: jest.fn() };
    const req = { path: '/auth/ping', method: 'GET', headers: {}, ip: '1.2.3.4', body: {} };

    const ctx = makeContext(req, res);

    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);

    const outcome1 = await Promise.resolve(guard.canActivate(ctx)).then(
      v => ({ v }),
      e => ({ e })
    );
    if ('e' in outcome1) {
      expect((outcome1.e as { getStatus(): number }).getStatus()).toBe(HttpStatus.TOO_MANY_REQUESTS);
    } else {
      throw new Error('Expected rate limit to trigger (HttpException)');
    }

    expect(res.setHeader).toHaveBeenCalled();
  });

  test('enforces sensitive email limit for POST /auth/login', async () => {
    const res = { setHeader: jest.fn() };
    const req = {
      originalUrl: '/api/v1/auth/login',
      path: '/auth/login',
      method: 'POST',
      headers: {},
      ip: '1.2.3.4',
      body: { email: 'test@example.com' },
    };

    const ctx = makeContext(req, res);

    await expect(guard.canActivate(ctx)).resolves.toBe(true);

    const outcome2 = await Promise.resolve(guard.canActivate(ctx)).then(
      v => ({ v }),
      e => ({ e })
    );
    if ('e' in outcome2) {
      expect((outcome2.e as { getStatus(): number }).getStatus()).toBe(HttpStatus.TOO_MANY_REQUESTS);
    } else {
      throw new Error('Expected sensitive rate limit to trigger (HttpException)');
    }

    expect(res.setHeader).toHaveBeenCalled();
  });

  test('does not rate-limit paths that only look like auth (e.g. /authenticate)', async () => {
    const res = { setHeader: jest.fn() };
    const req = {
      originalUrl: '/api/v1/authenticate/callback',
      path: '/authenticate/callback',
      method: 'GET',
      headers: {},
      ip: '9.9.9.9',
      body: {},
    };
    const ctx = makeContext(req, res);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(res.setHeader).not.toHaveBeenCalled();
  });
});
