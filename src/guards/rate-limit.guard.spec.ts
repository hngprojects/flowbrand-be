import * as dotenv from 'dotenv';
import { ModuleRef } from '@nestjs/core';
import { ExecutionContext, HttpException } from '@nestjs/common';
import { afterEach, beforeAll, beforeEach, describe, expect, jest, test } from '@jest/globals';
import type { RateLimitGuard as RateLimitGuardType } from './rate-limit.guard';

dotenv.config();

// Load after env is available so the guard reads .env values at import time.

let RateLimitGuard: typeof RateLimitGuardType;

function makeContext(req: any, res: any): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
    getHandler: () => undefined,
    getClass: () => undefined,
  } as unknown as ExecutionContext;
}

describe('RateLimitGuard (in-memory fallback)', () => {
  let guard: RateLimitGuardType;
  beforeAll(async () => {
    ({ RateLimitGuard } = await import('./rate-limit.guard'));
  });

  beforeEach(() => {
    const moduleRef = { get: jest.fn().mockReturnValue(undefined) } as unknown as ModuleRef;
    guard = new RateLimitGuard(moduleRef);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  test('enforces global per-IP limit and sets headers', async () => {
    const res = { setHeader: jest.fn() };
    const req = { path: '/auth/ping', method: 'GET', headers: {}, ip: '1.2.3.4', body: {} };

    const ctx = makeContext(req, res);

    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(HttpException);

    expect(res.setHeader).toHaveBeenCalled();
  });

  test('enforces sensitive email limit for POST /auth/login', async () => {
    const res = { setHeader: jest.fn() };
    const req = {
      path: '/auth/login',
      method: 'POST',
      headers: {},
      ip: '1.2.3.4',
      body: { email: 'test@example.com' },
    };

    const ctx = makeContext(req, res);

    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(HttpException);

    expect(res.setHeader).toHaveBeenCalled();
  });
});
