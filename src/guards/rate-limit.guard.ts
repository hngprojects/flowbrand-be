import { Injectable, CanActivate, ExecutionContext, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';

type RedisLike = {
  incr(key: string): Promise<number>;
  ttl(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
};

const DEFAULT_GLOBAL_LIMIT = Number(process.env.RATE_LIMIT_GLOBAL) || 100;
const DEFAULT_WINDOW_SEC = Number(process.env.RATE_LIMIT_WINDOW_SEC) || 15 * 60;
const DEFAULT_SENSITIVE_LIMIT = Number(process.env.RATE_LIMIT_SENSITIVE) || 5;
const SENSITIVE_WINDOW_SEC = Number(process.env.RATE_LIMIT_SENSITIVE_WINDOW_SEC) || 15 * 60;

@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);
  private redisClient: RedisLike | null = null;
  private readonly inMemory = new Map<string, { count: number; reset: number }>();

  constructor(private readonly moduleRef: ModuleRef) {}

  private async ensureRedis(): Promise<void> {
    if (this.redisClient) return;
    try {
      const candidates = ['REDIS', 'REDIS_CLIENT', 'RedisService', 'IoredisClient'];
      for (const token of candidates) {
        try {
          // @ts-ignore
          const client = this.moduleRef.get(token, { strict: false });
          if (client) {
            this.redisClient = client as RedisLike;
            this.logger.log(`RateLimitGuard: using Redis provider "${token}"`);
            return;
          }
        } catch (err) {
          // ignore and try next
        }
      }
      this.logger.warn('RateLimitGuard: no Redis provider found; using in-memory fallback (non-persistent)');
    } catch (err) {
      this.logger.error('RateLimitGuard: error while trying to resolve Redis client', err as any);
      this.redisClient = null;
    }
  }

  private async incrementKey(
    key: string,
    windowSec: number
  ): Promise<{ count: number; ttl: number; usingRedis: boolean }> {
    await this.ensureRedis();
    if (this.redisClient) {
      try {
        const count = await this.redisClient.incr(key);
        if (count === 1) {
          await this.redisClient.expire(key, windowSec);
        }
        let ttl = await this.redisClient.ttl(key);
        if (ttl < 0) ttl = windowSec;
        return { count, ttl, usingRedis: true };
      } catch (err) {
        this.logger.error('RateLimitGuard: Redis error, falling back to in-memory (fail-open)', err as any);
        this.redisClient = null;
      }
    }

    const now = Date.now();
    const cur = this.inMemory.get(key);
    if (!cur || cur.reset <= now) {
      const reset = now + windowSec * 1000;
      this.inMemory.set(key, { count: 1, reset });
      return { count: 1, ttl: windowSec, usingRedis: false };
    }
    cur.count += 1;
    this.inMemory.set(key, cur);
    const ttl = Math.max(0, Math.ceil((cur.reset - now) / 1000));
    return { count: cur.count, ttl, usingRedis: false };
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
    const global = await this.incrementKey(ipKey, DEFAULT_WINDOW_SEC);
    const globalRemaining = Math.max(0, DEFAULT_GLOBAL_LIMIT - global.count);
    const nowSec = Math.floor(Date.now() / 1000);
    const globalReset = nowSec + global.ttl;
    try {
      res.setHeader('X-RateLimit-Limit', String(DEFAULT_GLOBAL_LIMIT));
      res.setHeader('X-RateLimit-Remaining', String(globalRemaining));
      res.setHeader('X-RateLimit-Reset', String(globalReset));
    } catch (err) {
      // ignore
    }

    if (global.count > DEFAULT_GLOBAL_LIMIT) {
      const retryAfter = global.ttl;
      res.setHeader('Retry-After', String(retryAfter));
      throw new HttpException('Too Many Requests', HttpStatus.TOO_MANY_REQUESTS);
    }

    const isSensitive =
      req.method === 'POST' && ['/auth/login', '/auth/register', '/auth/forgot-password'].includes(path);
    if (isSensitive) {
      const body = req.body || {};
      const email = (body.email || body.username || body.identifier || '').toString().toLowerCase().trim();
      const sensitiveKeyBase = email ? `ratelimit:${email}` : `ratelimit:ip:${ip}`;
      const action = path.split('/').pop() || 'login';
      const sensitiveKey = `${sensitiveKeyBase}:${action}`;

      const sensitive = await this.incrementKey(sensitiveKey, SENSITIVE_WINDOW_SEC);
      const sensitiveRemaining = Math.max(0, DEFAULT_SENSITIVE_LIMIT - sensitive.count);
      const sensitiveReset = nowSec + sensitive.ttl;

      try {
        res.setHeader('X-RateLimit-Limit-Email', String(DEFAULT_SENSITIVE_LIMIT));
        res.setHeader('X-RateLimit-Remaining-Email', String(sensitiveRemaining));
        res.setHeader('X-RateLimit-Reset-Email', String(sensitiveReset));
      } catch (err) {
        // ignore
      }

      if (sensitive.count > DEFAULT_SENSITIVE_LIMIT) {
        const retryAfter = sensitive.ttl;
        res.setHeader('Retry-After', String(retryAfter));
        throw new HttpException('Too Many Requests', HttpStatus.TOO_MANY_REQUESTS);
      }
    }

    return true;
  }
}
