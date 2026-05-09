import { Injectable, CanActivate, ExecutionContext, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { RedisService } from '@modules/redis/services/redis.service';

/**
 * RateLimitGuard
 *
 * - Uses the application Redis (RedisService) for counters and TTLs.
 * - If Redis operations fail, responds with 503 so limits are not silently bypassed.
 * - Env values are read at runtime (via getters) so tests can set `process.env` before use.
 * - Only applies to URLs whose path contains an `auth` segment (e.g. /api/v1/auth/login), not /authenticate.
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

  /** Strip IPv4-mapped IPv6 prefix; trim. Trusted list entries must match literally (no CIDR yet). */
  private normalizeIp(value: string): string {
    if (!value) return '';
    const trimmed = value.trim();
    if (trimmed.startsWith('::ffff:')) return trimmed.slice(7);
    return trimmed;
  }

  /**
   * Prefer the socket peer for trust checks. Only read X-Forwarded-For when the immediate peer is listed in
   * TRUSTED_PROXIES, so arbitrary clients cannot spoof the header to bypass per-IP limits.
   */
  private getIpFromRequest(req: any): string {
    const trusted = (process.env.TRUSTED_PROXIES || '')
      .split(',')
      .map(s => this.normalizeIp(s))
      .filter(Boolean);
    const forwarded = req.headers?.['x-forwarded-for'];
    const socketRemote = this.normalizeIp(req.socket?.remoteAddress || req.connection?.remoteAddress || '');
    const remote = socketRemote || this.normalizeIp(String(req.ip || ''));
    const isTrustedProxy = socketRemote !== '' && trusted.includes(socketRemote);

    if (forwarded && isTrustedProxy) {
      const forwardedIp = this.normalizeIp(String(forwarded).split(',')[0]);
      return forwardedIp || remote;
    }
    return remote;
  }

  /** Pathname without query; prefers Express full path so global prefix (e.g. api/v1) is visible. */
  private pathnameFromRequest(req: any): string {
    const raw = String(req.originalUrl ?? req.url ?? req.path ?? '');
    return raw.split('?')[0] || '';
  }

  private pathSegments(pathname: string): string[] {
    return pathname.split('/').filter(Boolean);
  }

  /** True when URL contains an `auth` path segment (matches /api/v1/auth/..., not /authenticate). */
  private isAuthNamespacePath(pathname: string): boolean {
    return this.pathSegments(pathname).includes('auth');
  }

  /** POST …/auth/login|register|forgot-password (works with or without global prefix). */
  private isSensitiveAuthRoute(req: any): boolean {
    if (req.method !== 'POST') return false;
    const segments = this.pathSegments(this.pathnameFromRequest(req));
    const i = segments.indexOf('auth');
    if (i < 0 || i >= segments.length - 1) return false;
    const action = segments[i + 1];
    return action === 'login' || action === 'register' || action === 'forgot-password';
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const ctx = context.switchToHttp();
    const req = ctx.getRequest();
    const res = ctx.getResponse();

    if (!req || !res) return true;

    const pathname = this.pathnameFromRequest(req);
    if (!this.isAuthNamespacePath(pathname)) return true;

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

    if (this.isSensitiveAuthRoute(req)) {
      const body = req.body || {};
      const email = (body.email || body.username || body.identifier || '').toString().toLowerCase().trim();
      const sensitiveKeyBase = email ? `ratelimit:email:${email}` : `ratelimit:ip:${ip}`;
      const segments = this.pathSegments(pathname);
      const authIdx = segments.indexOf('auth');
      const action = authIdx >= 0 && segments[authIdx + 1] ? segments[authIdx + 1] : 'login';
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
