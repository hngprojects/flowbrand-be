/// <reference types="jest" />
import { Test, TestingModule } from '@nestjs/testing';
import { RedisService } from '../services/redis.service';

const mockRedisInstance = {
  on: jest.fn().mockReturnThis(),
  connect: jest.fn().mockResolvedValue(undefined),
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  exists: jest.fn(),
  incr: jest.fn(),
  ttl: jest.fn(),
  expire: jest.fn(),
  scan: jest.fn(),
  disconnect: jest.fn(),
  quit: jest.fn().mockResolvedValue('OK'),
};

jest.mock('ioredis', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => mockRedisInstance),
  };
});

describe('RedisService (unit)', () => {
  let service: RedisService;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockRedisInstance.connect.mockResolvedValue(undefined);
    mockRedisInstance.on.mockReturnThis();

    const module: TestingModule = await Test.createTestingModule({
      providers: [RedisService],
    }).compile();

    service = module.get<RedisService>(RedisService);
    await service.onModuleInit();
  });

  afterEach(async () => {
    await service.onModuleDestroy();
  });

  it('set stores value without TTL', async () => {
    mockRedisInstance.set.mockResolvedValue('OK');
    await service.set('sess:user1:abc', '{"role":"user"}');
    expect(mockRedisInstance.set).toHaveBeenCalledWith('sess:user1:abc', '{"role":"user"}');
  });

  it('set stores value with TTL using EX', async () => {
    mockRedisInstance.set.mockResolvedValue('OK');
    await service.set('otp:user1:login', '123456', 300);
    expect(mockRedisInstance.set).toHaveBeenCalledWith('otp:user1:login', '123456', 'EX', 300);
  });

  it('get returns value for existing key', async () => {
    mockRedisInstance.get.mockResolvedValue('{"role":"user"}');
    expect(await service.get('sess:user1:abc')).toBe('{"role":"user"}');
  });

  it('get returns null for missing key', async () => {
    mockRedisInstance.get.mockResolvedValue(null);
    expect(await service.get('sess:ghost')).toBeNull();
  });

  it('del calls delete on correct key', async () => {
    mockRedisInstance.del.mockResolvedValue(1);
    await service.del('sess:user1:abc');
    expect(mockRedisInstance.del).toHaveBeenCalledWith('sess:user1:abc');
  });

  it('exists returns true when key present', async () => {
    mockRedisInstance.exists.mockResolvedValue(1);
    expect(await service.exists('otp:user1:login')).toBe(true);
  });

  it('exists returns false when key absent', async () => {
    mockRedisInstance.exists.mockResolvedValue(0);
    expect(await service.exists('otp:ghost')).toBe(false);
  });

  it('incr increments atomically', async () => {
    mockRedisInstance.incr.mockResolvedValueOnce(1).mockResolvedValueOnce(2);
    expect(await service.incr('rl:user1:/api/login')).toBe(1);
    expect(await service.incr('rl:user1:/api/login')).toBe(2);
  });

  it('ttl returns seconds-to-live from Redis', async () => {
    mockRedisInstance.ttl.mockResolvedValue(42);
    expect(await service.ttl('rl:user1:key')).toBe(42);
    expect(mockRedisInstance.ttl).toHaveBeenCalledWith('rl:user1:key');
  });

  it('expire sets TTL on a key', async () => {
    mockRedisInstance.expire.mockResolvedValue(1);
    expect(await service.expire('rl:user1:key', 60)).toBe(true);
    expect(mockRedisInstance.expire).toHaveBeenCalledWith('rl:user1:key', 60);
  });

  it('delByPattern scans and deletes matching keys only', async () => {
    mockRedisInstance.scan.mockResolvedValueOnce(['0', ['sess:user99:s1', 'sess:user99:s2']]);
    mockRedisInstance.del.mockResolvedValue(2);

    await service.delByPattern('sess:user99:*');

    expect(mockRedisInstance.scan).toHaveBeenCalledWith('0', 'MATCH', 'sess:user99:*', 'COUNT', 100);
    expect(mockRedisInstance.del).toHaveBeenCalledWith('sess:user99:s1', 'sess:user99:s2');
  });

  it('get returns null and logs error when Redis is down', async () => {
    mockRedisInstance.get.mockRejectedValue(new Error('Stream not writable'));
    expect(await service.get('sess:any')).toBeNull();
  });
});
