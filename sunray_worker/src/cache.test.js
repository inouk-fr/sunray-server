import { describe, it, expect, beforeEach, vi } from 'vitest';
import { handleCacheRequest } from './cache.js';
import { getInvalidationTracker } from './invalidation-tracker.js';
import { getConfig, checkVersionChanges } from './config.js';

// Mock dependencies
vi.mock('./config.js', () => ({
  getConfig: vi.fn(),
  checkVersionChanges: vi.fn(),
  clearConfigCache: vi.fn()
}));

// Cache helper functions that are internal to cache.js should be mocked by mocking the cache actions
const mockCacheHelpers = {
  clearAllCaches: vi.fn(),
  clearUserSessions: vi.fn(), 
  clearHostConfig: vi.fn()
};

vi.mock('./invalidation-tracker.js', () => ({
  getInvalidationTracker: vi.fn(),
  InvalidationTracker: vi.fn()
}));

describe('Cache Management API', () => {
  let mockEnv;
  let mockRequest;
  let mockTracker;

  beforeEach(() => {
    vi.clearAllMocks();

    // Mock KV store
    const kvStore = new Map();
    mockEnv = {
      KV: {
        get: vi.fn(async (key) => kvStore.get(key)),
        put: vi.fn(async (key, value) => kvStore.set(key, value)),
        delete: vi.fn(async (key) => kvStore.delete(key)),
        list: vi.fn(async (options) => {
          const keys = Array.from(kvStore.keys())
            .filter(k => !options.prefix || k.startsWith(options.prefix))
            .slice(0, options.limit || 1000);
          return { keys: keys.map(name => ({ name })) };
        })
      },
      CONFIG_CACHE: {
        get: vi.fn(async (key) => kvStore.get(key)),
        put: vi.fn(async (key, value) => kvStore.set(key, value)),
        delete: vi.fn(async (key) => kvStore.delete(key))
      },
      CONTROL_SIGNALS: {
        get: vi.fn(async (key) => kvStore.get(key)),
        put: vi.fn(async (key, value, opts) => kvStore.set(key, value)),
        delete: vi.fn(async (key) => kvStore.delete(key))
      },
      SESSIONS: {
        get: vi.fn(async (key) => kvStore.get(key)),
        put: vi.fn(async (key, value, opts) => kvStore.set(key, value)),
        delete: vi.fn(async (key) => kvStore.delete(key))
      },
      WORKER_ID: 'test-worker-123',
      ADMIN_API_KEY: 'valid-token',
      SESSION_SECRET: 'test-secret'
    };

    // Mock InvalidationTracker
    mockTracker = {
      hasProcessed: vi.fn().mockReturnValue(false),
      markProcessed: vi.fn(),
      getProcessedCount: vi.fn().mockReturnValue(5),
      getLastInvalidation: vi.fn().mockReturnValue('2025-01-14T10:00:00Z'),
      processSignal: vi.fn().mockResolvedValue(true)
    };
    getInvalidationTracker.mockReturnValue(mockTracker);

    // Mock config
    getConfig.mockResolvedValue({
      exists: true,
      data: { hosts: [], users: [] },
      versions: {
        config_version: '2025-01-14T10:00:00Z',
        host_versions: {},
        user_versions: {}
      }
    });
  });

  describe('GET /cache - Status endpoint', () => {
    it('should return cache status', async () => {
      // Setup cached data in CONFIG_CACHE
      const cacheData = {
        data: { hosts: [], users: [] },
        timestamp: Date.now() - 30000, // 30 seconds old
        ttl: 300000,
        versions: {
          config_version: '2025-01-14T10:00:00Z',
          last_version_check: Date.now() - 10000
        }
      };
      
      // Mock CONFIG_CACHE.get to return the cached data
      mockEnv.CONFIG_CACHE.get.mockResolvedValue(cacheData);

      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-token'
        }
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'GET', '/sunray-wrkr/v1/cache');
      const result = await response.json();

      expect(response.status).toBe(200);
      expect(result.worker_id).toBe('test-worker-123');
      expect(result.caches.config.exists).toBe(true);
      expect(result.caches.config.age_seconds).toBeGreaterThan(29);
      expect(result.caches.config.age_seconds).toBeLessThan(31);
      expect(result.invalidation_tracker.processed_count).toBe(5);
    });

    it('should handle empty cache', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-token'
        }
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'GET', '/sunray-wrkr/v1/cache');
      const result = await response.json();

      expect(response.status).toBe(200);
      expect(result.caches.config.exists).toBe(false);
    });
  });

  describe('POST /cache/invalidate - Invalidation endpoint', () => {
    it('should trigger global invalidation', async () => {
      checkVersionChanges.mockResolvedValue();

      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/invalidate', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scope: 'global',
          reason: 'Manual refresh'
        })
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/invalidate');
      const result = await response.json();

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.message).toContain('Invalidation signal set');
      expect(result.scope).toBe('global');
    });

    it('should trigger user-specific invalidation', async () => {
      checkVersionChanges.mockResolvedValue();

      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/invalidate', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scope: 'user',
          target: 'testuser',
          reason: 'User data changed'
        })
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/invalidate');
      const result = await response.json();

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.scope).toBe('user');
      expect(result.target).toBe('testuser');
      expect(result.cleared).toContain('sessions for user testuser');
    });

    it('should handle duplicate invalidation signals', async () => {
      // Mock processSignal to return false (already processed)
      mockTracker.processSignal.mockResolvedValue(false);

      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/invalidate', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scope: 'host',
          target: 'example.com',
          reason: 'Host config changed'
        })
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/invalidate');
      const result = await response.json();

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.scope).toBe('host');
      expect(result.target).toBe('example.com');
    });

    it('should validate required target for user scope', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/invalidate', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scope: 'user'
          // Missing target
        })
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/invalidate');
      const result = await response.json();

      expect(response.status).toBe(400);
      expect(result.error).toContain('Target required');
    });

    it('should validate scope values', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/invalidate', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scope: 'invalid_scope'
        })
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/invalidate');
      const result = await response.json();

      expect(response.status).toBe(400);
      expect(result.error).toContain('Invalid scope');
    });
  });

  describe('POST /cache/clear - Clear cache endpoint', () => {
    beforeEach(async () => {
      // Setup test data in KV
      await mockEnv.KV.put('config', 'config_data');
      await mockEnv.KV.put('session_user123_abc', 'session_data');
      await mockEnv.KV.put('session_user456_def', 'session_data');
    });

    it('should clear all caches', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/clear', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scope: 'all'
        })
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/clear');
      const result = await response.json();

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.cleared).toContain('all caches');
      expect(result.worker_id).toBe('test-worker-123');
    });

    it('should clear config cache only', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/clear', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scope: 'config'
        })
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/clear');
      const result = await response.json();

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.cleared).toContain('configuration cache');
      expect(result.worker_id).toBe('test-worker-123');
    });

    it('should clear sessions for specific user', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/clear', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scope: 'sessions',
          target: 'user123'
        })
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/clear');
      const result = await response.json();

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.cleared).toContain('sessions for user user123');
      expect(result.worker_id).toBe('test-worker-123');
    });

    it('should validate scope values', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/clear', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scope: 'invalid'
        })
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/clear');
      const result = await response.json();

      expect(response.status).toBe(400);
      expect(result.error).toContain('Invalid scope');
    });
  });

  describe('Authentication', () => {
    it('should reject requests without authorization', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache', {
        method: 'GET'
        // No Authorization header
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'GET', '/sunray-wrkr/v1/cache');

      expect(response.status).toBe(401);
      const result = await response.text();
      expect(result).toContain('Unauthorized');
    });

    it('should reject requests with invalid token format', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache', {
        method: 'GET',
        headers: {
          'Authorization': 'Invalid token format'
        }
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'GET', '/sunray-wrkr/v1/cache');

      expect(response.status).toBe(401);
      const result = await response.text();
      expect(result).toContain('Unauthorized');
    });
  });

  describe('Error handling', () => {
    it('should handle KV errors gracefully', async () => {
      mockEnv.KV.get.mockRejectedValue(new Error('KV connection failed'));

      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-token'
        }
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'GET', '/sunray-wrkr/v1/cache');
      
      expect(response.status).toBe(200);
      // Even with KV errors, the response should still work as long as the basic structure is intact
    });

    it('should handle invalid JSON in request body', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache/invalidate', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-token',
          'Content-Type': 'application/json'
        },
        body: 'invalid json {]'
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'POST', '/sunray-wrkr/v1/cache/invalidate');
      
      expect(response.status).toBe(400);
      const result = await response.text();
      expect(result).toContain('Invalid JSON');
    });

    it('should handle unsupported methods', async () => {
      mockRequest = new Request('https://example.com/sunray-wrkr/v1/cache', {
        method: 'PUT',
        headers: {
          'Authorization': 'Bearer valid-token'
        }
      });

      const response = await handleCacheRequest(mockRequest, mockEnv, 'PUT', '/sunray-wrkr/v1/cache');
      
      expect(response.status).toBe(404);
      const result = await response.text();
      expect(result).toContain('Not Found');
    });
  });
});