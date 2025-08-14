/**
 * Tests for version-based cache invalidation
 */

import { getConfig, clearConfigCache } from '../src/config.js';
import { validateSession } from '../src/auth/session.js';
import { createMockEnv, createMockResponse } from './helpers/mock-env.js';

// Mock fetch globally
global.fetch = jest.fn();

describe('Version-based cache invalidation', () => {
  let mockEnv;
  
  beforeEach(() => {
    mockEnv = createMockEnv();
    jest.clearAllMocks();
  });
  
  describe('Config version checking', () => {
    test('should cache config with version information', async () => {
      const mockConfig = {
        version: 3,
        config_version: '2025-01-15T10:00:00',
        host_versions: {
          'test.example.com': '2025-01-15T09:00:00'
        },
        user_versions: {
          'testuser': '2025-01-15T09:30:00'
        },
        hosts: [],
        users: {}
      };
      
      // Mock fetch response
      global.fetch.mockResolvedValueOnce(createMockResponse(mockConfig));
      
      // Get config
      const config = await getConfig(mockEnv);
      
      // Verify config was fetched
      expect(config).toEqual(mockConfig);
      
      // Verify it was cached with version info
      expect(mockEnv.CONFIG_CACHE.put).toHaveBeenCalledWith(
        'config:test-worker',
        expect.stringContaining('"config_version":"2025-01-15T10:00:00"'),
        expect.objectContaining({ expirationTtl: 300 })
      );
    });
    
    test('should detect config version change after interval', async () => {
      // Setup: existing cached config
      const oldCache = {
        timestamp: Date.now() - 60000, // 1 minute ago
        lastVersionCheck: Date.now() - 35000, // 35 seconds ago (past check interval)
        versions: {
          config: '2025-01-15T10:00:00',
          hosts: {},
          users: {}
        },
        data: {
          config_version: '2025-01-15T10:00:00',
          hosts: [],
          users: {}
        }
      };
      
      mockEnv.CONFIG_CACHE.get.mockResolvedValueOnce(oldCache);
      
      // New config with updated version
      const newConfig = {
        version: 3,
        config_version: '2025-01-15T11:00:00', // Changed!
        host_versions: {},
        user_versions: {},
        hosts: [],
        users: {}
      };
      
      // Mock fetch for version check and new config
      global.fetch
        .mockResolvedValueOnce(createMockResponse(newConfig)) // Version check
        .mockResolvedValueOnce(createMockResponse(newConfig)); // Config refresh
      
      // Get config - should detect version change and refresh
      const config = await getConfig(mockEnv);
      
      // Verify fresh config was fetched
      expect(config.config_version).toBe('2025-01-15T11:00:00');
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });
    
    test('should not check versions within check interval', async () => {
      // Setup: cached config with recent version check
      const cache = {
        timestamp: Date.now() - 60000, // 1 minute ago
        lastVersionCheck: Date.now() - 10000, // 10 seconds ago (within 30s interval)
        versions: {
          config: '2025-01-15T10:00:00',
          hosts: {},
          users: {}
        },
        data: {
          config_version: '2025-01-15T10:00:00',
          hosts: [],
          users: {}
        }
      };
      
      mockEnv.CONFIG_CACHE.get.mockResolvedValueOnce(cache);
      
      // Get config - should use cache without version check
      const config = await getConfig(mockEnv);
      
      // Verify cached config was used
      expect(config.config_version).toBe('2025-01-15T10:00:00');
      expect(global.fetch).not.toHaveBeenCalled();
    });
    
    test('should clear user sessions when user version changes', async () => {
      // Setup: previous cache without user in versions
      const oldCache = {
        versions: {
          config: '2025-01-15T10:00:00',
          hosts: {},
          users: {}
        }
      };
      
      mockEnv.CONFIG_CACHE.get
        .mockResolvedValueOnce(null) // No main cache
        .mockResolvedValueOnce(oldCache); // Previous cache for comparison
      
      // New config with user in recent modifications
      const newConfig = {
        version: 3,
        config_version: '2025-01-15T11:00:00',
        host_versions: {},
        user_versions: {
          'john.doe': '2025-01-15T10:55:00' // Recently modified
        },
        hosts: [],
        users: {}
      };
      
      global.fetch.mockResolvedValueOnce(createMockResponse(newConfig));
      
      // Get config
      await getConfig(mockEnv, true);
      
      // Verify user invalidation signal was set
      expect(mockEnv.SESSIONS.put).toHaveBeenCalledWith(
        'invalidate:user:john.doe',
        expect.any(String),
        expect.objectContaining({ expirationTtl: 300 })
      );
    });
  });
  
  describe('Session validation with version checks', () => {
    test('should invalidate session if user has invalidation signal', async () => {
      const sessionData = {
        session_id: 'test-session',
        user_id: 'user123',
        username: 'john.doe',
        created_at: Date.now() - 3600000, // 1 hour ago
        expires_at: Date.now() + 3600000,
        is_active: true
      };
      
      // Mock JWT verification
      const jwt = require('jose');
      jest.spyOn(jwt, 'jwtVerify').mockResolvedValueOnce({
        payload: { sid: 'test-session' }
      });
      
      // Session exists in KV
      mockEnv.SESSIONS.get
        .mockResolvedValueOnce(sessionData) // Session data
        .mockResolvedValueOnce(null) // No revocation
        .mockResolvedValueOnce((Date.now() - 1800000).toString()); // Invalidation signal 30 min ago
      
      // Validate session
      const result = await validateSession('mock-jwt', mockEnv);
      
      // Should be null due to invalidation
      expect(result).toBeNull();
      
      // Session should be deleted
      expect(mockEnv.SESSIONS.delete).toHaveBeenCalledWith('session:test-session');
    });
    
    test('should not invalidate session created after invalidation signal', async () => {
      const invalidationTime = Date.now() - 3600000; // 1 hour ago
      
      const sessionData = {
        session_id: 'test-session',
        user_id: 'user123',
        username: 'john.doe',
        created_at: Date.now() - 1800000, // 30 minutes ago (after invalidation)
        expires_at: Date.now() + 3600000,
        is_active: true
      };
      
      // Mock JWT verification
      const jwt = require('jose');
      jest.spyOn(jwt, 'jwtVerify').mockResolvedValueOnce({
        payload: { sid: 'test-session' }
      });
      
      // Session exists in KV
      mockEnv.SESSIONS.get
        .mockResolvedValueOnce(sessionData) // Session data
        .mockResolvedValueOnce(null) // No revocation
        .mockResolvedValueOnce(invalidationTime.toString()); // Old invalidation signal
      
      // Validate session
      const result = await validateSession('mock-jwt', mockEnv);
      
      // Should be valid (created after invalidation)
      expect(result).toEqual(sessionData);
      
      // Session should NOT be deleted
      expect(mockEnv.SESSIONS.delete).not.toHaveBeenCalledWith('session:test-session');
    });
  });
  
  describe('Host version changes', () => {
    test('should detect host version changes', async () => {
      // Previous cache with host version
      const oldCache = {
        versions: {
          config: '2025-01-15T10:00:00',
          hosts: {
            'app.example.com': '2025-01-15T09:00:00'
          },
          users: {}
        }
      };
      
      mockEnv.CONFIG_CACHE.get
        .mockResolvedValueOnce(null) // No main cache
        .mockResolvedValueOnce(oldCache); // Previous cache
      
      // New config with updated host version
      const newConfig = {
        version: 3,
        config_version: '2025-01-15T11:00:00',
        host_versions: {
          'app.example.com': '2025-01-15T10:30:00' // Changed!
        },
        user_versions: {},
        hosts: [],
        users: {}
      };
      
      global.fetch.mockResolvedValueOnce(createMockResponse(newConfig));
      
      // Spy on console.log to verify host change detection
      const consoleSpy = jest.spyOn(console, 'log');
      
      // Get config
      await getConfig(mockEnv, true);
      
      // Verify host version change was detected
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Host app.example.com version changed')
      );
      
      consoleSpy.mockRestore();
    });
  });
});

// Helper to make tests work with both Jest and Node test runner
if (typeof jest === 'undefined') {
  global.jest = {
    fn: () => {
      const fn = function() {};
      fn.mockResolvedValueOnce = () => fn;
      fn.mockResolvedValue = () => fn;
      return fn;
    },
    spyOn: () => ({ mockResolvedValueOnce: () => {} }),
    clearAllMocks: () => {}
  };
}