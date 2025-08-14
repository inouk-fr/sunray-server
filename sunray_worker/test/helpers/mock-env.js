/**
 * Mock environment for testing
 */

export function createMockEnv() {
  return {
    CONFIG_CACHE: {
      get: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    },
    CONTROL_SIGNALS: {
      get: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    },
    SESSIONS: {
      get: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    },
    ADMIN_API_KEY: 'test-api-key',
    ADMIN_API_ENDPOINT: 'https://test.example.com',
    WORKER_ID: 'test-worker',
    CACHE_TTL: '300',
    SESSION_TTL: '86400',
    SESSION_SECRET: 'test-secret-key'
  };
}

export function createMockRequest(options = {}) {
  return new Request(options.url || 'https://test.example.com', {
    method: options.method || 'GET',
    headers: options.headers || {},
    body: options.body
  });
}

export function createMockResponse(data, options = {}) {
  return {
    ok: options.ok !== undefined ? options.ok : true,
    status: options.status || 200,
    statusText: options.statusText || 'OK',
    json: async () => data,
    text: async () => JSON.stringify(data),
    headers: new Headers(options.headers || {})
  };
}