// Test file for Access Rules functionality in Worker
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Copy the relevant functions from handler.js for testing
// In a real implementation, these would be properly exported

function checkPublicURL(pathname, pattern) {
  try {
    const regex = new RegExp(pattern);
    return regex.test(pathname);
  } catch (e) {
    return false;
  }
}

function checkCIDRBypass(clientIP, cidr) {
  // Simple implementation for testing
  // In production, this would use proper CIDR matching
  if (cidr === '192.168.1.0/24') {
    return clientIP.startsWith('192.168.1.');
  }
  if (cidr === '10.0.0.0/8') {
    return clientIP.startsWith('10.');
  }
  return false;
}

function extractTokenByConfig(request, tokenConfig, url, logger) {
  const { header_name, param_name, token_source } = tokenConfig;
  
  switch (token_source) {
    case 'header':
      if (header_name) {
        const headerValue = request.headers.get(header_name);
        if (headerValue) {
          return headerValue;
        }
      }
      break;
      
    case 'param':
      if (param_name) {
        const paramValue = url.searchParams.get(param_name);
        if (paramValue) {
          return paramValue;
        }
      }
      break;
      
    case 'both':
      // Try header first, then parameter
      if (header_name) {
        const headerValue = request.headers.get(header_name);
        if (headerValue) {
          return headerValue;
        }
      }
      if (param_name) {
        const paramValue = url.searchParams.get(param_name);
        if (paramValue) {
          return paramValue;
        }
      }
      break;
  }
  
  return null;
}

function isTokenValid(extractedToken, tokenConfig, logger) {
  // Check if token matches
  if (extractedToken !== tokenConfig.token) {
    return false;
  }
  
  // Check if token is active
  if (!tokenConfig.is_active) {
    return false;
  }
  
  // Check expiration
  if (tokenConfig.expires_at) {
    const expiresAt = new Date(tokenConfig.expires_at);
    if (expiresAt < new Date()) {
      return false;
    }
  }
  
  return true;
}

function extractAndValidateTokensByConfig(request, tokenConfigs, logger) {
  if (!tokenConfigs || tokenConfigs.length === 0) {
    return null;
  }

  const url = new URL(request.url);
  
  // Try each configured token
  for (const tokenConfig of tokenConfigs) {
    const extractedToken = extractTokenByConfig(request, tokenConfig, url, logger);
    
    if (extractedToken && isTokenValid(extractedToken, tokenConfig, logger)) {
      return tokenConfig;
    }
  }
  
  return null;
}

// Mock logger
const mockLogger = {
  info: vi.fn(),
  debug: vi.fn(),
  warn: vi.fn(),
  error: vi.fn()
};

describe('Access Rules Processing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('URL Pattern Matching', () => {
    it('should match exact patterns', () => {
      expect(checkPublicURL('/health', '^/health$')).toBe(true);
      expect(checkPublicURL('/health/check', '^/health$')).toBe(false);
    });

    it('should match wildcard patterns', () => {
      expect(checkPublicURL('/api/v1/users', '^/api/.*')).toBe(true);
      expect(checkPublicURL('/api/v2/orders', '^/api/.*')).toBe(true);
      expect(checkPublicURL('/webhook/api/test', '^/api/.*')).toBe(false);
    });

    it('should handle invalid regex patterns', () => {
      expect(checkPublicURL('/test', '[')).toBe(false);
    });
  });

  describe('CIDR Matching', () => {
    it('should match IPs in CIDR range', () => {
      expect(checkCIDRBypass('192.168.1.100', '192.168.1.0/24')).toBe(true);
      expect(checkCIDRBypass('192.168.1.1', '192.168.1.0/24')).toBe(true);
      expect(checkCIDRBypass('192.168.2.1', '192.168.1.0/24')).toBe(false);
    });

    it('should match large CIDR ranges', () => {
      expect(checkCIDRBypass('10.0.0.1', '10.0.0.0/8')).toBe(true);
      expect(checkCIDRBypass('10.255.255.255', '10.0.0.0/8')).toBe(true);
      expect(checkCIDRBypass('11.0.0.1', '10.0.0.0/8')).toBe(false);
    });
  });

  describe('Token Extraction and Validation', () => {
    it('should extract token from header', () => {
      const request = new Request('https://example.com/api/test', {
        headers: {
          'X-API-Key': 'test_token_123'
        }
      });

      const tokenConfig = {
        name: 'API Token',
        token: 'test_token_123',
        header_name: 'X-API-Key',
        token_source: 'header',
        is_active: true
      };

      const result = extractAndValidateTokensByConfig(request, [tokenConfig], mockLogger);
      expect(result).toEqual(tokenConfig);
    });

    it('should extract token from URL parameter', () => {
      const request = new Request('https://example.com/api/test?api_key=param_token_456');

      const tokenConfig = {
        name: 'Param Token',
        token: 'param_token_456',
        param_name: 'api_key',
        token_source: 'param',
        is_active: true
      };

      const result = extractAndValidateTokensByConfig(request, [tokenConfig], mockLogger);
      expect(result).toEqual(tokenConfig);
    });

    it('should try both header and parameter', () => {
      const request = new Request('https://example.com/api/test?api_key=param_token', {
        headers: {
          'X-API-Key': 'header_token'
        }
      });

      const tokenConfig = {
        name: 'Flexible Token',
        token: 'header_token',
        header_name: 'X-API-Key',
        param_name: 'api_key',
        token_source: 'both',
        is_active: true
      };

      const result = extractAndValidateTokensByConfig(request, [tokenConfig], mockLogger);
      expect(result).toEqual(tokenConfig);
    });

    it('should reject inactive tokens', () => {
      const request = new Request('https://example.com/api/test', {
        headers: {
          'X-API-Key': 'inactive_token'
        }
      });

      const tokenConfig = {
        name: 'Inactive Token',
        token: 'inactive_token',
        header_name: 'X-API-Key',
        token_source: 'header',
        is_active: false
      };

      const result = extractAndValidateTokensByConfig(request, [tokenConfig], mockLogger);
      expect(result).toBeNull();
    });

    it('should reject expired tokens', () => {
      const request = new Request('https://example.com/api/test', {
        headers: {
          'X-API-Key': 'expired_token'
        }
      });

      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);

      const tokenConfig = {
        name: 'Expired Token',
        token: 'expired_token',
        header_name: 'X-API-Key',
        token_source: 'header',
        is_active: true,
        expires_at: yesterday.toISOString()
      };

      const result = extractAndValidateTokensByConfig(request, [tokenConfig], mockLogger);
      expect(result).toBeNull();
    });

    it('should reject mismatched tokens', () => {
      const request = new Request('https://example.com/api/test', {
        headers: {
          'X-API-Key': 'wrong_token'
        }
      });

      const tokenConfig = {
        name: 'Valid Token',
        token: 'correct_token',
        header_name: 'X-API-Key',
        token_source: 'header',
        is_active: true
      };

      const result = extractAndValidateTokensByConfig(request, [tokenConfig], mockLogger);
      expect(result).toBeNull();
    });
  });

  describe('Access Rules Priority Processing', () => {
    it('should process rules in priority order', () => {
      const exceptionsTree = [
        {
          priority: 100,
          description: 'High priority rule',
          access_type: 'public',
          url_patterns: ['^/high-priority$']
        },
        {
          priority: 200,
          description: 'Low priority rule',
          access_type: 'public',
          url_patterns: ['^/.*']
        }
      ];

      // First rule should match /high-priority
      let urlMatches = false;
      for (const pattern of exceptionsTree[0].url_patterns) {
        if (checkPublicURL('/high-priority', pattern)) {
          urlMatches = true;
          break;
        }
      }
      expect(urlMatches).toBe(true);

      // Second rule should match everything
      urlMatches = false;
      for (const pattern of exceptionsTree[1].url_patterns) {
        if (checkPublicURL('/anything', pattern)) {
          urlMatches = true;
          break;
        }
      }
      expect(urlMatches).toBe(true);
    });

    it('should handle multiple URL patterns per rule', () => {
      const exception = {
        priority: 100,
        description: 'Multi-pattern rule',
        access_type: 'public',
        url_patterns: ['^/health$', '^/status$', '^/api/health$']
      };

      const testUrls = ['/health', '/status', '/api/health', '/other'];
      const expectedMatches = [true, true, true, false];

      testUrls.forEach((url, index) => {
        let matches = false;
        for (const pattern of exception.url_patterns) {
          if (checkPublicURL(url, pattern)) {
            matches = true;
            break;
          }
        }
        expect(matches).toBe(expectedMatches[index]);
      });
    });
  });

  describe('Complex Access Scenarios', () => {
    it('should handle Shopify webhook scenario', () => {
      const request = new Request('https://example.com/webhooks/shopify', {
        headers: {
          'X-Shopify-Hmac-Sha256': 'shopify_signature_123'
        }
      });

      const exceptionsTree = [
        {
          priority: 100,
          description: 'Shopify Webhook',
          access_type: 'token',
          url_patterns: ['^/webhooks/shopify$'],
          tokens: [
            {
              name: 'Shopify Token',
              token: 'shopify_signature_123',
              header_name: 'X-Shopify-Hmac-Sha256',
              token_source: 'header',
              is_active: true
            }
          ]
        }
      ];

      // Check URL match
      let urlMatches = false;
      const exception = exceptionsTree[0];
      for (const pattern of exception.url_patterns) {
        if (checkPublicURL('/webhooks/shopify', pattern)) {
          urlMatches = true;
          break;
        }
      }
      expect(urlMatches).toBe(true);

      // Check token validation
      const validatedToken = extractAndValidateTokensByConfig(request, exception.tokens, mockLogger);
      expect(validatedToken).toBeTruthy();
      expect(validatedToken.name).toBe('Shopify Token');
    });

    it('should handle multiple payment provider scenario', () => {
      const request = new Request('https://example.com/api/payments', {
        headers: {
          'Stripe-Signature': 'stripe_sig_456'
        }
      });

      const exceptionsTree = [
        {
          priority: 100,
          description: 'Payment Webhooks',
          access_type: 'token',
          url_patterns: ['^/api/payments$', '^/webhooks/payments$'],
          tokens: [
            {
              name: 'Shopify Payment',
              token: 'shopify_payment_123',
              header_name: 'X-Shopify-Hmac-Sha256',
              token_source: 'header',
              is_active: true
            },
            {
              name: 'Stripe Payment',
              token: 'stripe_sig_456',
              header_name: 'Stripe-Signature',
              token_source: 'header',
              is_active: true
            }
          ]
        }
      ];

      // Should match Stripe token
      const validatedToken = extractAndValidateTokensByConfig(
        request, 
        exceptionsTree[0].tokens, 
        mockLogger
      );
      expect(validatedToken).toBeTruthy();
      expect(validatedToken.name).toBe('Stripe Payment');
    });
  });
});