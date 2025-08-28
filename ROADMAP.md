# Sunray Development Roadmap

This document outlines future improvements and architectural enhancements for the Sunray Web/HTTP Zero Trust access solution.

## Completed Architectural Improvements

### Token Consumption Refactoring ✅
**Status:** Completed - Better separation of concerns for setup token lifecycle management

**What was done:**
- Moved token consumption logic from `sunray.passkey` model to `sunray.setup.token` model
- Added dedicated `consume()` method to setup token model
- Created comprehensive test suite in `test_setup_token.py`
- Improved code maintainability and testability

**Benefits achieved:**
- Better separation of concerns
- Single responsibility principle compliance
- Independent testing of token lifecycle
- Centralized token state management

## Optional Improvements - Future Consideration

### 3.1 Token Validation Methods Enhancement
**Priority:** Medium
**Estimated effort:** 1-2 days

Add comprehensive validation methods to the `sunray.setup.token` model:

```python
def is_valid(self):
    """Check if token can be used (not expired, not consumed, usage limit not exceeded)"""
    
def is_expired(self):
    """Check if token has expired"""
    
def can_be_used(self):
    """Check if token has remaining uses available"""
    
def validate_for_registration(self, client_ip=None):
    """Comprehensive validation including CIDR checks"""
```

**Benefits:**
- Move all validation logic from passkey model to token model
- Cleaner, more readable code
- Better error handling and specific error messages
- Independent validation testing

### 3.2 Token Business Logic Consolidation
**Priority:** Medium  
**Estimated effort:** 2-3 days

Move remaining token validation logic from `register_with_setup_token()` to setup token model:

- Token hash validation and lookup
- Expiry checking
- Consumption status validation  
- Usage limit verification
- CIDR restrictions validation

**Target architecture:**
```python
# In sunray.setup.token
def validate_and_consume(self, plain_token, client_ip=None):
    """Complete validation and consumption in one atomic operation"""
    
# In sunray.passkey  
def register_with_setup_token(self, ...):
    # Only passkey-specific logic remains
    token_obj = self.env['sunray.setup.token'].find_and_validate(setup_token, username)
    # ... passkey creation ...
    token_obj.consume()
```

**Benefits:**
- Complete separation of token and passkey concerns
- Atomic token validation and consumption
- Simplified passkey registration method
- Better error isolation and debugging

### 3.3 Token Lifecycle Management API
**Priority:** Low
**Estimated effort:** 3-4 days

Create a complete token lifecycle management system:

```python
def revoke(self, reason=None):
    """Manually revoke a token before expiry"""
    
def extend_expiry(self, additional_hours):
    """Extend token validity (admin only)"""
    
def reset_usage(self):
    """Reset usage counter (admin only, for debugging)"""
    
def get_usage_stats(self):
    """Get detailed usage statistics"""
```

**Benefits:**
- Better administrative control
- Enhanced debugging capabilities  
- Improved audit trail
- Support for complex token management scenarios

## Infrastructure Improvements

### Multi-Host Token Support
**Priority:** Low
**Estimated effort:** 1 week

Allow tokens to work across multiple hosts for users with multi-host access:

- Token not bound to specific host
- Host validation during registration
- Enhanced security with host-specific credentials

### Token Analytics and Monitoring
**Priority:** Low  
**Estimated effort:** 2-3 days

Add comprehensive token usage analytics:
- Usage patterns and trends
- Popular device names and types
- Token lifetime analysis
- Security incident correlation

## Performance Optimizations

### Token Lookup Optimization
**Priority:** Low
**Estimated effort:** 1 day

Optimize token hash lookups for high-volume environments:
- Database index optimization
- Caching layer for active tokens
- Bulk token operations

### Concurrent Token Consumption
**Priority:** Low
**Estimated effort:** 2 days

Add proper concurrency handling for token consumption:
- Database-level locking
- Race condition prevention
- Atomic increment operations

## Security Enhancements

### Enhanced Token Entropy
**Priority:** Low
**Estimated effort:** 1 day

Improve token generation security:
- Longer tokens with more entropy
- Multiple hash algorithms support
- Cryptographically secure random generation audit

### Token Binding Enhancements  
**Priority:** Low
**Estimated effort:** 3 days

Additional token security mechanisms:
- Browser fingerprinting
- Device identification
- Geographic restrictions
- Time-based access windows

### Worker-Server Communication Security
**Priority:** Medium
**Estimated effort:** 2-3 days

Enhance security of network communications between workers and server:

**Current State:**
- Workers authenticate to server using API keys only
- API key compromise allows full authentication bypass
- No request integrity verification between worker and server

**Proposed Enhancement:**
- Add HMAC signatures to worker-server API calls
- Include timestamp and request hash in signature to prevent replay attacks
- Implement request/response integrity verification
- Add optional mutual TLS support for high-security deployments

**Security Benefits:**
- **Defense-in-depth**: Even if API key is compromised, HMAC prevents abuse
- **Request integrity**: Ensures messages aren't tampered with in transit
- **Replay protection**: Timestamp-based signatures prevent replay attacks
- **Audit trail**: Failed signature verification creates security alerts

**Implementation approach:**
```
Worker side:
- Generate HMAC signature for each API request
- Include timestamp and request body hash
- Send signature in X-Request-Signature header

Server side:
- Verify HMAC signature using shared secret
- Check timestamp freshness (configurable window)
- Log failed signature attempts as security events
```

**Configuration:**
- `WORKER_HMAC_SECRET`: Shared secret for HMAC generation
- `HMAC_SIGNATURE_WINDOW_S`: Acceptable timestamp drift (default: 300s)
- `HMAC_REQUIRED`: Whether to enforce HMAC validation (default: false for compatibility)

## Testing and Quality Assurance

### Performance Testing Suite
**Priority:** Medium
**Estimated effort:** 2-3 days

Comprehensive performance testing for token operations:
- Load testing for concurrent registrations
- Token creation/consumption benchmarks
- Database performance under high load
- Memory usage optimization

### Security Testing Framework
**Priority:** Medium
**Estimated effort:** 1 week

Automated security testing for token-related vulnerabilities:
- Token prediction analysis
- Timing attack resistance
- Concurrent consumption race conditions
- Token replay attack prevention

---

## Contributing to the Roadmap

When adding items to this roadmap:

1. **Estimate effort realistically** - Include time for testing and documentation
2. **Consider dependencies** - Note any prerequisites or blocking items  
3. **Define success criteria** - How will we know the improvement is complete?
4. **Document breaking changes** - Note any API or database schema changes

## Implementation Priority

**High:** Critical for security, performance, or major features
**Medium:** Improves developer experience or system maintainability  
**Low:** Nice-to-have improvements that can be deferred

Items should generally be implemented in priority order, but developer availability and project needs may influence the actual sequence.