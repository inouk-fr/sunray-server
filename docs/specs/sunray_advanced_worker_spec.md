# Sunray Advanced Worker Specification

## 🎯 Overview

This document specifies the advanced features available in the Sunray Advanced edition Worker. These features extend the core functionality described in [muppy_sunray_worker_spec_v3.md](./muppy_sunray_worker_spec_v3.md).

## 🔐 Edition Detection

The Worker detects its edition through environment variables and feature flags:

```javascript
const SUNRAY_EDITION = env.SUNRAY_EDITION || 'core'; // 'core' or 'advanced'

function isAdvanced() {
  return SUNRAY_EDITION === 'advanced';
}

function requiresAdvanced(feature) {
  if (!isAdvanced()) {
    throw new Error(`Feature '${feature}' requires Sunray Advanced`);
  }
}
```

## 📦 Advanced Features

### 1. Advanced Session Management

Enhanced session policies with granular control:

```javascript
// Advanced session validation
async function validateAdvancedSession(session, request, env) {
  const config = await getHostConfig(request.url, env);
  
  // Strict IP binding
  if (config.session_ip_binding === 'strict') {
    if (session.created_ip !== request.headers.get('CF-Connecting-IP')) {
      return { valid: false, reason: 'IP_CHANGED' };
    }
  }
  
  // Device trust verification
  const deviceTrust = await calculateDeviceTrust(session, request);
  if (deviceTrust < config.min_device_trust_level) {
    return { valid: false, reason: 'DEVICE_UNTRUSTED' };
  }
  
  // Geolocation restrictions
  if (config.allowed_countries?.length > 0) {
    const country = request.cf.country;
    if (!config.allowed_countries.includes(country)) {
      return { valid: false, reason: 'COUNTRY_BLOCKED' };
    }
  }
  
  // Time-based access
  if (config.access_schedule) {
    const allowed = checkAccessSchedule(config.access_schedule, request.cf.timezone);
    if (!allowed) {
      return { valid: false, reason: 'OUTSIDE_SCHEDULE' };
    }
  }
  
  return { valid: true };
}
```

### 2. TOTP (Two-Factor Authentication)

Additional authentication factor beyond passkeys:

```javascript
router.post('/sunray-wrkr/v1/auth/totp/challenge', async (request, env) => {
  requiresAdvanced('totp');
  
  const { session_id } = await request.json();
  const session = await env.SESSIONS.get(session_id);
  
  if (!session || !session.passkey_verified) {
    return new Response(JSON.stringify({ error: 'Invalid session' }), { 
      status: 401 
    });
  }
  
  // Generate TOTP challenge
  return new Response(JSON.stringify({
    challenge: 'totp_required',
    session_id: session_id,
    expires_in: 300 // 5 minutes
  }));
});

router.post('/sunray-wrkr/v1/auth/totp/verify', async (request, env) => {
  requiresAdvanced('totp');
  
  const { session_id, totp_code } = await request.json();
  
  // Verify with Admin Server
  const response = await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/advanced/verify-totp`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      session_id: session_id,
      totp_code: totp_code
    })
  });
  
  if (response.ok) {
    // Upgrade session
    const session = JSON.parse(await env.SESSIONS.get(session_id));
    session.totp_verified = true;
    session.totp_verified_at = Date.now();
    await env.SESSIONS.put(session_id, JSON.stringify(session), {
      expirationTtl: session.ttl
    });
    
    return new Response(JSON.stringify({ success: true }));
  }
  
  return new Response(JSON.stringify({ error: 'Invalid code' }), { 
    status: 401 
  });
});
```

### 3. Rate Limiting

Advanced rate limiting with multiple strategies:

```javascript
class RateLimiter {
  constructor(env) {
    this.env = env;
  }
  
  async check(identifier, config) {
    requiresAdvanced('rate_limiting');
    
    const key = `rate:${identifier}`;
    const now = Date.now();
    const window = config.window || 60000; // 1 minute default
    const limit = config.limit || 100;
    
    // Get current counter
    const data = await this.env.RATE_LIMITS.get(key);
    const counter = data ? JSON.parse(data) : { count: 0, reset: now + window };
    
    // Reset if window expired
    if (now > counter.reset) {
      counter.count = 0;
      counter.reset = now + window;
    }
    
    // Check limit
    if (counter.count >= limit) {
      return {
        allowed: false,
        retryAfter: Math.ceil((counter.reset - now) / 1000),
        limit: limit,
        remaining: 0
      };
    }
    
    // Increment and save
    counter.count++;
    await this.env.RATE_LIMITS.put(key, JSON.stringify(counter), {
      expirationTtl: Math.ceil(window / 1000)
    });
    
    return {
      allowed: true,
      limit: limit,
      remaining: limit - counter.count,
      reset: counter.reset
    };
  }
}

// Apply rate limiting
async function applyRateLimit(request, env) {
  if (!isAdvanced()) return { allowed: true };
  
  const limiter = new RateLimiter(env);
  const ip = request.headers.get('CF-Connecting-IP');
  
  // Different limits for different endpoints
  const path = new URL(request.url).pathname;
  let config = { window: 60000, limit: 100 }; // Default
  
  if (path.startsWith('/sunray-wrkr/v1/auth')) {
    config = { window: 300000, limit: 10 }; // 10 attempts per 5 minutes
  } else if (path.startsWith('/sunray-wrkr/v1/setup')) {
    config = { window: 3600000, limit: 5 }; // 5 attempts per hour
  }
  
  const result = await limiter.check(ip, config);
  
  if (!result.allowed) {
    return new Response(JSON.stringify({
      error: 'Rate limit exceeded',
      retry_after: result.retryAfter
    }), {
      status: 429,
      headers: {
        'Retry-After': result.retryAfter.toString(),
        'X-RateLimit-Limit': result.limit.toString(),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': result.reset.toString()
      }
    });
  }
  
  return { 
    allowed: true,
    headers: {
      'X-RateLimit-Limit': result.limit.toString(),
      'X-RateLimit-Remaining': result.remaining.toString(),
      'X-RateLimit-Reset': result.reset.toString()
    }
  };
}
```

### 4. Emergency Access

Break-glass access for emergency situations:

```javascript
router.post('/sunray-wrkr/v1/emergency/request', async (request, env) => {
  requiresAdvanced('emergency_access');
  
  const { username, justification, duration_minutes } = await request.json();
  
  // Create emergency access request
  const response = await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/advanced/emergency-access`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      username: username,
      justification: justification,
      duration_minutes: duration_minutes || 60,
      request_ip: request.headers.get('CF-Connecting-IP'),
      request_time: new Date().toISOString()
    })
  });
  
  if (response.ok) {
    const { token, expires_at } = await response.json();
    
    // Send notification to security team
    await notifySecurityTeam({
      type: 'EMERGENCY_ACCESS_REQUESTED',
      username: username,
      justification: justification,
      expires_at: expires_at
    });
    
    return new Response(JSON.stringify({
      success: true,
      token: token,
      expires_at: expires_at
    }));
  }
  
  return new Response(JSON.stringify({ 
    error: 'Emergency access denied' 
  }), { status: 403 });
});
```

### 5. Security Monitoring & Alerts

Real-time security event detection:

```javascript
class SecurityMonitor {
  constructor(env) {
    this.env = env;
  }
  
  async detectAnomalies(request, session) {
    requiresAdvanced('security_alerts');
    
    const anomalies = [];
    
    // Impossible travel detection
    if (session.last_location) {
      const distance = calculateDistance(
        session.last_location,
        request.cf.coordinates
      );
      const timeDiff = Date.now() - session.last_access;
      const speed = distance / (timeDiff / 3600000); // km/h
      
      if (speed > 1000) { // Faster than commercial flight
        anomalies.push({
          type: 'IMPOSSIBLE_TRAVEL',
          severity: 'HIGH',
          details: {
            from: session.last_location,
            to: request.cf.coordinates,
            speed_kmh: speed
          }
        });
      }
    }
    
    // Unusual user agent
    const ua = request.headers.get('User-Agent');
    if (isAutomatedUA(ua)) {
      anomalies.push({
        type: 'AUTOMATED_ACCESS',
        severity: 'MEDIUM',
        details: { user_agent: ua }
      });
    }
    
    // Multiple failed attempts
    const failedAttempts = await this.getFailedAttempts(
      request.headers.get('CF-Connecting-IP')
    );
    if (failedAttempts > 5) {
      anomalies.push({
        type: 'BRUTE_FORCE_ATTEMPT',
        severity: 'HIGH',
        details: { attempts: failedAttempts }
      });
    }
    
    // Report anomalies
    if (anomalies.length > 0) {
      await this.reportAnomalies(anomalies, request, session);
    }
    
    return anomalies;
  }
  
  async reportAnomalies(anomalies, request, session) {
    // Send to Admin Server
    await fetch(`${this.env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/advanced/security-alerts`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.env.ADMIN_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        anomalies: anomalies,
        session_id: session?.id,
        username: session?.username,
        ip_address: request.headers.get('CF-Connecting-IP'),
        url: request.url,
        timestamp: new Date().toISOString()
      })
    });
    
    // High severity = immediate notification
    const highSeverity = anomalies.some(a => a.severity === 'HIGH');
    if (highSeverity) {
      await this.sendImmediateAlert(anomalies, session);
    }
  }
}
```

### 6. Advanced Monitoring

Prometheus metrics and detailed telemetry:

```javascript
class MetricsCollector {
  constructor(env) {
    this.env = env;
    this.metrics = new Map();
  }
  
  async collect(name, value, labels = {}) {
    requiresAdvanced('advanced_monitoring');
    
    const key = this.getMetricKey(name, labels);
    const current = this.metrics.get(key) || 0;
    this.metrics.set(key, current + value);
    
    // Batch write to Durable Object every 10 seconds
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), 10000);
    }
  }
  
  async flush() {
    const batch = Array.from(this.metrics.entries()).map(([key, value]) => ({
      key: key,
      value: value,
      timestamp: Date.now()
    }));
    
    await this.env.METRICS.put('batch', JSON.stringify(batch));
    this.metrics.clear();
    this.flushTimer = null;
  }
  
  // Prometheus format export
  async export() {
    const metrics = await this.env.METRICS.list();
    let output = '';
    
    for (const [name, data] of metrics) {
      const metric = JSON.parse(data);
      output += `# TYPE ${name} counter\n`;
      output += `${name}{${this.labelsToString(metric.labels)}} ${metric.value}\n`;
    }
    
    return output;
  }
}

// Metrics endpoint
router.get('/metrics', async (request, env) => {
  requiresAdvanced('advanced_monitoring');
  
  // Verify metrics token
  const token = request.headers.get('Authorization');
  if (token !== `Bearer ${env.METRICS_TOKEN}`) {
    return new Response('Unauthorized', { status: 401 });
  }
  
  const collector = new MetricsCollector(env);
  const metrics = await collector.export();
  
  return new Response(metrics, {
    headers: { 'Content-Type': 'text/plain; version=0.0.4' }
  });
});
```

## 🔄 Feature Flags

All advanced features are controlled through feature flags:

```javascript
const FEATURES = {
  // Core features (always enabled)
  passkey_auth: true,
  session_management: true,
  webhook_auth: true,
  
  // Advanced features
  advanced_sessions: isAdvanced(),
  totp: isAdvanced(),
  emergency_access: isAdvanced(),
  rate_limiting: isAdvanced(),
  security_alerts: isAdvanced(),
  compliance_reports: isAdvanced(),
  bulk_operations: isAdvanced(),
  saml_oidc: isAdvanced(),
  advanced_monitoring: isAdvanced()
};
```

## 📊 Advanced Headers

Additional headers included in advanced edition:

```javascript
// Request headers to backend
'X-Sunray-Risk-Score': calculateRiskScore(request, session),
'X-Sunray-Device-Trust': deviceTrust.level,
'X-Sunray-Anomaly-Count': anomalies.length,
'X-Sunray-Rate-Limit-Remaining': rateLimit.remaining,

// Response headers to client
'X-Sunray-Edition': 'advanced',
'X-Sunray-Session-Expires': session.expires_at,
'X-Sunray-Next-TOTP-Required': session.next_totp_check
```

## 🚀 Deployment

Advanced Worker deployment requires additional KV namespaces and environment variables:

```toml
# wrangler.toml additions for advanced
[[kv_namespaces]]
binding = "RATE_LIMITS"
id = "YOUR_RATE_LIMITS_KV_ID"

[[kv_namespaces]]
binding = "SECURITY_EVENTS"
id = "YOUR_SECURITY_EVENTS_KV_ID"

[[durable_objects.bindings]]
name = "METRICS"
class_name = "MetricsCollector"

[vars]
SUNRAY_EDITION = "advanced"
SUNRAY_LICENSE_KEY = "YOUR_LICENSE_KEY"
```

## 📝 License Validation

The Worker validates its advanced license on startup and periodically:

```javascript
async function validateLicense(env) {
  if (!isAdvanced()) return true;
  
  const response = await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/advanced/validate-license`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      license_key: env.SUNRAY_LICENSE_KEY,
      worker_id: env.WORKER_ID,
      feature_usage: await getFeatureUsage()
    })
  });
  
  if (!response.ok) {
    console.error('License validation failed, reverting to free edition');
    SUNRAY_EDITION = 'free';
    return false;
  }
  
  return true;
}
```