/**
 * Session management
 */

import { SignJWT, jwtVerify } from 'jose';
import { createLogger } from '../utils/logger.js';

/**
 * Create a new session
 */
export async function createSession(user, hostId, env) {
  const logger = createLogger(env);
  const sessionId = crypto.randomUUID();
  const now = Date.now();
  const ttl = parseInt(env.SESSION_TTL || '86400') * 1000; // Convert to ms
  const expiresAt = now + ttl;
  
  logger.info(`[createSession] Creating session for user ${user.username} on host ${hostId}`);
  
  const sessionData = {
    session_id: sessionId,
    user_id: user.id,
    username: user.username,
    host_id: hostId,
    created_at: now,
    expires_at: expiresAt,
    is_active: true
  };
  
  logger.debug(`[createSession] Session data:`, JSON.stringify(sessionData));
  
  // Store in KV
  const sessionKey = `session:${sessionId}`;
  logger.debug(`[createSession] Storing in KV with key: ${sessionKey}`);
  
  await env.SESSIONS.put(
    sessionKey,
    JSON.stringify(sessionData),
    { expirationTtl: parseInt(env.SESSION_TTL || '86400') }
  );
  
  logger.debug(`[createSession] Session stored successfully`);
  
  // Create JWT for cookie
  const secret = new TextEncoder().encode(env.SESSION_SECRET || 'default-secret-change-me');
  const jwt = await new SignJWT({
    sid: sessionId,
    uid: user.id,
    usr: user.username,
    hid: hostId
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresAt / 1000)
    .sign(secret);
  
  // Report session creation to admin server
  try {
    await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/sessions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
        'X-Worker-ID': env.WORKER_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        session_id: sessionId,
        username: user.username,
        credential_id: user.credential_id || 'unknown',
        host_domain: hostId,
        created_ip: '127.0.0.1', // TODO: Get from request
        device_fingerprint: 'worker-session',
        user_agent: 'Cloudflare Worker',
        csrf_token: crypto.randomUUID(),
        duration: ttl / 1000 // Convert to seconds
      })
    });
  } catch (error) {
    console.error('Failed to report session to admin:', error);
  }
  
  return {
    sessionId,
    jwt,
    expiresAt
  };
}

/**
 * Validate a session
 */
export async function validateSession(sessionCookie, env) {
  console.log(`[validateSession] Starting validation, cookie length: ${sessionCookie.length}`);
  
  try {
    // Verify JWT
    const secret = new TextEncoder().encode(env.SESSION_SECRET || 'default-secret-change-me');
    console.log(`[validateSession] Using secret: ${env.SESSION_SECRET ? 'custom' : 'default'}`);
    
    const { payload } = await jwtVerify(sessionCookie, secret);
    console.log(`[validateSession] JWT verified successfully, payload:`, JSON.stringify(payload));
    
    if (!payload.sid) {
      console.log(`[validateSession] ✗ No session ID in JWT payload`);
      return null;
    }
    
    // Check session in KV
    const sessionKey = `session:${payload.sid}`;
    console.log(`[validateSession] Looking up KV key: ${sessionKey}`);
    
    const sessionData = await env.SESSIONS.get(sessionKey, { type: 'json' });
    console.log(`[validateSession] KV lookup result:`, sessionData ? 'FOUND' : 'NOT FOUND');
    
    if (!sessionData) {
      console.log(`[validateSession] ✗ Session not found in KV`);
      return null;
    }
    
    console.log(`[validateSession] Session data:`, JSON.stringify({
      session_id: sessionData.session_id,
      username: sessionData.username,
      host_id: sessionData.host_id,
      is_active: sessionData.is_active,
      expires_at: sessionData.expires_at,
      created_at: sessionData.created_at
    }));
    
    // Check if session is active and not expired
    if (!sessionData.is_active) {
      console.log(`[validateSession] ✗ Session is not active`);
      return null;
    }
    
    const now = Date.now();
    if (sessionData.expires_at < now) {
      console.log(`[validateSession] ✗ Session expired (expires_at: ${sessionData.expires_at}, now: ${now})`);
      // Session expired, clean up
      await env.SESSIONS.delete(sessionKey);
      return null;
    }
    
    // Check revocation list
    const revoked = await env.SESSIONS.get(`revoked:${sessionData.user_id}`);
    if (revoked) {
      const revokedTime = parseInt(revoked);
      if (sessionData.created_at < revokedTime) {
        // Session was created before revocation
        await env.SESSIONS.delete(`session:${payload.sid}`);
        return null;
      }
    }
    
    // Check for user-specific invalidation signal (from version changes)
    const invalidateSignal = await env.SESSIONS.get(`invalidate:user:${sessionData.username}`);
    if (invalidateSignal) {
      const invalidateTime = parseInt(invalidateSignal);
      console.log(`[validateSession] User ${sessionData.username} has invalidation signal at ${invalidateTime}`);
      
      // If session was created before the invalidation signal, invalidate it
      if (sessionData.created_at < invalidateTime) {
        console.log(`[validateSession] ✗ Session invalidated due to user version change`);
        await env.SESSIONS.delete(sessionKey);
        // Clean up the invalidation signal if it's old enough
        if (Date.now() - invalidateTime > 300000) { // 5 minutes
          await env.SESSIONS.delete(`invalidate:user:${sessionData.username}`);
        }
        return null;
      }
    }
    
    console.log(`[validateSession] ✓ Session is valid and active`);
    return sessionData;
    
  } catch (error) {
    console.error('[validateSession] Error during validation:', error.message);
    console.error('[validateSession] Error stack:', error.stack);
    return null;
  }
}

/**
 * Revoke a session
 */
export async function revokeSession(sessionId, env) {
  await env.SESSIONS.delete(`session:${sessionId}`);
  
  // Report to admin server
  try {
    await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/sessions/${sessionId}/revoke`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
        'X-Worker-ID': env.WORKER_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        reason: 'User logout'
      })
    });
  } catch (error) {
    console.error('Failed to report session revocation:', error);
  }
}

/**
 * Revoke all sessions for a user
 */
export async function revokeUserSessions(userId, env) {
  // Add to revocation list with current timestamp
  await env.SESSIONS.put(
    `revoked:${userId}`,
    Date.now().toString(),
    { expirationTtl: parseInt(env.SESSION_TTL || '86400') }
  );
  
  // Note: Actual session cleanup happens during validation
}

/**
 * Create session cookie
 */
export function createSessionCookie(jwt, expiresAt, domain) {
  const expires = new Date(expiresAt).toUTCString();
  const secure = domain !== 'localhost';
  
  const cookieParts = [
    `sunray_session=${jwt}`,
    `Domain=${domain}`,
    `Path=/`,
    `Expires=${expires}`,
    'HttpOnly',
    secure ? 'Secure' : '',
    'SameSite=Lax'
  ].filter(Boolean);
  
  const cookie = cookieParts.join('; ');
  
  console.log(`[createSessionCookie] Created cookie:`, {
    domain,
    expires,
    secure,
    jwtLength: jwt.length,
    cookieLength: cookie.length,
    preview: cookie.substring(0, 100) + '...'
  });
  
  return cookie;
}

/**
 * Create logout cookie (clears session)
 */
export function createLogoutCookie(domain) {
  const secure = domain !== 'localhost';
  
  return [
    'sunray_session=',
    `Domain=${domain}`,
    'Path=/',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'HttpOnly',
    secure ? 'Secure' : '',
    'SameSite=Lax'
  ].filter(Boolean).join('; ');
}

/**
 * Create WAF bypass cookie (sublimation cookie)
 */
export async function createWAFBypassCookie(sessionId, clientIP, userAgent, env) {
  const logger = createLogger(env);
  const secret = env.WAF_BYPASS_SECRET || env.SESSION_SECRET || 'default-secret-change-me';
  const timestamp = Math.floor(Date.now() / 1000);
  
  console.log(`[createWAFBypassCookie] Starting cookie creation:`, {
    sessionIdLength: sessionId.length,
    sessionIdPreview: sessionId.substring(0, 8) + '...',
    clientIP,
    userAgentLength: userAgent.length,
    userAgentPreview: userAgent.substring(0, 50) + '...',
    timestamp,
    secretSource: env.WAF_BYPASS_SECRET ? 'WAF_BYPASS_SECRET' : (env.SESSION_SECRET ? 'SESSION_SECRET' : 'default')
  });
  
  try {
    // Create hashes (first 8 chars for brevity)
    const sessionHash = await hashPrefix(sessionId, 8);
    const ipHash = await hashPrefix(clientIP, 8);
    const uaHash = await hashPrefix(userAgent, 8);
    
    console.log(`[createWAFBypassCookie] Generated hashes:`, {
      sessionHash,
      ipHash,
      uaHash,
      timestamp
    });
    
    // Create HMAC
    const data = `${sessionHash}:${ipHash}:${uaHash}:${timestamp}`;
    const hmac = await createHMAC(data, secret);
    
    console.log(`[createWAFBypassCookie] HMAC data and result:`, {
      dataString: data,
      hmacLength: hmac.length,
      hmacPreview: hmac.substring(0, 16) + '...'
    });
    
    // Combine and encode
    const cookieValue = btoa(`${data}:${hmac}`);
    
    console.log(`[createWAFBypassCookie] Final cookie value:`, {
      cookieValueLength: cookieValue.length,
      cookieValuePreview: cookieValue.substring(0, 30) + '...'
    });
    
    logger.info(`[WAF Bypass] Created sublimation cookie for session ${sessionId} from IP ${clientIP}`);
    
    return cookieValue;
  } catch (error) {
    console.error(`[createWAFBypassCookie] Error creating cookie:`, {
      errorMessage: error.message,
      errorStack: error.stack,
      sessionId: sessionId.substring(0, 8) + '...',
      clientIP
    });
    logger.error(`[WAF Bypass] Error creating cookie: ${error.message}`);
    throw error;
  }
}

/**
 * Validate WAF bypass cookie with detailed audit logging
 */
export async function validateWAFBypassCookie(cookieValue, sessionId, clientIP, userAgent, maxAge, env, username) {
  const logger = createLogger(env);
  
  try {
    const decoded = atob(cookieValue);
    const parts = decoded.split(':');
    
    if (parts.length !== 5) {
      logger.warn(`[WAF Bypass] Invalid cookie format for user ${username} from IP ${clientIP}`);
      await reportSublimationManipulation(env, username, clientIP, 'invalid_format', { parts_count: parts.length });
      return false;
    }
    
    const [sessionHash, ipHash, uaHash, timestamp, hmac] = parts;
    
    // Verify HMAC
    const data = `${sessionHash}:${ipHash}:${uaHash}:${timestamp}`;
    const expectedHMAC = await createHMAC(data, env.WAF_BYPASS_SECRET || env.SESSION_SECRET || 'default-secret-change-me');
    if (hmac !== expectedHMAC) {
      logger.error(`[WAF Bypass] HMAC verification failed for user ${username} from IP ${clientIP}`);
      await reportSublimationManipulation(env, username, clientIP, 'hmac_mismatch', { 
        provided_hmac: hmac.substring(0, 8) + '...',
        timestamp: timestamp 
      });
      return false;
    }
    
    // Verify session binding
    const expectedSessionHash = await hashPrefix(sessionId, 8);
    if (sessionHash !== expectedSessionHash) {
      logger.warn(`[WAF Bypass] Session mismatch for user ${username} from IP ${clientIP}`);
      await reportSublimationManipulation(env, username, clientIP, 'session_mismatch', { 
        cookie_session: sessionHash,
        actual_session: expectedSessionHash 
      });
      return false;
    }
    
    // Verify IP binding
    const expectedIPHash = await hashPrefix(clientIP, 8);
    if (ipHash !== expectedIPHash) {
      logger.warn(`[WAF Bypass] IP mismatch for user ${username} - cookie IP hash: ${ipHash}, current IP: ${clientIP}`);
      await reportSublimationManipulation(env, username, clientIP, 'ip_mismatch', { 
        cookie_ip_hash: ipHash,
        current_ip: clientIP 
      });
      return false;
    }
    
    // Verify User-Agent
    const expectedUAHash = await hashPrefix(userAgent, 8);
    if (uaHash !== expectedUAHash) {
      logger.warn(`[WAF Bypass] User-Agent mismatch for user ${username} from IP ${clientIP}`);
      await reportSublimationManipulation(env, username, clientIP, 'ua_mismatch', { 
        cookie_ua_hash: uaHash,
        current_ua_hash: expectedUAHash 
      });
      return false;
    }
    
    // Verify timestamp not too old
    const age = Math.floor(Date.now() / 1000) - parseInt(timestamp);
    if (age > maxAge) {
      logger.info(`[WAF Bypass] Cookie expired for user ${username} from IP ${clientIP} (age: ${age}s, max: ${maxAge}s)`);
      await reportSublimationManipulation(env, username, clientIP, 'expired', { 
        age_seconds: age,
        max_age: maxAge 
      });
      return false;
    }
    
    // All validations passed
    logger.debug(`[WAF Bypass] Cookie validated successfully for user ${username} from IP ${clientIP}`);
    return true;
    
  } catch (error) {
    logger.error(`[WAF Bypass] Validation error for user ${username}: ${error.message}`);
    await reportSublimationManipulation(env, username, clientIP, 'validation_error', { 
      error: error.message 
    });
    return false;
  }
}

/**
 * Create sublimation cookie string
 */
export function createSublimationCookie(value, expiresAt, domain) {
  const expires = new Date(expiresAt).toUTCString();
  const secure = domain !== 'localhost';
  
  const cookieParts = [
    `sunray_sublimation=${value}`,
    `Domain=${domain}`,
    `Path=/`,
    `Expires=${expires}`,
    secure ? 'Secure' : '',
    'SameSite=Lax'
  ].filter(Boolean);
  
  const cookie = cookieParts.join('; ');
  
  console.log(`[createSublimationCookie] Creating WAF bypass cookie:`, {
    domain,
    expires,
    secure,
    valueLength: value.length,
    cookieLength: cookie.length,
    hasHttpOnly: cookie.includes('HttpOnly'),
    cookieName: 'sunray_sublimation',
    valuePreview: value.substring(0, 20) + '...',
    cookiePreview: cookie.substring(0, 100) + '...'
  });
  
  return cookie;
}

/**
 * Create sublimation clear cookie
 */
export function createSublimationClearCookie(domain) {
  const secure = domain !== 'localhost';
  
  return [
    'sunray_sublimation=',
    `Domain=${domain}`,
    'Path=/',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    secure ? 'Secure' : '',
    'SameSite=Lax'
  ].filter(Boolean).join('; ');
}

/**
 * Helper function to create hash prefix
 */
async function hashPrefix(data, length) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = new Uint8Array(hashBuffer);
  const hashHex = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex.substring(0, length);
}

/**
 * Helper function to create HMAC
 */
async function createHMAC(data, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureArray = new Uint8Array(signature);
  return Array.from(signatureArray).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Report sublimation cookie manipulation to admin server
 */
async function reportSublimationManipulation(env, username, clientIP, reason, details) {
  try {
    await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/audit/sublimation-manipulation`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
        'X-Worker-ID': env.WORKER_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username,
        client_ip: clientIP,
        reason,
        details,
        timestamp: new Date().toISOString()
      })
    });
  } catch (error) {
    console.error('Failed to report sublimation manipulation:', error);
  }
}