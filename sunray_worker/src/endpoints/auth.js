/**
 * Authentication endpoint - handles user login
 */

import { getAuthHTML } from '../templates/auth.js';
import { verifyPasskey } from '../auth/webauthn.js';
import { createSession, createSessionCookie, createWAFBypassCookie, createSublimationCookie } from '../auth/session.js';
import { checkUserExists, getConfig } from '../config.js';

export async function handleAuth(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // GET /sunray-wrkr/v1/auth - Show login form
  if (request.method === 'GET' && path === '/sunray-wrkr/v1/auth') {
    const returnTo = url.searchParams.get('return_to') || '/';
    const html = getAuthHTML(env.RP_NAME, returnTo);
    return new Response(html, {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
  
  // POST /sunray-wrkr/v1/auth/challenge - Get authentication challenge
  if (request.method === 'POST' && path === '/sunray-wrkr/v1/auth/challenge') {
    // Validate Content-Type
    const contentType = request.headers.get('Content-Type');
    if (!contentType || !contentType.includes('application/json')) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Content-Type must be application/json'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const body = await request.json();
    const { username } = body;
    
    if (!username) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Username is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Check if user exists
    const userExists = await checkUserExists(username, env);
    
    if (!userExists) {
      // Don't reveal whether user exists or not
      return new Response(JSON.stringify({
        success: false,
        error: 'Invalid username or password'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Generate authentication challenge
    const challenge = crypto.randomUUID();
    
    // Store challenge temporarily
    await env.CHALLENGES.put(
      `auth:${username}:${challenge}`,
      JSON.stringify({
        username,
        timestamp: Date.now()
      }),
      { expirationTtl: parseInt(env.CHALLENGE_TTL || '300') }
    );
    
    // Return WebAuthn authentication options
    return new Response(JSON.stringify({
      success: true,
      options: {
        challenge,
        rpId: env.RP_ID,
        userVerification: 'required',
        timeout: 60000
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // POST /sunray-wrkr/v1/auth/verify - Verify authentication
  if (request.method === 'POST' && path === '/sunray-wrkr/v1/auth/verify') {
    // Validate Content-Type
    const contentType = request.headers.get('Content-Type');
    if (!contentType || !contentType.includes('application/json')) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Content-Type must be application/json'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const body = await request.json();
    const { username, challenge, credential, returnTo } = body;
    
    if (!username || !challenge || !credential) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Missing required parameters'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Verify challenge
    const challengeData = await env.CHALLENGES.get(
      `auth:${username}:${challenge}`,
      { type: 'json' }
    );
    
    if (!challengeData) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Invalid or expired challenge'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Clean up challenge
    await env.CHALLENGES.delete(`auth:${username}:${challenge}`);
    
    // Verify passkey with admin server
    const user = await verifyPasskey(username, credential, challenge, env);
    
    if (!user) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Authentication failed'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Get host domain from return URL
    const returnUrl = new URL(returnTo || '/', url);
    const hostDomain = returnUrl.hostname;
    
    // Create session with the host domain
    const session = await createSession(user, hostDomain, env);
    
    // Create session cookie
    const sessionCookie = createSessionCookie(
      session.jwt,
      session.expiresAt,
      env.RP_ID
    );
    
    // Check if WAF bypass is enabled for this host
    const config = await getConfig(env);
    const hostConfig = config?.hosts.find(h => h.domain === hostDomain);
    const cookies = [sessionCookie];
    
    if (hostConfig?.bypass_waf_for_authenticated) {
      try {
        // Get client info for WAF bypass cookie
        const clientIP = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
        const userAgent = request.headers.get('User-Agent') || '';
        
        // Create WAF bypass cookie
        const wafBypassValue = await createWAFBypassCookie(
          session.sessionId,
          clientIP,
          userAgent,
          env
        );
        
        // Add sublimation cookie (NOT HttpOnly so WAF can read it)
        const sublimationCookie = createSublimationCookie(
          wafBypassValue,
          session.expiresAt,
          env.RP_ID
        );
        
        cookies.push(sublimationCookie);
        
        console.log(`[WAF Bypass] Created sublimation cookie for ${user.username} on ${hostDomain}`);
      } catch (error) {
        console.error(`[WAF Bypass] Failed to create sublimation cookie: ${error.message}`);
        // Continue without WAF bypass cookie - session will still work
      }
    }
    
    // Store session info temporarily for cookie setting
    await env.SESSIONS.put(
      `pending:${session.sessionId}`,
      JSON.stringify({
        cookies,
        redirectTo: returnTo || '/'
      }),
      { expirationTtl: 60 } // 1 minute TTL
    );
    
    console.log(`Session created: ${session.sessionId}, pending redirect to: ${returnTo || '/'}`);
    
    // Return success with session ID for redirect
    return new Response(JSON.stringify({
      success: true,
      sessionId: session.sessionId
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }
  
  // GET /sunray-wrkr/v1/auth/complete - Complete auth and set cookie
  if (request.method === 'GET' && path === '/sunray-wrkr/v1/auth/complete') {
    const sessionId = url.searchParams.get('sid');
    
    console.log(`[auth/complete] Completing authentication for session: ${sessionId}`);
    
    if (!sessionId) {
      console.log(`[auth/complete] ✗ No session ID provided`);
      return Response.redirect('/sunray-wrkr/v1/auth', 302);
    }
    
    // Get pending session
    const pendingKey = `pending:${sessionId}`;
    console.log(`[auth/complete] Looking up pending session: ${pendingKey}`);
    
    const pending = await env.SESSIONS.get(pendingKey, { type: 'json' });
    if (!pending) {
      console.log(`[auth/complete] ✗ Pending session not found`);
      return Response.redirect('/sunray-wrkr/v1/auth', 302);
    }
    
    console.log(`[auth/complete] Found pending session:`, {
      redirectTo: pending.redirectTo,
      cookieCount: pending.cookies ? pending.cookies.length : (pending.cookie ? 1 : 0),
      // Show both old single cookie format and new multiple cookies format for compatibility
      cookiePreview: pending.cookies ? `[${pending.cookies.length} cookies]` : 
                     (pending.cookie ? pending.cookie.substring(0, 100) + '...' : 'none')
    });
    
    // Clean up pending session
    await env.SESSIONS.delete(pendingKey);
    console.log(`[auth/complete] Cleaned up pending session`);
    
    // Prepare response headers
    const headers = {
      'Location': pending.redirectTo
    };
    
    // Set cookies - handle both new format (multiple cookies) and old format (single cookie) for compatibility
    if (pending.cookies && Array.isArray(pending.cookies)) {
      // New format: multiple cookies
      pending.cookies.forEach((cookie, index) => {
        if (index === 0) {
          headers['Set-Cookie'] = cookie;
        } else {
          // For multiple Set-Cookie headers, we need to use an array or multiple header entries
          // Cloudflare Workers handles this by allowing array values
          if (Array.isArray(headers['Set-Cookie'])) {
            headers['Set-Cookie'].push(cookie);
          } else {
            headers['Set-Cookie'] = [headers['Set-Cookie'], cookie];
          }
        }
      });
      console.log(`[auth/complete] ✓ Redirecting to ${pending.redirectTo} with ${pending.cookies.length} cookies`);
    } else if (pending.cookie) {
      // Legacy format: single cookie (for backward compatibility)
      headers['Set-Cookie'] = pending.cookie;
      console.log(`[auth/complete] ✓ Redirecting to ${pending.redirectTo} with single session cookie`);
    }
    
    return new Response(null, {
      status: 302,
      headers
    });
  }
  
  return new Response('Not Found', { status: 404 });
}

/**
 * Get host ID for a domain
 */
async function getHostIdForDomain(domain, env) {
  const { getConfig } = await import('../config.js');
  const config = await getConfig(env);
  
  if (!config || !config.hosts) {
    return null;
  }
  
  const host = config.hosts.find(h => h.domain === domain);
  return host ? host.id : null;
}