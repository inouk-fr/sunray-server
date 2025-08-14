/**
 * Internal Sunray endpoints handler
 * Handles authentication UI and WebAuthn flows
 */

import { handleSetup } from './endpoints/setup.js';
import { handleAuth } from './endpoints/auth.js';
import { handleLogout } from './endpoints/logout.js';

export async function handleInternalRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // Route to appropriate handler
  if (path.startsWith('/sunray-wrkr/v1/setup')) {
    return handleSetup(request, env, ctx);
  }
  
  if (path.startsWith('/sunray-wrkr/v1/auth')) {
    return handleAuth(request, env, ctx);
  }
  
  if (path === '/sunray-wrkr/v1/logout') {
    return handleLogout(request, env, ctx);
  }
  
  // Health check endpoint
  if (path === '/sunray-wrkr/v1/health') {
    // Only allow GET requests
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method Not Allowed', { 
        status: 405,
        headers: { 
          'Content-Type': 'text/plain',
          'Allow': 'GET, HEAD'
        }
      });
    }
    
    return new Response(JSON.stringify({
      status: 'healthy',
      worker_id: env.WORKER_ID,
      timestamp: new Date().toISOString()
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // Cache management endpoints
  if (path.startsWith('/sunray-wrkr/v1/cache')) {
    const { handleCacheRequest } = await import('./cache.js');
    return handleCacheRequest(request, env);
  }
  
  return new Response('Not Found', { status: 404 });
}