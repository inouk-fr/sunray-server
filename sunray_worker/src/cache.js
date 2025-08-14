/**
 * Cache management API endpoints
 */

import { clearConfigCache } from './config.js';
import { getInvalidationTracker } from './invalidation-tracker.js';

/**
 * Handle cache-related requests
 */
export async function handleCacheRequest(request, env) {
  const url = new URL(request.url);
  const method = request.method;
  
  // Verify admin authorization for all cache endpoints
  const auth = request.headers.get('Authorization');
  if (!auth || auth !== `Bearer ${env.ADMIN_API_KEY}`) {
    return new Response('Unauthorized', { status: 401 });
  }
  
  // Route to appropriate handler
  if (method === 'GET' && url.pathname === '/sunray-wrkr/v1/cache') {
    return await getCacheStatus(env);
  }
  
  if (method === 'POST' && url.pathname === '/sunray-wrkr/v1/cache/invalidate') {
    return await handleInvalidate(request, env);
  }
  
  if (method === 'POST' && url.pathname === '/sunray-wrkr/v1/cache/clear') {
    return await handleClearCache(request, env);
  }
  
  return new Response('Not Found', { status: 404 });
}

/**
 * GET /sunray-wrkr/v1/cache - Get cache status
 */
async function getCacheStatus(env) {
  const configCacheKey = `config:${env.WORKER_ID}`;
  const configCache = await env.CONFIG_CACHE.get(configCacheKey, { type: 'json' });
  
  const tracker = getInvalidationTracker();
  
  const status = {
    worker_id: env.WORKER_ID,
    timestamp: new Date().toISOString(),
    caches: {
      config: {
        exists: !!configCache,
        age_seconds: configCache ? Math.floor((Date.now() - configCache.timestamp) / 1000) : null,
        last_version_check: configCache?.lastVersionCheck ? new Date(configCache.lastVersionCheck).toISOString() : null,
        ttl_seconds: parseInt(env.CACHE_TTL || '300'),
        versions: configCache?.versions || null
      },
      sessions: {
        // Would need iteration or separate tracking
        active_estimate: 'unknown',
        ttl_seconds: parseInt(env.SESSION_TTL || '86400')
      }
    },
    invalidation_tracker: {
      processed_count: tracker.getProcessedCount(),
      last_invalidation: tracker.getLastInvalidation()
    }
  };
  
  return new Response(JSON.stringify(status, null, 2), {
    headers: { 'Content-Type': 'application/json' }
  });
}

/**
 * POST /sunray-wrkr/v1/cache/invalidate - Set invalidation signal
 */
async function handleInvalidate(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (error) {
    return new Response('Invalid JSON', { status: 400 });
  }
  
  const { scope, target, reason } = body;
  
  // Validate scope
  if (!['global', 'user', 'host', 'config'].includes(scope)) {
    return new Response(JSON.stringify({ error: 'Invalid scope' }), { 
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // Validate target for user/host scopes
  if ((scope === 'user' || scope === 'host') && !target) {
    return new Response(JSON.stringify({ error: 'Target required for user/host scope' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // Create invalidation signal
  const signalKey = `invalidate:${scope}:${target || 'all'}`;
  const signalValue = {
    version: Date.now(),
    reason: reason || 'Manual invalidation',
    requested_by: 'admin_server',
    created_at: new Date().toISOString()
  };
  
  // Store signal with minimum TTL (other worker instances will see it)
  await env.CONTROL_SIGNALS.put(
    signalKey,
    JSON.stringify(signalValue),
    { expirationTtl: 60 }
  );
  
  // Also immediately clear relevant caches in this worker
  let cleared = [];
  const tracker = getInvalidationTracker();
  
  switch(scope) {
    case 'global':
      await tracker.processSignal(signalKey, signalValue.version, async () => {
        await clearAllCaches(env);
      });
      cleared.push('all caches');
      break;
      
    case 'user':
      if (target) {
        await tracker.processSignal(signalKey, signalValue.version, async () => {
          await clearUserSessions(target, env);
        });
        cleared.push(`sessions for user ${target}`);
      }
      break;
      
    case 'host':
      if (target) {
        await tracker.processSignal(signalKey, signalValue.version, async () => {
          await clearHostConfig(target, env);
        });
        cleared.push(`config for host ${target}`);
      }
      break;
      
    case 'config':
      await tracker.processSignal(signalKey, signalValue.version, async () => {
        await clearConfigCache(env);
      });
      cleared.push('configuration cache');
      break;
  }
  
  return new Response(JSON.stringify({
    success: true,
    scope: scope,
    target: target,
    signal_key: signalKey,
    cleared: cleared,
    message: `Invalidation signal set. Cache cleared in this worker, other workers will clear within 30s.`
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

/**
 * POST /sunray-wrkr/v1/cache/clear - Direct cache clear
 */
async function handleClearCache(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (error) {
    return new Response('Invalid JSON', { status: 400 });
  }
  
  const { scope, target } = body;
  
  // Direct cache clear (no signal, just this worker)
  let cleared = [];
  
  switch(scope) {
    case 'all':
      await clearAllCaches(env);
      cleared.push('all caches');
      break;
      
    case 'config':
      await clearConfigCache(env);
      cleared.push('configuration cache');
      break;
      
    case 'sessions':
      // Clear all sessions or specific user
      if (target) {
        await clearUserSessions(target, env);
        cleared.push(`sessions for user ${target}`);
      } else {
        // Would need to implement full session clear
        cleared.push('all sessions (not implemented)');
      }
      break;
      
    default:
      return new Response(JSON.stringify({ error: 'Invalid scope' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
  }
  
  return new Response(JSON.stringify({
    success: true,
    worker_id: env.WORKER_ID,
    cleared: cleared,
    timestamp: new Date().toISOString()
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

/**
 * Clear all caches
 */
async function clearAllCaches(env) {
  console.log('Clearing all caches');
  
  // Clear config cache
  await clearConfigCache(env);
  
  // Clear any other caches
  // Note: Sessions are not cleared globally for security reasons
  // Individual sessions should be invalidated through proper channels
}

/**
 * Clear cache for a specific host
 */
async function clearHostConfig(host, env) {
  console.log(`Clearing cache for host: ${host}`);
  // For now, clear the entire config cache
  // In future, could have host-specific cache entries
  await clearConfigCache(env);
}

/**
 * Clear sessions for a specific user
 */
async function clearUserSessions(username, env) {
  console.log(`Clearing sessions for user: ${username}`);
  
  // Set invalidation signal for user
  await env.SESSIONS.put(
    `invalidate:user:${username}`,
    Date.now().toString(),
    { expirationTtl: 300 } // 5 minutes
  );
  
  // Note: Actual session deletion happens during validation
  // This is safer than trying to iterate and delete all sessions
}

export { clearAllCaches, clearHostConfig, clearUserSessions };