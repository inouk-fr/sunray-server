/**
 * Configuration management
 * Fetches and caches configuration from admin server
 */

export async function getConfig(env, forceRefresh = false) {
  const cacheKey = `config:${env.WORKER_ID}`;
  
  // Check cache first (unless forced refresh)
  if (!forceRefresh) {
    const cached = await env.CONFIG_CACHE.get(cacheKey, { type: 'json' });
    if (cached) {
      // Check if cache is still valid
      const cacheAge = Date.now() - (cached.timestamp || 0);
      const maxAge = parseInt(env.CACHE_TTL || '300') * 1000; // Convert to ms
      
      if (cacheAge < maxAge) {
        // Cache is still within TTL, but check if we need to verify versions
        // This happens periodically to detect version changes
        if (shouldCheckVersions(cached)) {
          const versionChanged = await checkConfigVersions(cached, env);
          if (versionChanged) {
            console.log('Config version changed, forcing refresh');
            forceRefresh = true;
          } else {
            return cached.data;
          }
        } else {
          return cached.data;
        }
      }
    }
  }
  
  // Fetch fresh configuration from admin server
  try {
    const response = await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/config`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
        'X-Worker-ID': env.WORKER_ID,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      console.error(`Failed to fetch config: ${response.status} ${response.statusText}`);
      
      // Try to use stale cache if available
      const staleCache = await env.CONFIG_CACHE.get(cacheKey, { type: 'json' });
      if (staleCache && staleCache.data) {
        console.log('Using stale cache due to fetch failure');
        return staleCache.data;
      }
      
      return null;
    }
    
    const config = await response.json();
    
    // Cache the configuration with version information
    const cacheData = {
      timestamp: Date.now(),
      lastVersionCheck: Date.now(),
      versions: {
        config: config.config_version,
        hosts: config.host_versions || {},
        users: config.user_versions || {}
      },
      data: config
    };
    
    // Store with TTL
    const ttl = parseInt(env.CACHE_TTL || '300');
    await env.CONFIG_CACHE.put(cacheKey, JSON.stringify(cacheData), {
      expirationTtl: ttl
    });
    
    // Check if we need to clear specific caches based on version changes
    await handleVersionChanges(cacheData, env);
    
    return config;
    
  } catch (error) {
    console.error('Error fetching config:', error);
    
    // Try to use stale cache if available
    const staleCache = await env.CONFIG_CACHE.get(cacheKey, { type: 'json' });
    if (staleCache && staleCache.data) {
      console.log('Using stale cache due to error');
      return staleCache.data;
    }
    
    return null;
  }
}

/**
 * Clear configuration cache
 */
export async function clearConfigCache(env) {
  const cacheKey = `config:${env.WORKER_ID}`;
  await env.CONFIG_CACHE.delete(cacheKey);
  console.log('Configuration cache cleared');
}

/**
 * Get user configuration from admin server
 */
export async function getUserConfig(username, env) {
  try {
    const response = await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/users/${username}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
        'X-Worker-ID': env.WORKER_ID,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        return null; // User not found
      }
      console.error(`Failed to fetch user config: ${response.status}`);
      return null;
    }
    
    return await response.json();
    
  } catch (error) {
    console.error('Error fetching user config:', error);
    return null;
  }
}

/**
 * Check if user exists
 */
export async function checkUserExists(username, env) {
  try {
    const response = await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/users/check`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
        'X-Worker-ID': env.WORKER_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username })
    });
    
    if (!response.ok) {
      console.error(`Failed to check user: ${response.status}`);
      return false;
    }
    
    const result = await response.json();
    return result.exists === true;
    
  } catch (error) {
    console.error('Error checking user:', error);
    return false;
  }
}

/**
 * Check if we should verify versions (periodically, not on every request)
 */
function shouldCheckVersions(cached) {
  // Check versions every 60 seconds to detect changes faster than TTL
  const versionCheckInterval = 60000; // 60 seconds
  const lastCheck = cached.lastVersionCheck || cached.timestamp;
  return (Date.now() - lastCheck) > versionCheckInterval;
}

/**
 * Check if config versions have changed
 */
async function checkConfigVersions(cached, env) {
  try {
    // Lightweight version check endpoint (could be a HEAD request in future)
    const response = await fetch(`${env.ADMIN_API_ENDPOINT}/sunray-srvr/v1/config`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${env.ADMIN_API_KEY}`,
        'X-Worker-ID': env.WORKER_ID,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      return false; // Don't invalidate on error
    }
    
    const newConfig = await response.json();
    
    // Compare versions
    const oldVersion = cached.versions?.config;
    const newVersion = newConfig.config_version;
    
    if (oldVersion !== newVersion) {
      console.log(`Config version changed: ${oldVersion} -> ${newVersion}`);
      return true;
    }
    
    // Update last version check time
    cached.lastVersionCheck = Date.now();
    const cacheKey = `config:${env.WORKER_ID}`;
    await env.CONFIG_CACHE.put(cacheKey, JSON.stringify(cached), {
      expirationTtl: parseInt(env.CACHE_TTL || '300')
    });
    
    return false;
  } catch (error) {
    console.error('Error checking config versions:', error);
    return false;
  }
}

/**
 * Handle version changes by clearing relevant caches
 */
async function handleVersionChanges(newCache, env) {
  const cacheKey = `config:${env.WORKER_ID}`;
  
  // Get previous cache to compare versions
  const oldCache = await env.CONFIG_CACHE.get(`${cacheKey}_prev`, { type: 'json' });
  
  if (!oldCache || !oldCache.versions) {
    // First time or no previous versions, save current as previous
    await env.CONFIG_CACHE.put(`${cacheKey}_prev`, JSON.stringify(newCache), {
      expirationTtl: parseInt(env.CACHE_TTL || '300') * 2
    });
    return;
  }
  
  // Compare host versions
  const oldHostVersions = oldCache.versions.hosts || {};
  const newHostVersions = newCache.versions.hosts || {};
  
  for (const [host, newVersion] of Object.entries(newHostVersions)) {
    const oldVersion = oldHostVersions[host];
    if (oldVersion && oldVersion !== newVersion) {
      console.log(`Host ${host} version changed: ${oldVersion} -> ${newVersion}`);
      // Clear host-specific cache if needed
      await clearHostCache(host, env);
    }
  }
  
  // Compare user versions (these are only recently modified users)
  const newUserVersions = newCache.versions.users || {};
  
  for (const [username, version] of Object.entries(newUserVersions)) {
    console.log(`User ${username} was recently modified (version: ${version})`);
    // Clear user sessions for recently modified users
    await clearUserSessions(username, env);
  }
  
  // Save current as previous for next comparison
  await env.CONFIG_CACHE.put(`${cacheKey}_prev`, JSON.stringify(newCache), {
    expirationTtl: parseInt(env.CACHE_TTL || '300') * 2
  });
}

/**
 * Clear cache for a specific host
 */
async function clearHostCache(host, env) {
  // Implementation depends on how host-specific data is cached
  console.log(`Clearing cache for host: ${host}`);
  // For now, just log - actual implementation would clear host-specific entries
}

/**
 * Clear sessions for a specific user
 */
async function clearUserSessions(username, env) {
  console.log(`Clearing sessions for user: ${username}`);
  // Mark user for session revalidation
  await env.SESSIONS.put(`invalidate:user:${username}`, Date.now().toString(), {
    expirationTtl: 300 // 5 minutes
  });
}