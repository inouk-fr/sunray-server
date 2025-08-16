/**
 * Logout endpoint - handles session termination
 */

import { revokeSession, createLogoutCookie, createSublimationClearCookie } from '../auth/session.js';

export async function handleLogout(request, env, ctx) {
  const url = new URL(request.url);
  const returnTo = url.searchParams.get('return_to') || '/';
  
  // Get session cookie
  const cookieHeader = request.headers.get('Cookie');
  if (cookieHeader) {
    const cookies = cookieHeader.split(';').map(c => c.trim());
    for (const cookie of cookies) {
      const [key, value] = cookie.split('=');
      if (key === 'sunray_session' && value) {
        // Extract session ID from JWT (would need to decode)
        try {
          const { jwtVerify } = await import('jose');
          const secret = new TextEncoder().encode(env.SESSION_SECRET || 'default-secret-change-me');
          const { payload } = await jwtVerify(value, secret);
          
          if (payload.sid) {
            await revokeSession(payload.sid, env);
          }
        } catch (error) {
          console.error('Failed to revoke session:', error);
        }
      }
    }
  }
  
  // Clear both session and sublimation cookies
  const sessionClearCookie = createLogoutCookie(env.RP_ID);
  const sublimationClearCookie = createSublimationClearCookie(env.RP_ID);
  
  console.log(`[Logout] Clearing session and sublimation cookies for domain ${env.RP_ID}`);
  
  // Redirect to return URL or home with both cookies cleared
  return Response.redirect(returnTo, 302, {
    headers: {
      'Set-Cookie': [sessionClearCookie, sublimationClearCookie]
    }
  });
}