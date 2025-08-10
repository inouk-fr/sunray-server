import { Router } from 'itty-router';

const router = Router();

// Health check endpoint
router.get('/sunray-wrkr/v1/health', () => {
  return new Response(JSON.stringify({
    status: 'healthy',
    timestamp: new Date().toISOString()
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// Setup endpoints
router.post('/sunray-wrkr/v1/setup/validate', async (request, env) => {
  // TODO: Implement token validation
  return new Response(JSON.stringify({ status: 'not_implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  });
});

router.post('/sunray-wrkr/v1/setup/register', async (request, env) => {
  // TODO: Implement WebAuthn registration
  return new Response(JSON.stringify({ status: 'not_implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  });
});

// Authentication endpoints
router.post('/sunray-wrkr/v1/auth/challenge', async (request, env) => {
  // TODO: Generate WebAuthn challenge
  return new Response(JSON.stringify({ status: 'not_implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  });
});

router.post('/sunray-wrkr/v1/auth/verify', async (request, env) => {
  // TODO: Verify passkey assertion
  return new Response(JSON.stringify({ status: 'not_implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  });
});

router.post('/sunray-wrkr/v1/auth/logout', async (request, env) => {
  // TODO: Clear session
  return new Response(JSON.stringify({ status: 'not_implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  });
});

// Default route handler
router.all('*', () => new Response('Not Found', { status: 404 }));

export default {
  async fetch(request, env, ctx) {
    return router.handle(request, env, ctx);
  }
};
