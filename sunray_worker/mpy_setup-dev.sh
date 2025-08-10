#!/bin/bash

# Install Node.js LTS 20 + npm from NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Check install
echo "Node.js version : $(node -v)"
echo "npm version     : $(npm -v)"

# To uninstall
#sudo apt remove --purge nodejs
#sudo rm /etc/apt/sources.list.d/nodesource.list

# Install Cloudflare Wrangler globally (requires sudo on Ubuntu)
echo "Installing Cloudflare Wrangler globally (requires sudo)..."
sudo npm install -g wrangler

# Check Wrangler installation
echo "Wrangler version: $(wrangler --version 2>/dev/null || echo 'Not installed')"

# Create project structure if it doesn't exist
echo "Setting up project structure..."
mkdir -p src
mkdir -p tests
mkdir -p config

# Initialize package.json if it doesn't exist
if [ ! -f package.json ]; then
    echo "Initializing package.json..."
    npm init -y
    
    # Update package.json with project details
    npm pkg set name="sunray-worker"
    npm pkg set description="Cloudflare Worker for Sunray authentication"
    npm pkg set version="1.0.0"
    npm pkg set main="src/index.js"
    npm pkg set scripts.dev="wrangler dev"
    npm pkg set scripts.deploy="wrangler deploy"
    npm pkg set scripts.test="jest"
    npm pkg set scripts.lint="eslint src/"
fi

# Install development dependencies
echo "Installing development dependencies..."
npm install --save-dev \
    wrangler \
    @cloudflare/workers-types \
    typescript \
    jest \
    eslint \
    @types/jest \
    miniflare

# Install production dependencies
echo "Installing production dependencies..."
npm install \
    @simplewebauthn/server \
    jose \
    itty-router

# Create wrangler.toml if it doesn't exist
if [ ! -f wrangler.toml ]; then
    echo "Creating wrangler.toml..."
    cat > wrangler.toml << 'EOF'
name = "sunray-worker"
main = "src/index.js"
compatibility_date = "2024-01-01"

[env.development]
vars = { ENVIRONMENT = "development" }

[env.production]
vars = { ENVIRONMENT = "production" }

# KV Namespaces for storing session data
[[kv_namespaces]]
binding = "SESSIONS"
id = "YOUR_KV_NAMESPACE_ID"
preview_id = "YOUR_PREVIEW_KV_NAMESPACE_ID"

[[kv_namespaces]]
binding = "CONFIG_CACHE"
id = "YOUR_CONFIG_KV_NAMESPACE_ID"
preview_id = "YOUR_CONFIG_PREVIEW_KV_NAMESPACE_ID"

# Durable Objects (if needed for WebAuthn state)
# [[durable_objects.bindings]]
# name = "WEBAUTHN_STATE"
# class_name = "WebAuthnState"

# Environment variables (set these in Cloudflare dashboard)
# [vars]
# ADMIN_API_ENDPOINT = "https://your-odoo-server.com"
# ADMIN_API_KEY = "your-api-key"
# WORKER_ID = "worker-1"
EOF
fi

# Create basic source structure
if [ ! -f src/index.js ]; then
    echo "Creating src/index.js..."
    cat > src/index.js << 'EOF'
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
EOF
fi

# Create .gitignore if it doesn't exist
if [ ! -f .gitignore ]; then
    echo "Creating .gitignore..."
    cat > .gitignore << 'EOF'
node_modules/
dist/
.wrangler/
.env
.env.local
*.log
.DS_Store
coverage/
.vscode/
.idea/
EOF
fi

# Create README.md
if [ ! -f README.md ]; then
    echo "Creating README.md..."
    cat > README.md << 'EOF'
# Sunray Worker

Cloudflare Worker for Sunray authentication using WebAuthn/Passkeys.

## Development Setup

1. Run the setup script:
   ```bash
   ./mpy_setup-dev.sh
   ```

2. Configure your Cloudflare account:
   ```bash
   wrangler login
   ```

3. Update `wrangler.toml` with your KV namespace IDs

4. Set environment variables in `.env`:
   ```
   ADMIN_API_ENDPOINT=https://your-odoo-server.com
   ADMIN_API_KEY=your-api-key
   WORKER_ID=worker-1
   ```

## Development

Start the development server:
```bash
npm run dev
```

## Testing

Run tests:
```bash
npm test
```

## Deployment

Deploy to Cloudflare:
```bash
npm run deploy
```

## API Endpoints

- `POST /sunray-wrkr/v1/setup/validate` - Validate setup token
- `POST /sunray-wrkr/v1/setup/register` - Register passkey
- `POST /sunray-wrkr/v1/auth/challenge` - Get authentication challenge
- `POST /sunray-wrkr/v1/auth/verify` - Verify passkey
- `POST /sunray-wrkr/v1/auth/logout` - Clear session
- `GET /sunray-wrkr/v1/health` - Health check
EOF
fi

echo ""
echo "✅ Development environment setup complete!"
echo ""
echo "Next steps:"
echo "1. Make this script executable: chmod +x mpy_setup-dev.sh"
echo "2. Configure Cloudflare: wrangler login"
echo "3. Update wrangler.toml with your KV namespace IDs"
echo "4. Start development: npm run dev"
echo ""
echo "Project structure created:"
echo "  sunray_worker/"
echo "  ├── src/"
echo "  │   └── index.js       # Main worker code"
echo "  ├── tests/             # Test files"
echo "  ├── config/            # Configuration files"
echo "  ├── package.json       # Node dependencies"
echo "  ├── wrangler.toml      # Cloudflare config"
echo "  ├── .gitignore"
echo "  └── README.md"