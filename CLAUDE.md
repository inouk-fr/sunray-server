# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Muppy Sunray is a lightweight, secure, self-hosted solution for authorizing HTTP access to private cloud services without VPN or fixed IPs. The project integrates with Cloudflare's infrastructure to provide enterprise-grade security at a fraction of traditional costs.

### Main Components

1. **Cloudflare Worker**: Edge authentication using WebAuthn/Passkeys
2. **Sunray Server (Odoo 18 Addon)**: Admin interface and configuration management
3. **Demo Application**: Protected web application for testing

## Project Structure

```
/opt/muppy/appserver-sunray18/
├── worker/                    # Cloudflare Worker (to be created)
│   ├── src/                   # Worker source code
│   ├── wrangler.toml          # Cloudflare configuration
│   └── package.json           # Node dependencies
├── sunray_server/             # Odoo 18 addons
│   ├── sunray_core/           # Free edition addon
│   │   ├── __manifest__.py
│   │   ├── models/
│   │   ├── controllers/
│   │   ├── views/
│   │   └── security/
│   └── sunray_enterprise/     # Advanced edition addon (future)
├── demo-app/                  # Demo application (to be created)
├── docs/                      # Documentation
│   ├── specs/                 # Technical specifications
│   ├── market_analysis_pricing_comparison.md
│   └── mvp_implementation_plan.md
├── config/                    # Configuration examples
├── schema/                    # JSON Schema validation
├── bin/                       # Executable scripts
│   └── sunray-srvr           # Odoo launcher script
└── etc/                       # Configuration files
    └── odoo.buildit.cfg       # Generated Odoo config
```

## Development Commands

### Environment Setup

```bash
# Node.js 20.19.4 and npm 10.8.2 are already installed
node --version  # v20.19.4
npm --version   # 10.8.2

# Install Cloudflare Wrangler globally
npm install -g wrangler

# Initialize Odoo build environment (if needed)
/usr/local/python/current/bin/ikb init      # Initialize build environment
/usr/local/python/current/bin/ikb install   # Install Python dependencies
```

### Sunray Server (Odoo 18) Development

```bash
# Start Sunray Server
bin/sunray-srvr                              # Normal startup
bin/sunray-srvr --dev=all                    # Development mode with auto-reload

# Module Management
bin/sunray-srvr -u sunray_core               # Update sunray_core module
bin/sunray-srvr -u all --stop-after-init     # Update all modules and exit
bin/sunray-srvr -i sunray_core               # Install sunray_core module

# Testing
bin/sunray-srvr --test-enable --stop-after-init -u sunray_core
bin/sunray-srvr --log-level=debug_sql --test-enable --stop-after-init -u sunray_core

# Fresh Database for Testing
export TESTDB="sunray_test_$(date +%s)"
dropdb ${TESTDB} 2>/dev/null || true
createdb ${TESTDB}
bin/sunray-srvr --database=${TESTDB} --init=base --without-demo=all --stop-after-init
bin/sunray-srvr --database=${TESTDB} -i sunray_core
```

**Note**: `bin/sunray-srvr` is a wrapper that:
- Selects the correct Python environment with all required packages
- Injects the configuration file (`-c etc/odoo.buildit.cfg`)
- Maps PostgreSQL environment variables (PGUSER, PGPASSWORD, PGDATABASE) to Odoo equivalents

### Worker Development

```bash
# Navigate to worker directory (once created)
cd worker/

# Install dependencies
npm install

# Run local development server
wrangler dev

# Deploy to Cloudflare
wrangler deploy

# Run tests
npm test
```

## Architecture Details

### Authentication Flow (WebAuthn/Passkeys)

1. **User Registration**:
   - Admin generates setup token in Sunray Server
   - User visits `/sunray-wrkr/v1/setup` page
   - WebAuthn passkey created and stored

2. **Authentication**:
   - User attempts to access protected resource
   - Redirected to `/sunray-wrkr/v1/auth`
   - Passkey authentication via WebAuthn
   - Session cookie set upon success

### API Endpoints

**Worker Endpoints** (`/sunray-wrkr/v1/*`):
- `/setup/validate` - Validate setup token
- `/setup/register` - Complete passkey registration
- `/auth/challenge` - Get authentication challenge
- `/auth/verify` - Verify passkey and create session
- `/auth/logout` - Clear session

**Server Endpoints** (`/sunray-srvr/v1/*`):
- `/config` - Get configuration (Worker → Server)
- `/setup-tokens/validate` - Validate setup token
- `/users/<username>/passkeys` - Register passkey

### Security Model

- **Default Locked**: All resources protected by default
- **Whitelist Exceptions**:
  - CIDR ranges for IP-based access
  - Public URL patterns (regex)
  - Webhook tokens for API access
- **WebAuthn/Passkeys**: Primary authentication method
- **Session Management**: Secure cookies with configurable TTL

## Odoo Development Guidelines

### Module Structure
```python
sunray_core/
├── __manifest__.py           # Module metadata
├── models/
│   ├── sunray_user.py       # User model
│   ├── sunray_host.py       # Host configuration
│   └── sunray_session.py    # Session management
├── controllers/
│   └── main.py              # API endpoints
├── views/
│   └── sunray_views.xml     # UI definitions
├── security/
│   └── ir.model.access.csv  # Access rights
└── tests/
    └── test_sunray.py       # Unit tests
```

### Coding Conventions

- **Odoo Recordsets**: Suffix with `_obj` or `_objs`
  ```python
  user_obj = self.env['sunray.user'].browse(user_id)
  host_objs = self.env['sunray.host'].search([])
  ```

- **Relational Fields**: Suffix with `_id` or `_ids`
  ```python
  class SunrayUser(models.Model):
      host_id = fields.Many2one('sunray.host')
      passkey_ids = fields.One2many('sunray.passkey', 'user_id')
  ```

- **Return Convention**: Use `False` (not `None`) for empty recordsets
  ```python
  def get_user(self, username):
      user_obj = self.env['sunray.user'].search([('username', '=', username)])
      return user_obj or False
  ```

### Testing Best Practices

```python
# Minimal viable test records
def setUp(self):
    super().setUp()
    self.host_obj = self.env['sunray.host'].create({
        'name': 'test.example.com',  # Required field
        'domain': 'test.example.com', # Required field
    })

# Mock external dependencies
from unittest.mock import patch

@patch('requests.post')
def test_webhook(self, mock_post):
    mock_post.return_value.status_code = 200
    # Test code here
```

## Current Development Status

### MVP Implementation (4-week timeline)

**Week 1**: Core Infrastructure ✓
- Project structure setup
- Basic Odoo addon scaffolding
- Worker project initialization

**Week 2**: Authentication Implementation (Current)
- WebAuthn integration in Worker
- Passkey storage in Odoo
- Session management

**Week 3**: Admin Interface
- Odoo views for user management
- Host configuration UI
- Setup token generation

**Week 4**: Testing & Documentation
- Integration tests
- Demo application
- Deployment documentation

### Next Steps

1. Create Worker implementation with WebAuthn
2. Implement sunray_core Odoo addon
3. Set up demo application
4. Write comprehensive tests

## Configuration Management

### Build Configuration
- `buildit.json`: Odoo build configuration (if using ikb)
- `wrangler.toml`: Cloudflare Worker configuration
- `etc/odoo.buildit.cfg`: Generated Odoo configuration

### Environment Variables
- PostgreSQL: `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGHOST`, `PGPORT`
- Worker: `ADMIN_API_ENDPOINT`, `ADMIN_API_KEY`, `WORKER_ID`
- Development: Set in `.env` file (not committed)

## Important Notes

- This is the transition from ED25519 signatures to WebAuthn/Passkeys
- The Chrome Extension mentioned in old docs is being replaced by native passkey support
- TocToc mode has been removed in favor of WebAuthn-only authentication
- Focus on MVP with sunray_core only; enterprise features come later