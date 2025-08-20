# Sunray Server

Universal authentication and authorization server supporting multiple edge worker implementations.

**Sunray Server** is the core component of the Sunray ecosystem - a lightweight, secure, self-hosted solution for authorizing HTTP access to private cloud services without VPN or fixed IPs. The server provides a rich API that handles all business logic, while workers are thin adapters that translate platform-specific requests to the server's universal API.

## ✨ Key Features

- 🔐 **WebAuthn/Passkeys**: Passwordless authentication using biometrics
- 🎛️ **Odoo 18 Admin Interface**: Centralized user and host management
- 🔒 **Zero Trust Security**: Default deny, access rules with priority-based evaluation
- 📊 **Audit Logging**: Complete authentication and access trails
- 🌐 **Multi-Worker Support**: Server-centric API supports various edge implementations
- ⚡ **Rich REST API**: Comprehensive endpoints for worker communication

## 🏗️ Architecture

### Server-Centric Design
The Sunray Server contains all business logic:
- User management and WebAuthn/Passkeys
- Access rules and policy evaluation  
- Session management
- Audit logging
- Token validation

### Supported Workers
Workers are thin adapters that translate platform-specific requests to our API:
- [inouk-sunray-worker-cloudflare](https://gitlab.com/cmorisse/inouk-sunray-worker-cloudflare) - Cloudflare Workers
- [inouk-sunray-worker-k8s](https://gitlab.com/cmorisse/inouk-sunray-worker-k8s) - Kubernetes ForwardAuth (coming soon)
- Future: nginx, Traefik, Istio, AWS Lambda workers

## 📂 Project Structure

```
inouk-sunray-server/
├── project_addons/            # Odoo 18 addons (ikb standard)
│   └── sunray_core/           # Core authentication addon
├── docs/                      # Documentation and specifications
├── config/                    # Configuration examples
├── schema/                    # JSON Schema validation
├── bin/                       # Executable scripts
│   └── sunray-srvr           # Odoo launcher script
└── etc/                       # Configuration files
```

## 🚀 Quick Start

### Prerequisites

- Node.js 20.x and npm 10.x
- Python 3.10+
- PostgreSQL 14+
- Domain for protected services

### Installation

1. **Clone the repository**
   ```bash
   git clone https://gitlab.com/cmorisse/inouk-sunray-server.git
   cd inouk-sunray-server
   ```

2. **Install dependencies**
   ```bash
   # Python dependencies for Sunray Server
   ikb install  # Processes buildit.json and requirements.txt
   ```

3. **Start Sunray Server**
   ```bash
   # Install sunray_core addon
   bin/sunray-srvr -i sunray_core
   
   # Start server
   bin/sunray-srvr
   ```

4. **Generate API key for workers**
   ```bash
   bin/sunray-srvr srctl apikey create Worker_API_Key --sr-worker
   ```

5. **Deploy a worker**
   Choose and deploy a worker implementation:
   - [Cloudflare Workers Setup](https://gitlab.com/cmorisse/inouk-sunray-worker-cloudflare)
   - Kubernetes ForwardAuth (coming soon)

## 🔧 Development

### Sunray Server Development

```bash
# Start server in development mode
bin/sunray-srvr --dev=all

# Update modules
bin/sunray-srvr -u sunray_core

# Run server tests
bin/test_server.sh
bin/test_server.sh --test TestAccessRules  # Specific test class
bin/test_server.sh --coverage --verbose    # With coverage
```

### Sunray CLI (srctl)

Manage Sunray objects via command line:

```bash
# Usage: bin/sunray-srvr srctl <object> <action> [options]
bin/sunray-srvr srctl apikey list
bin/sunray-srvr srctl user create "username" --sr-email "user@example.com"
bin/sunray-srvr srctl setuptoken create "username" --sr-device "laptop" --sr-hours 24
```

## 🔐 Security Model

- **Default Locked**: All resources protected by default
- **Access Rules System**: Priority-based rule evaluation
  - **Public Access**: No authentication required
  - **CIDR Access**: IP address/range whitelist  
  - **Token Access**: API/webhook token authentication
- **WebAuthn/Passkeys**: Primary authentication method
- **Session Management**: Secure cookies with configurable TTL

## 📡 API Documentation

The server provides a comprehensive REST API at `/sunray-srvr/v1/*`:

### Core Endpoints
- `/config` - Get configuration and access rules (Worker → Server)
- `/setup-tokens/validate` - Validate setup tokens
- `/users/<username>/passkeys` - Register passkeys
- `/sessions/validate` - Validate sessions
- `/audit` - Record audit events

See [API_CONTRACT.md](./docs/API_CONTRACT.md) for complete API specification.

## 🧪 Testing

```bash
# Run all server tests with comprehensive reporting
bin/test_server.sh

# Run specific test class
bin/test_server.sh --test TestAccessRules

# Full test run with coverage
bin/test_server.sh --coverage --verbose

# List all available test classes
bin/test_server.sh --list-tests
```

## 🐳 Docker

```bash
# Build server image
bin/docker-build-srvr.sh

# Run server in container
docker run -e IKB_ODOO_ADMIN_PASSWORD="admin" -it sunray-srvr18:latest
```

## 📚 Documentation

- [CLAUDE.md](./CLAUDE.md) - Complete development guide
- [docs/specs/](./docs/specs/) - Technical specifications
- [API_CONTRACT.md](./docs/API_CONTRACT.md) - API specification for workers

## 🤝 Contributing

1. Ensure server API changes are backward compatible
2. Update docs/API_CONTRACT.md for any API changes
3. Test with multiple worker implementations
4. Run comprehensive test suite before submitting

## 📄 License

[Your License Here]

---

**Note**: This is the server component of the Sunray ecosystem. For edge workers, see the respective worker repositories listed above.