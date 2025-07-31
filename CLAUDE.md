# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Muppy Sunray is a lightweight, secure, self-hosted solution for authorizing HTTP access to private cloud services without VPN or fixed IPs. The project consists of three main components:

1. **Cloudflare Worker**: Validates requests using ED25519 signatures
2. **Chrome Extension**: Signs outgoing requests with private keys
3. **YAML Configuration**: Version-controlled access control with JSON Schema validation

## Project Structure

The codebase is organized as follows:
- `worker/` - Cloudflare Worker implementation (to be created)
- `extension/` - Chrome extension implementation (to be created)
- `config/` - YAML configuration examples
- `schema/` - JSON Schema for configuration validation
- `prompts/` - Project specifications and documentation

## Development Commands

### Initial Setup
```bash
# Install Node.js LTS 20 and npm
./mpy_setup.sh

# Install Cloudflare Wrangler globally
npm install -g wrangler
```

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
```

### Extension Development
```bash
# Navigate to extension directory (once created)
cd extension/

# Install dependencies
npm install

# Build extension
npm run build

# Watch mode for development
npm run watch
```

## Architecture Details

### Authentication Modes

1. **Extension Mode (ED25519 signatures)**
   - Header format: `X-MPY-SUNRAY: <username>:<timestamp>:<signature>`
   - Timestamp window: ±30 seconds
   - Private keys stored in Chrome extension's localStorage

2. **TocToc Mode (Email + PIN without extension)**
   - Email validation workflow with PIN confirmation
   - JWT tokens with 60s expiry and automatic renewal
   - IP verification and session management

### Configuration Schema

The YAML configuration (`config/general_config.yaml`) follows the schema defined in `schema/muppy_sunray_worker_config_schema.json`:

- `version`: Schema version (currently 1)
- `users`: Map of usernames to ED25519 public keys
- `hosts`: Array of protected domains with:
  - `authorized_users`: List of allowed usernames
  - `allowed_ips`: Whitelist of IP addresses
  - `allowed_paths`: Path-specific authentication rules (open, header, query_param)

### Security Considerations

- ED25519 signatures prevent replay attacks via timestamp validation
- Configuration is embedded in the Worker at build time
- Private keys never leave the client (Chrome extension)
- Multiple authentication methods for different use cases

## Current Development Status

The project is in initial development phase. Key components to implement:

1. Cloudflare Worker with YAML parsing and signature verification
2. Chrome extension with key generation and request signing
3. CLI tool for generating YAML configuration entries
4. Comprehensive test suite

## Testing Strategy

When implementing tests:
- Unit tests for signature verification logic
- Integration tests for Worker request handling
- End-to-end tests simulating Chrome extension interactions
- Configuration validation tests against JSON Schema