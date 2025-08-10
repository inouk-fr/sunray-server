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
