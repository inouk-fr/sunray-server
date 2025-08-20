# Sunray Server API Contract v1

This document defines the API that ALL Sunray workers must use. The server provides a rich, comprehensive API that handles all business logic, while workers are thin translation layers.

## Design Principles

1. **Server contains ALL business logic** - Workers are stateless translators
2. **Workers query server for decisions** - No local policy evaluation
3. **Server responses are cacheable** - Workers can cache for performance
4. **API versioning for backward compatibility** - Ensures worker stability
5. **Consistent error handling** - Standard error responses across endpoints

## Authentication

All API requests must include the `X-API-Key` header with a valid worker API key:

```
X-API-Key: your_worker_api_key_here
```

## Core Endpoints

### GET /sunray-srvr/v1/config

**Purpose**: Returns complete configuration including access rules for a host.
**Usage**: Workers should cache this and use it for local decision making.

**Query Parameters**:
- `host` (required): The host/domain being accessed

**Response**:
```json
{
  "version": 4,
  "host": "example.com",
  "exceptions_tree": {
    "public_patterns": ["/health", "/status"],
    "cidr_rules": [
      {
        "priority": 200,
        "patterns": ["/admin/*"],
        "cidrs": ["192.168.1.0/24"]
      }
    ],
    "token_rules": [
      {
        "priority": 300,
        "patterns": ["/api/*", "/webhook/*"],
        "tokens": [
          {
            "name": "API_Token_1",
            "header_name": "X-API-Key",
            "token_source": "header"
          }
        ]
      }
    ]
  },
  "default_action": "authenticate",
  "session_ttl_seconds": 86400
}
```

### POST /sunray-srvr/v1/setup-tokens/validate

**Purpose**: Validates setup tokens for new device registration.

**Request Body**:
```json
{
  "username": "user@example.com",
  "token": "setup_token_string"
}
```

**Response** (Success):
```json
{
  "success": true,
  "user_id": 123,
  "device_name": "laptop"
}
```

**Response** (Error):
```json
{
  "success": false,
  "error": "Invalid or expired setup token"
}
```

### POST /sunray-srvr/v1/users/{username}/passkeys

**Purpose**: Registers a new passkey for a user.

**Path Parameters**:
- `username`: The username to register the passkey for

**Request Body**:
```json
{
  "credential": {
    "id": "credential_id",
    "rawId": "base64_raw_id",
    "response": {
      "attestationObject": "base64_attestation",
      "clientDataJSON": "base64_client_data"
    },
    "type": "public-key"
  },
  "setup_token": "valid_setup_token"
}
```

**Response**:
```json
{
  "success": true,
  "passkey_id": "new_passkey_id"
}
```

### POST /sunray-srvr/v1/sessions/validate

**Purpose**: Validates an existing session.

**Request Body**:
```json
{
  "session_id": "session_id_string",
  "ip_address": "client_ip",
  "user_agent": "client_user_agent"
}
```

**Response** (Valid):
```json
{
  "valid": true,
  "username": "user@example.com",
  "expires_at": "2024-01-01T12:00:00Z"
}
```

**Response** (Invalid):
```json
{
  "valid": false,
  "reason": "expired"
}
```

### POST /sunray-srvr/v1/auth/challenge

**Purpose**: Initiates WebAuthn authentication challenge.

**Request Body**:
```json
{
  "username": "user@example.com",
  "host": "example.com"
}
```

**Response**:
```json
{
  "challenge": "base64_challenge",
  "allowCredentials": [
    {
      "id": "credential_id",
      "type": "public-key"
    }
  ],
  "timeout": 60000
}
```

### POST /sunray-srvr/v1/auth/verify

**Purpose**: Verifies WebAuthn authentication response and creates session.

**Request Body**:
```json
{
  "username": "user@example.com",
  "credential": {
    "id": "credential_id",
    "rawId": "base64_raw_id",
    "response": {
      "authenticatorData": "base64_auth_data",
      "clientDataJSON": "base64_client_data",
      "signature": "base64_signature"
    },
    "type": "public-key"
  },
  "host": "example.com",
  "ip_address": "client_ip",
  "user_agent": "client_user_agent"
}
```

**Response**:
```json
{
  "success": true,
  "session_id": "new_session_id",
  "expires_at": "2024-01-01T12:00:00Z",
  "waf_bypass_cookie": "optional_waf_bypass_data"
}
```

### POST /sunray-srvr/v1/audit

**Purpose**: Records audit events from workers.

**Request Body**:
```json
{
  "event_type": "auth.success",
  "username": "user@example.com",
  "host": "example.com",
  "ip_address": "client_ip",
  "user_agent": "client_user_agent",
  "details": {
    "additional": "context"
  }
}
```

**Response**:
```json
{
  "success": true,
  "audit_id": 12345
}
```

## Error Handling

All endpoints use consistent error responses:

```json
{
  "error": "Error description",
  "code": "ERROR_CODE",
  "details": {
    "additional": "context"
  }
}
```

Common HTTP status codes:
- `200`: Success
- `400`: Bad Request (invalid input)
- `401`: Unauthorized (invalid API key)
- `403`: Forbidden (access denied)
- `404`: Not Found (resource doesn't exist)
- `500`: Internal Server Error

## Caching Guidelines

### Configuration Endpoint
- Cache duration: 5 minutes
- Invalidate on: Worker restart, server config changes
- Cache key: `config_{host}`

### Token Validation
- Cache duration: 1 hour
- Invalidate on: Token revocation
- Cache key: `token_{token_hash}`

### Session Validation
- Cache duration: 30 seconds
- Invalidate on: Session revocation, logout
- Cache key: `session_{session_id}`

## Version Compatibility

- **v1**: Current stable version
- **v2**: Future version with additional features
- Workers should specify API version in `Accept` header: `application/vnd.sunray.v1+json`
- Server maintains backward compatibility for at least one major version

## Worker Implementation Requirements

1. **Always query server for authentication decisions**
2. **Implement proper caching with TTL**
3. **Handle server unavailability gracefully**
4. **Log all authentication events via audit endpoint**
5. **Validate server responses before acting**
6. **Use secure defaults (deny access) on errors**

## Example Worker Flow

1. **Request Interception**: Worker intercepts incoming request
2. **Cache Check**: Check if config/session is cached and valid
3. **Server Query**: Query server API for decisions if needed
4. **Action**: Allow/deny/redirect based on server response
5. **Audit**: Log the decision via audit endpoint
6. **Cache Update**: Update local cache with server responses

This API contract ensures all workers behave consistently while allowing platform-specific optimizations.