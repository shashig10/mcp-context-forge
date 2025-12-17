# Auth Header Injector Plugin

A flexible plugin for injecting authentication headers into HTTP requests based on URL path patterns.

## Overview

The Auth Header Injector plugin allows you to automatically add authentication headers (like `Authorization`, `X-API-Key`, custom tokens, etc.) to HTTP requests that match specific URL path patterns. This is useful when you need to add authentication to specific endpoints without modifying application code.

## Features

- **Path-based header injection**: Configure different headers for different URL paths
- **Wildcard pattern matching**: Use `*` for simple patterns like `/api/*`
- **Regex pattern support**: Use full regex for complex patterns like `^/v[0-9]+/protected/.*$`
- **Global headers**: Apply headers to all requests (optional)
- **Case-sensitive/insensitive matching**: Configurable path matching behavior
- **Non-intrusive**: Only injects headers if they don't already exist in the request
- **Multiple pattern support**: Match requests against multiple patterns simultaneously

## Installation

The plugin is already included in the MCP Gateway plugins directory. To enable it:

1. Edit `plugins/config.yaml`
2. Uncomment and configure the `auth_header_injector` section
3. Restart the MCP Gateway server

## Configuration

### Basic Configuration

```yaml
plugins:
  - name: auth_header_injector
    kind: "plugins.auth_header_injector.auth_header_injector.AuthHeaderInjectorPlugin"
    description: "Injects authentication headers for HTTP requests to specific URL paths"
    enabled: true
    hooks:
      - "http_pre_request"
    priority: 10
    config:
      url_path_patterns:
        - pattern: "/api/*"
          headers:
            Authorization: "Bearer your-token-here"
          description: "API authentication"
```

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `url_path_patterns` | List[PathHeaderMapping] | No | `[]` | List of path patterns with their associated headers |
| `headers` | Dict[str, str] | No | `{}` | Global headers applied to all requests |
| `case_sensitive` | bool | No | `false` | Whether URL path matching should be case-sensitive |

### PathHeaderMapping Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `pattern` | str | Yes | URL path pattern (supports wildcards `*` and regex) |
| `headers` | Dict[str, str] | Yes | Dictionary of headers to inject for matching paths |
| `description` | str | No | Optional description of this mapping |

## Usage Examples

### Example 1: Bearer Token for API Endpoints

Add a Bearer token to all `/api/*` endpoints:

```yaml
config:
  url_path_patterns:
    - pattern: "/api/*"
      headers:
        Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
      description: "API endpoints authentication"
```

### Example 2: API Key for Specific Service

Add API key and service name headers for runtime endpoints:

```yaml
config:
  url_path_patterns:
    - pattern: "/runtimes/*"
      headers:
        X-API-Key: "sk-1234567890abcdef"
        X-Service-Name: "runtime-service"
      description: "Runtime service authentication"
```

### Example 3: Multiple Authentication Schemes

Configure different authentication for different services:

```yaml
config:
  url_path_patterns:
    # External API with Bearer token
    - pattern: "/external/api/*"
      headers:
        Authorization: "Bearer external-token-123"
        X-Client-ID: "client-456"
      description: "External API authentication"

    # Internal service with custom auth
    - pattern: "/internal/service/*"
      headers:
        X-Auth-Token: "internal-secret-789"
        X-Service-ID: "internal-svc"
      description: "Internal service authentication"
```

### Example 4: Regex Pattern for Versioned APIs

Use regex to match versioned API endpoints:

```yaml
config:
  url_path_patterns:
    # Matches /v1/protected/*, /v2/protected/*, etc.
    - pattern: "^/v[0-9]+/protected/.*$"
      headers:
        Authorization: "Bearer versioned-api-token"
      description: "Versioned protected endpoints"
```

### Example 5: Global Headers + Path-Specific Headers

Apply global headers to all requests, plus path-specific headers:

```yaml
config:
  # Global headers for ALL requests
  headers:
    X-Request-ID: "global-request-id"
    X-Client-Version: "1.0.0"

  # Path-specific headers
  url_path_patterns:
    - pattern: "/api/*"
      headers:
        Authorization: "Bearer api-token"
      description: "API authentication"
```

### Example 6: Case-Sensitive Matching

Enable case-sensitive path matching:

```yaml
config:
  case_sensitive: true
  url_path_patterns:
    # This will only match "/API/*", not "/api/*"
    - pattern: "/API/*"
      headers:
        Authorization: "Bearer uppercase-api-token"
```

## Pattern Matching

### Wildcard Patterns

Use `*` for simple wildcard matching:

- `/api/*` - Matches `/api/users`, `/api/posts`, `/api/anything`
- `/services/*/health` - Matches `/services/user/health`, `/services/auth/health`
- `*` - Matches all paths

### Regex Patterns

For complex matching, use full regex syntax:

- `^/v[0-9]+/.*$` - Matches `/v1/users`, `/v2/posts`, etc.
- `^/(api|services)/.*$` - Matches both `/api/*` and `/services/*`
- `^/users/[0-9]+$` - Matches `/users/123`, `/users/456`, but not `/users/abc`

**Note**: If your pattern contains `*` and doesn't start with `^`, it will be treated as a wildcard pattern and converted to regex automatically.

## How It Works

1. The plugin intercepts HTTP requests using the `http_pre_request` hook
2. It checks if the request path matches any configured patterns
3. For each match, it merges the configured headers into the request
4. Headers are only injected if they don't already exist in the request
5. The modified request continues through the normal processing pipeline

## Hook Type

This plugin uses the `http_pre_request` hook, which runs in the middleware layer **before** authentication processing. This allows the plugin to inject authentication headers that will then be used by the authentication system.

## Priority

The default priority is `10`. Lower numbers run first. Adjust the priority if you need this plugin to run before or after other HTTP plugins:

```yaml
priority: 5  # Run earlier (before plugins with priority 10)
priority: 15 # Run later (after plugins with priority 10)
```

## Logging

The plugin logs header injection events at the `INFO` level:

```
INFO: Injected 2 auth headers for GET /api/users: ['Authorization', 'X-Client-ID']
```

Enable debug logging to see more details about pattern matching.

## Security Considerations

1. **Sensitive Data**: Authentication tokens are sensitive. Ensure your `plugins/config.yaml` file is:
   - Not committed to version control (use `.gitignore`)
   - Has restricted file permissions (e.g., `chmod 600`)
   - Stored securely in production environments

2. **Environment Variables**: Consider using environment variables for tokens:
   ```yaml
   headers:
     Authorization: "${AUTH_TOKEN}"
   ```

3. **Header Precedence**: The plugin will NOT override existing headers. If a request already has an `Authorization` header, the plugin won't replace it.

4. **Pattern Security**: Be specific with patterns to avoid accidentally adding auth headers to public endpoints.

## Troubleshooting

### Headers Not Being Injected

1. **Check plugin is enabled**: Verify `enabled: true` in config
2. **Check pattern matching**: Enable debug logging to see if patterns match
3. **Check existing headers**: Plugin won't override existing headers
4. **Check priority**: Ensure plugin runs before authentication (priority < 50)

### Pattern Not Matching

1. **Test with wildcard**: Start with `/path/*` before trying complex regex
2. **Check case sensitivity**: Set `case_sensitive: false` for flexible matching
3. **Verify path format**: Paths should start with `/`
4. **Test regex separately**: Use a regex tester to validate complex patterns

### Configuration Errors

1. **YAML syntax**: Ensure proper indentation (2 spaces)
2. **Valid YAML**: Use a YAML validator to check syntax
3. **Plugin path**: Verify `kind` points to correct plugin class

## Examples in Production

### Microservices Authentication

```yaml
config:
  url_path_patterns:
    # User service
    - pattern: "/users/*"
      headers:
        Authorization: "Bearer user-service-token"
        X-Service: "user-service"

    # Auth service
    - pattern: "/auth/*"
      headers:
        Authorization: "Bearer auth-service-token"
        X-Service: "auth-service"

    # Data service
    - pattern: "/data/*"
      headers:
        Authorization: "Bearer data-service-token"
        X-Service: "data-service"
```

### Multi-Tenant Application

```yaml
config:
  url_path_patterns:
    # Tenant A
    - pattern: "/tenant-a/*"
      headers:
        Authorization: "Bearer tenant-a-token"
        X-Tenant-ID: "tenant-a"

    # Tenant B
    - pattern: "/tenant-b/*"
      headers:
        Authorization: "Bearer tenant-b-token"
        X-Tenant-ID: "tenant-b"
```

## API Reference

### AuthHeaderInjectorPlugin

Main plugin class that handles header injection.

**Methods:**

- `__init__(config: PluginConfig)` - Initialize the plugin with configuration
- `http_pre_request(payload: HttpPreRequestPayload, context: PluginContext) -> PluginResult[HttpHeaderPayload]` - Hook method called before request processing

### AuthHeaderInjectorConfig

Configuration model for the plugin.

**Attributes:**

- `url_path_patterns: list[PathHeaderMapping]` - List of path patterns
- `headers: Dict[str, str]` - Global headers
- `case_sensitive: bool` - Case-sensitive matching flag

### PathHeaderMapping

Model for individual path-to-headers mappings.

**Attributes:**

- `pattern: str` - URL path pattern
- `headers: Dict[str, str]` - Headers to inject
- `description: str | None` - Optional description

## License

Copyright 2025
SPDX-License-Identifier: Apache-2.0

## Author

ContextForge

## Version

0.1.0

## Support

For issues, questions, or contributions, please refer to the main MCP Gateway documentation or open an issue in the repository.
