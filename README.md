# Auth Proxy with Embedded OPA

A Go-based authentication and authorization proxy sidecar with embedded Open Policy Agent (OPA) for tenant isolation in multi-tenant applications.

## Features

- **Tenant Authorization**: Enforces tenant isolation using embedded OPA
- **JWT Parsing**: Extracts tenant information from JWT tokens provided by ESP
- **Policy Management**: Loads, watches, and updates OPA policies
- **Metrics Collection**: Provides HTTP request metrics
- **Logging**: Structured logging with configurable formats and levels
- **Health Checks**: HTTP endpoint for health monitoring
- **ESP Integration**: Works with Google's Extensible Service Proxy for authentication

## Architecture

The auth proxy sits between Google ESP and your backend service, implementing tenant isolation:

```
┌────────┐     ┌───────────┐     ┌───────────────┐     ┌────────────┐
│        │     │           │     │               │     │            │
│ Client ├────►│    ESP    ├────►│  Auth Proxy   ├────►│  Backend   │
│        │     │           │     │  with OPA     │     │  Service   │
└────────┘     └───────────┘     └───────────────┘     └────────────┘
                     │                   │  ▲
                     │                   │  │
                     ▼                   ▼  │
               ┌─────────────┐    ┌─────────────────┐
               │ Service Acct │    │   OPA Policies  │
               │    JSON      │    │   (ConfigMap)   │
               └─────────────┘    └─────────────────┘
```

## Getting Started

### Prerequisites

- Go 1.22+
- Docker (for containerization)
- Kubernetes (for deployment)
- Helm (for chart installation)

### Building

```bash
# Clone the repository
git clone https://github.com/emphereio/auth-proxy.git
cd auth-proxy

# Build the binary
go build -o auth-proxy ./cmd/main.go

# Build Docker image
docker build -t emphereio/auth-proxy:latest .
```

### Running Locally

```bash
# Run with default settings
./auth-proxy

# Run with custom configuration
export BACKEND_HOST=my-service
export BACKEND_PORT=8000
export TENANT_ID=your-tenant-id
export POLICY_DIR=./policies
export LOG_LEVEL=DEBUG
export LOG_FORMAT=console
./auth-proxy
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | Port to listen on | 8080 |
| BACKEND_HOST | Backend service host | localhost |
| BACKEND_PORT | Backend service port | 8000 |
| TENANT_ID | Expected tenant ID for validation | |
| POLICY_DIR | Directory containing OPA policies | /policies |
| REQUEST_TIMEOUT | Timeout for backend requests (seconds) | 10 |
| SHUTDOWN_TIMEOUT | Timeout for graceful shutdown (seconds) | 10 |
| LOG_LEVEL | Log level (TRACE, DEBUG, INFO, WARN, ERROR) | INFO |
| LOG_FORMAT | Log format (json, console) | json |
| ENVIRONMENT | Runtime environment (development, production) | production |
| POLICY_REFRESH_INTERVAL | Interval to check for policy updates (seconds) | 30 |

## Policy Configuration

The auth proxy uses OPA policies to control tenant access. Policies are written in Rego language and loaded from the `POLICY_DIR` directory.

### Default Policy

A default policy is provided that enforces tenant isolation by matching the tenant ID from JWT tokens with the expected tenant ID.

Example policy:

```rego
package http.authz

# Default deny policy for all requests
default allow = false

# Extract user info from JWT
user_info = info {
  # Extract from X-Endpoint-API-UserInfo header if available
  header := input.attributes.request.http.headers["x-endpoint-api-userinfo"]
  header != ""
  decoded := b64_decode(header)
  info := json.unmarshal(decoded)
}

# Allow access if tenant ID in token matches the expected tenant
allow {
  info := user_info
  info.tenantId == input.expected_tenant_id
}

# Also allow access for superadmin role
allow {
  info := user_info
  info.role == "superadmin"
}
```

### Custom Policies

You can create custom policies by placing `.rego` files in the policy directory. The proxy will automatically load and compile all policies in the directory.

## Deployment with ESP and Auth Engine

This auth proxy is designed to work as a sidecar alongside Google's Extensible Service Proxy (ESP) and your authentication engine:

```yaml
containers:
  - name: esp
    image: gcr.io/endpoints-release/endpoints-runtime:2.52.0
    args: [
      "--backend=http://127.0.0.1:8080",  # Point to auth-proxy
      # other ESP configuration...
    ]
    
  - name: auth-proxy
    image: emphereio/auth-proxy:latest
    env:
      - name: TENANT_ID
        value: "your-tenant-id"
      - name: BACKEND_HOST
        value: "localhost" 
      - name: BACKEND_PORT
        value: "5000"  # Port of your auth-engine
    volumeMounts:
      - name: auth-proxy-policies
        mountPath: /policies
        
  - name: auth-engine
    image: your-auth-engine:latest
    # your auth engine configuration...
```

## Project Structure

```
auth-proxy/
├── cmd/
│   └── main.go                       # Application entry point                     
├── internal/
│   ├── config/                       # Configuration loading and validation
│   │   └── config.go
│   ├── middleware/                   # HTTP middleware components
│   │   ├── auth.go                   # Authentication middleware
│   │   ├── logging.go                # Logging middleware 
│   │   ├── metrics.go                # Metrics middleware
│   │   └── recovery.go               # Recovery middleware
│   ├── opa/                          # OPA engine and policy management
│   │   ├── engine.go                 # OPA engine implementation
│   │   ├── policy.go                 # Policy loading and management
│   │   └── watcher.go                # Policy file watcher
│   ├── proxy/                        # Reverse proxy implementation
│   │   └── proxy.go                  # Reverse proxy setup
│   ├── server/                       # HTTP server setup
│   │   └── server.go                 # Server configuration
│   └── jwt/                          # JWT token parsing and validation
│       └── jwt.go                    # JWT processing
├── pkg/
│   └── logging/                      # Logging utilities
│       └── logging.go                # Zerolog configuration
├── policies/                         # Default OPA policies
│   └── authz.rego                    # Default authorization policy
├── Dockerfile                        # Container definition
├── go.mod                            # Go module file
└── README.md                         # This file
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.