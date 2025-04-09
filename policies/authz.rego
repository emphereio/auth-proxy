package http.authz

default allow = false

# Allow if tenant IDs from JWT and host match
allow {
    # Get tenant ID from JWT userinfo
    jwt_payload := parse_jwt_payload(input.attributes.request.http.headers["x-endpoint-api-userinfo"])
    tenant_from_jwt := jwt_payload.tenantId

    # Get tenant ID from host
    host := input.attributes.request.http.host
    parts := split(host, ".")
    count(parts) >= 2
    tenant_from_host := parts[0]

    # Both tenant IDs exist and match
    tenant_from_jwt != ""
    tenant_from_host != ""
    tenant_from_jwt == tenant_from_host

    # Also match against expected tenant ID
    input.expected_tenant_id == tenant_from_jwt
}

# Allow if tenant ID from header exactly matches expected
allow {
    # Both must exist and match exactly
    input.attributes.request.http.headers["x-tenant-id"] != ""
    input.expected_tenant_id != ""
    input.attributes.request.http.headers["x-tenant-id"] == input.expected_tenant_id
}

# Allow health and metrics endpoints
allow {
    path := input.attributes.request.http.path
    startswith(path, "/health")
}

allow {
    path := input.attributes.request.http.path
    startswith(path, "/metrics")
}

# Allow debug endpoints
allow {
    path := input.attributes.request.http.path
    startswith(path, "/debug/")
}

# Parse JWT payload from a header
parse_jwt_payload(header) = payload {
    header != ""
    decoded := base64_decode(header)
    payload := json.unmarshal(decoded)
} else = {}

# Helper function to decode base64 - fixed version without variable reassignment
base64_decode(encoded) = decoded {
    # No padding needed (multiple of 4)
    remainder := count(encoded) % 4
    remainder == 0
    decoded := base64.decode(encoded)
} else = decoded {
    # Need 1 padding character
    remainder := count(encoded) % 4
    remainder == 3
    decoded := base64.decode(concat("", [encoded, "="]))
} else = decoded {
    # Need 2 padding characters
    remainder := count(encoded) % 4
    remainder == 2
    decoded := base64.decode(concat("", [encoded, "=="]))
} else = decoded {
    # Need 3 padding characters
    remainder := count(encoded) % 4
    remainder == 1
    decoded := base64.decode(concat("", [encoded, "==="]))
}