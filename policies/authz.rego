package http.authz

# Default deny policy for all requests
default allow = false

# Allow access if tenant ID from token matches the expected tenant
allow {
    # Get tenant ID from JWT user info
    jwt_payload := parse_jwt_payload(input.attributes.request.http.headers["x-endpoint-api-userinfo"])
    tenant_id := jwt_payload.tenantId

    # Match against expected tenant ID
    tenant_id == input.expected_tenant_id
}

# Also allow if tenant ID is in Firebase claims
allow {
    # Get tenant ID from JWT user info
    jwt_payload := parse_jwt_payload(input.attributes.request.http.headers["x-endpoint-api-userinfo"])
    tenant_id := jwt_payload.firebase.tenant

    # Match against expected tenant ID
    tenant_id == input.expected_tenant_id
}

# Also allow for superadmin role
allow {
    # Get role from JWT user info
    jwt_payload := parse_jwt_payload(input.attributes.request.http.headers["x-endpoint-api-userinfo"])
    role := jwt_payload.role

    # Allow if superadmin
    role == "superadmin"
}

# Additional allow rule for OPTIONS requests (CORS preflight)
allow {
    input.attributes.request.http.method == "OPTIONS"
}

# Health check and metrics endpoints are always allowed
allow {
    path := input.attributes.request.http.path
    startswith(path, "/health") or startswith(path, "/metrics")
}

# Parse JWT payload from a header
parse_jwt_payload(header) = payload {
    # Strip any prefix
    header != ""

    # For base64 encoded user info (x-endpoint-api-userinfo)
    decoded := base64_decode(header)
    payload := json.unmarshal(decoded)
} else = payload {
    # For Authorization header with Bearer token
    startswith(header, "Bearer ")
    token := substring(header, 7, -1)

    # Split the token
    parts := split(token, ".")
    count(parts) >= 2

    # Decode the payload part
    payload_b64 := parts[1]
    padding_needed := 4 - (count(payload_b64) % 4)
    padding := concat("", array.concat(["="], array.range(0, padding_needed - 1)))
    payload_padded := concat("", [payload_b64, padding])
    payload_json := base64_decode(payload_padded)

    payload := json.unmarshal(payload_json)
} else = {
    # Default empty payload if parsing fails
}

# Helper function to decode base64
base64_decode(encoded) = decoded {
    # Add padding if needed
    padding_needed := 4 - (count(encoded) % 4)
    padding := concat("", array.concat(["="], array.range(0, padding_needed - 1)))
    padded := concat("", [encoded, padding])

    # Try standard base64 decoding
    decoded := base64.decode(padded)
}