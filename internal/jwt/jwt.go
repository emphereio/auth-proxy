// Package jwt provides JWT token parsing and validation
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// Payload represents a simplified JWT payload structure
type Payload struct {
	// Standard claims
	Subject string `json:"sub,omitempty"`

	// Custom claims for tenant identification
	TenantID string `json:"tenantId,omitempty"`
	Role     string `json:"role,omitempty"`

	// Nested structures for tenant identification
	Firebase struct {
		Tenant string `json:"tenant,omitempty"`
	} `json:"firebase,omitempty"`
}

// ExtractTokenFromHeader extracts a JWT token from an Authorization header
func ExtractTokenFromHeader(authHeader string) string {
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return authHeader
}

// DecodePayload decodes the payload portion of a JWT token
func DecodePayload(token string) (*Payload, error) {
	// Strip any Bearer prefix
	token = strings.TrimPrefix(token, "Bearer ")

	// Split the token to get the payload part (second part)
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token format: expected at least 2 parts")
	}

	// Get the payload part
	payloadBase64 := parts[1]

	// Add padding if needed
	if padding := len(payloadBase64) % 4; padding > 0 {
		payloadBase64 += strings.Repeat("=", 4-padding)
	}

	// Try standard base64 decoding first
	payloadJSON, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		// If that fails, try URL-safe base64 decoding
		payloadJSON, err = base64.URLEncoding.DecodeString(payloadBase64)
		if err != nil {
			// If that fails too, try Raw URL-safe base64 decoding
			payloadJSON, err = base64.RawURLEncoding.DecodeString(payloadBase64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode token payload: %w", err)
			}
		}
	}

	// Parse the JSON payload
	var payload Payload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse token payload: %w", err)
	}

	return &payload, nil
}

// ExtractTenantIDFromHost extracts the tenant ID from the subdomain
// e.g., from "tenantid.api.xyz.io" it extracts "tenantid"
func ExtractTenantIDFromHost(host string) string {
	// Split the host on dots
	parts := strings.Split(host, ".")

	// If we have enough parts (subdomain.domain.tld), extract the first part
	if len(parts) >= 3 {
		return parts[0]
	}

	return ""
}

// ExtractTenantID extracts the tenant ID from the request
func ExtractTenantID(r *http.Request) string {
	// Try to get from endpoint API userinfo header
	userInfoHeader := r.Header.Get("x-endpoint-api-userinfo")
	if userInfoHeader != "" {
		payload, err := DecodePayload(userInfoHeader)
		if err == nil {
			// Check tenantId field first
			if payload.TenantID != "" {
				log.Debug().Str("source", "userinfo.tenantId").Str("tenantID", payload.TenantID).Msg("Found tenant ID")
				return payload.TenantID
			}

			// Try Firebase tenant
			if payload.Firebase.Tenant != "" {
				log.Debug().Str("source", "userinfo.firebase.tenant").Str("tenantID", payload.Firebase.Tenant).Msg("Found tenant ID")
				return payload.Firebase.Tenant
			}
		}
	}

	// Try to get from header directly as fallback
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		log.Debug().Str("source", "header").Str("tenantID", tenantID).Msg("Found tenant ID")
		return tenantID
	}

	return ""
}
