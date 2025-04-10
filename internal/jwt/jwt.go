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
	log.Debug().
		Str("raw_token", token).
		Msg("Attempting to decode payload")

	// First, try splitting by dots (full JWT)
	parts := strings.Split(token, ".")

	var payloadBase64 string
	if len(parts) >= 2 {
		// Full JWT, use second part
		payloadBase64 = parts[1]
	} else {
		// Assume it's already a base64 encoded payload
		payloadBase64 = token
	}

	log.Debug().
		Str("payload_base64", payloadBase64).
		Msg("Using payload base64")

	// Try decoding methods
	decodingMethods := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		func(s string) ([]byte, error) {
			if padding := len(s) % 4; padding > 0 {
				s += strings.Repeat("=", 4-padding)
			}
			return base64.RawURLEncoding.DecodeString(s)
		},
		func(s string) ([]byte, error) {
			if padding := len(s) % 4; padding > 0 {
				s += strings.Repeat("=", 4-padding)
			}
			return base64.StdEncoding.DecodeString(s)
		},
	}

	var payloadJSON []byte
	var err error
	for i, decodeFunc := range decodingMethods {
		payloadJSON, err = decodeFunc(payloadBase64)
		if err == nil {
			log.Debug().
				Int("attempt", i+1).
				Msg("Successfully decoded payload")
			break
		} else {
			log.Debug().
				Int("attempt", i+1).
				Err(err).
				Msg("Payload decoding attempt failed")
		}
	}

	if err != nil {
		log.Error().
			Str("payload_base64", payloadBase64).
			Msg("Failed to decode payload")
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	// Parse the JSON payload
	var payload Payload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		log.Error().
			Err(err).
			RawJSON("payload_json", payloadJSON).
			Msg("Failed to parse payload JSON")
		return nil, fmt.Errorf("failed to parse token payload: %w", err)
	}

	log.Debug().
		Str("tenantId", payload.TenantID).
		Msg("Decoded payload with tenant ID")

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
	log.Debug().
		Str("x-endpoint-api-userinfo", r.Header.Get("x-endpoint-api-userinfo")).
		Str("host", r.Host).
		Msg("Extracting tenant ID")

	// Try to get from endpoint API userinfo header
	userInfoHeader := r.Header.Get("x-endpoint-api-userinfo")
	if userInfoHeader == "" {
		log.Warn().Msg("x-endpoint-api-userinfo header is empty")
		return ""
	}

	payload, err := DecodePayload(userInfoHeader)
	if err != nil {
		log.Error().
			Err(err).
			Str("userInfoHeader", userInfoHeader).
			Msg("Failed to decode payload")
		return ""
	}

	// Check tenantId field first
	if payload.TenantID != "" {
		log.Debug().
			Str("source", "userinfo.tenantId").
			Str("tenantID", payload.TenantID).
			Msg("Found tenant ID")
		return payload.TenantID
	}

	// Try Firebase tenant
	if payload.Firebase.Tenant != "" {
		log.Debug().
			Str("source", "userinfo.firebase.tenant").
			Str("tenantID", payload.Firebase.Tenant).
			Msg("Found tenant ID")
		return payload.Firebase.Tenant
	}

	log.Warn().Msg("No tenant ID found in payload")
	return ""
}
