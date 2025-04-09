package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emphereio/auth-proxy/internal/jwt"
	"github.com/stretchr/testify/assert"
)

func TestExtractTokenFromHeader(t *testing.T) {
	testCases := []struct {
		name          string
		authHeader    string
		expectedToken string
	}{
		{
			name:          "WithBearerPrefix",
			authHeader:    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		},
		{
			name:          "WithoutBearerPrefix",
			authHeader:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		},
		{
			name:          "EmptyHeader",
			authHeader:    "",
			expectedToken: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := jwt.ExtractTokenFromHeader(tc.authHeader)
			assert.Equal(t, tc.expectedToken, token)
		})
	}
}

func TestDecodePayload(t *testing.T) {
	// Create a valid payload with tenantId
	payload := jwt.Payload{
		Subject:  "user123",
		TenantID: "tenant456",
		Role:     "admin",
	}
	payloadJSON, _ := json.Marshal(payload)

	// Standard base64 encode the payload
	encodedPayload := base64.StdEncoding.EncodeToString(payloadJSON)
	// Create a mock JWT with the payload (use a dummy header and signature)
	tokenWithStdEncoding := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + encodedPayload + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// URL-safe base64 encode the payload
	encodedPayloadURL := base64.URLEncoding.EncodeToString(payloadJSON)
	// Create a mock JWT with the URL-safe payload
	tokenWithURLEncoding := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + encodedPayloadURL + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// Raw URL-safe base64 encode the payload (without padding)
	encodedPayloadRawURL := base64.RawURLEncoding.EncodeToString(payloadJSON)
	// Create a mock JWT with the Raw URL-safe payload
	tokenWithRawURLEncoding := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + encodedPayloadRawURL + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	testCases := []struct {
		name            string
		token           string
		expectedError   bool
		expectedPayload *jwt.Payload
	}{
		{
			name:          "ValidTokenWithStdEncoding",
			token:         tokenWithStdEncoding,
			expectedError: false,
			expectedPayload: &jwt.Payload{
				Subject:  "user123",
				TenantID: "tenant456",
				Role:     "admin",
			},
		},
		{
			name:          "ValidTokenWithURLEncoding",
			token:         tokenWithURLEncoding,
			expectedError: false,
			expectedPayload: &jwt.Payload{
				Subject:  "user123",
				TenantID: "tenant456",
				Role:     "admin",
			},
		},
		{
			name:          "ValidTokenWithRawURLEncoding",
			token:         tokenWithRawURLEncoding,
			expectedError: false,
			expectedPayload: &jwt.Payload{
				Subject:  "user123",
				TenantID: "tenant456",
				Role:     "admin",
			},
		},
		{
			name:          "TokenWithBearerPrefix",
			token:         "Bearer " + tokenWithStdEncoding,
			expectedError: false,
			expectedPayload: &jwt.Payload{
				Subject:  "user123",
				TenantID: "tenant456",
				Role:     "admin",
			},
		},
		{
			name:            "InvalidTokenFormat",
			token:           "not.a.valid.token",
			expectedError:   true,
			expectedPayload: nil,
		},
		{
			name:            "EmptyToken",
			token:           "",
			expectedError:   true,
			expectedPayload: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := jwt.DecodePayload(tc.token)

			if tc.expectedError {
				assert.Error(t, err)
				assert.Nil(t, payload)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedPayload.Subject, payload.Subject)
				assert.Equal(t, tc.expectedPayload.TenantID, payload.TenantID)
				assert.Equal(t, tc.expectedPayload.Role, payload.Role)
			}
		})
	}
}

func TestExtractTenantID(t *testing.T) {
	// Create a valid payload with tenantId
	createToken := func(tenantID string, firebaseTenant string) string {
		// Create payload
		payload := jwt.Payload{
			TenantID: tenantID,
		}
		if firebaseTenant != "" {
			payload.Firebase.Tenant = firebaseTenant
		}

		payloadJSON, _ := json.Marshal(payload)
		encodedPayload := base64.StdEncoding.EncodeToString(payloadJSON)

		// Create a proper JWT token format (header.payload.signature)
		// Using a dummy header and signature
		return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + encodedPayload + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	}

	testCases := []struct {
		name             string
		setupRequest     func() *http.Request
		expectedTenantID string
	}{
		{
			name: "FromUserInfoHeader",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("x-endpoint-api-userinfo", createToken("tenant123", ""))
				return req
			},
			expectedTenantID: "tenant123",
		},
		{
			name: "FromFirebaseTenant",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("x-endpoint-api-userinfo", createToken("", "firebase789"))
				return req
			},
			expectedTenantID: "firebase789",
		},
		{
			name: "FromTenantHeader",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Tenant-ID", "header456")
				return req
			},
			expectedTenantID: "header456",
		},
		{
			name: "PrecedenceOrder",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("x-endpoint-api-userinfo", createToken("userinfo555", ""))
				req.Header.Set("X-Tenant-ID", "header999")
				return req
			},
			expectedTenantID: "userinfo555", // Should prefer userinfo over header
		},
		{
			name: "NoTenantInfo",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com", nil)
			},
			expectedTenantID: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.setupRequest()
			tenantID := jwt.ExtractTenantID(req)
			assert.Equal(t, tc.expectedTenantID, tenantID)
		})
	}
}

func TestExtractTenantIDFromHost(t *testing.T) {
	testCases := []struct {
		name             string
		host             string
		expectedTenantID string
	}{
		{
			name:             "ValidSubdomain",
			host:             "tenant123.api.example.com",
			expectedTenantID: "tenant123",
		},
		{
			name:             "NoSubdomain",
			host:             "example.com",
			expectedTenantID: "",
		},
		{
			name:             "EmptyHost",
			host:             "",
			expectedTenantID: "",
		},
		{
			name:             "MultipleSubdomains",
			host:             "stage.tenant456.api.example.com",
			expectedTenantID: "stage", // Takes first part
		},
		{
			name:             "LocalhostWithPort",
			host:             "localhost:8080",
			expectedTenantID: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tenantID := jwt.ExtractTenantIDFromHost(tc.host)
			assert.Equal(t, tc.expectedTenantID, tenantID)
		})
	}
}
