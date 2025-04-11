package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper function to generate a fake RSA key pair
func generateTestRSAKey() (*rsa.PrivateKey, string, error) {
	// Generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	// Create PEM block for the public key
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(publicKeyBlock))

	return privateKey, publicKeyPem, nil
}

// Test helper to generate a signed JWT token for testing
func generateTestToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims *CustomClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err, "Failed to sign test token")
	return tokenString
}

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
			token := ExtractTokenFromHeader(tc.authHeader)
			assert.Equal(t, tc.expectedToken, token)
		})
	}
}

// For tests that need to mock the Firebase public keys endpoint
func setupMockFirebaseServer(t *testing.T) (*httptest.Server, string, *rsa.PrivateKey) {
	// Generate a test RSA key pair
	privateKey, publicKeyPem, err := generateTestRSAKey()
	require.NoError(t, err, "Failed to generate test RSA key")

	// Create a mock key ID
	kid := "test-key-id-1"

	// Setup a mock server that returns our test public key
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a response similar to Firebase's format
		keys := map[string]string{
			kid: publicKeyPem,
		}

		// Set cache-control header to test expiry handling
		w.Header().Set("Cache-Control", "public, max-age=21600")
		w.Header().Set("Content-Type", "application/json")

		// Write the response
		json.NewEncoder(w).Encode(keys)
	}))

	return server, kid, privateKey
}

// TestInitJWTVerification tests JWT initialization using a modified package variable
func TestInitJWTVerification(t *testing.T) {
	// Setup a mock server for Firebase public keys
	server, kid, _ := setupMockFirebaseServer(t)
	defer server.Close()

	// Save original HTTP client and restore after test
	originalClient := http.DefaultClient
	defer func() { http.DefaultClient = originalClient }()

	// Create a custom client that redirects to our test server
	http.DefaultClient = &http.Client{
		Transport: &mockTransport{
			server: server,
		},
	}

	// Clear any existing keys
	publicKeysMutex.Lock()
	publicKeys = make(map[string]interface{})
	publicKeysMutex.Unlock()

	// Call the initialization function
	err := InitJWTVerification()
	assert.NoError(t, err, "InitJWTVerification should not return an error")

	// Verify that we've loaded keys
	publicKeysMutex.RLock()
	keyCount := len(publicKeys)
	hasKey := publicKeys[kid] != nil
	publicKeysMutex.RUnlock()

	assert.Equal(t, 1, keyCount, "Should have loaded exactly one public key")
	assert.True(t, hasKey, "Should have loaded the key with expected ID")
}

// mockTransport intercepts HTTP requests and redirects them to our test server
type mockTransport struct {
	server *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only intercept requests to the Firebase public keys URL
	if req.URL.String() == FirebasePublicKeysURL {
		// Create a new request to our test server
		newReq, err := http.NewRequest(req.Method, m.server.URL, req.Body)
		if err != nil {
			return nil, err
		}

		// Copy headers
		newReq.Header = req.Header

		// Send the request to our test server
		return m.server.Client().Do(newReq)
	}

	// For other requests, use the default transport
	return http.DefaultTransport.RoundTrip(req)
}

// TestVerifyToken tests the VerifyToken function
func TestVerifyToken(t *testing.T) {
	// Setup a mock server
	server, kid, privateKey := setupMockFirebaseServer(t)
	defer server.Close()

	// Save original HTTP client and restore after test
	originalClient := http.DefaultClient
	defer func() { http.DefaultClient = originalClient }()

	// Create a custom client that redirects to our test server
	http.DefaultClient = &http.Client{
		Transport: &mockTransport{
			server: server,
		},
	}

	// Initialize JWT verification to load our mock keys
	err := InitJWTVerification()
	require.NoError(t, err, "Failed to initialize JWT verification")

	// Create a valid token
	validClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		TenantID: "tenant456",
	}
	validToken := generateTestToken(t, privateKey, kid, validClaims)

	// Create an expired token
	expiredClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
		TenantID: "tenant456",
	}
	expiredToken := generateTestToken(t, privateKey, kid, expiredClaims)

	// Create a token with firebase tenant info
	firebaseTenantClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	firebaseTenantClaims.Firebase.Tenant = "firebase789"
	firebaseTenantToken := generateTestToken(t, privateKey, kid, firebaseTenantClaims)

	// Create a token with unknown key ID
	unknownKidToken := generateTestToken(t, privateKey, "unknown-kid", validClaims)

	// Test cases
	testCases := []struct {
		name        string
		token       string
		expectError bool
		checkClaims func(t *testing.T, claims *CustomClaims)
	}{
		{
			name:        "ValidToken",
			token:       validToken,
			expectError: false,
			checkClaims: func(t *testing.T, claims *CustomClaims) {
				assert.Equal(t, "user123", claims.Subject)
				assert.Equal(t, "tenant456", claims.TenantID)
			},
		},
		{
			name:        "ExpiredToken",
			token:       expiredToken,
			expectError: true,
			checkClaims: nil,
		},
		{
			name:        "FirebaseTenantToken",
			token:       firebaseTenantToken,
			expectError: false,
			checkClaims: func(t *testing.T, claims *CustomClaims) {
				assert.Equal(t, "user123", claims.Subject)
				assert.Equal(t, "firebase789", claims.Firebase.Tenant)
			},
		},
		{
			name:        "EmptyToken",
			token:       "",
			expectError: true,
			checkClaims: nil,
		},
		{
			name:        "InvalidToken",
			token:       "not.a.valid.token",
			expectError: true,
			checkClaims: nil,
		},
		{
			name:        "UnknownKidToken",
			token:       unknownKidToken,
			expectError: true,
			checkClaims: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := VerifyToken(tc.token)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
				if tc.checkClaims != nil {
					tc.checkClaims(t, claims)
				}
			}
		})
	}
}

// TestExtractTenantID tests the ExtractTenantID function
func TestExtractTenantID(t *testing.T) {
	// Setup a mock server
	server, kid, privateKey := setupMockFirebaseServer(t)
	defer server.Close()

	// Save original HTTP client and restore after test
	originalClient := http.DefaultClient
	defer func() { http.DefaultClient = originalClient }()

	// Create a custom client that redirects to our test server
	http.DefaultClient = &http.Client{
		Transport: &mockTransport{
			server: server,
		},
	}

	// Initialize JWT verification to load our mock keys
	err := InitJWTVerification()
	require.NoError(t, err, "Failed to initialize JWT verification")

	// Create tokens with different tenant configurations
	regularTenantClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		TenantID: "tenant456",
	}
	regularTenantToken := generateTestToken(t, privateKey, kid, regularTenantClaims)

	firebaseTenantClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	firebaseTenantClaims.Firebase.Tenant = "firebase789"
	firebaseTenantToken := generateTestToken(t, privateKey, kid, firebaseTenantClaims)

	bothTenantsClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		TenantID: "tenant456",
	}
	bothTenantsClaims.Firebase.Tenant = "firebase789"
	bothTenantsToken := generateTestToken(t, privateKey, kid, bothTenantsClaims)

	testCases := []struct {
		name             string
		setupRequest     func() *http.Request
		expectedTenantID string
	}{
		{
			name: "EmptyAuthHeader",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				return req
			},
			expectedTenantID: "",
		},
		{
			name: "InvalidToken",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Authorization", "Bearer invalid-token")
				return req
			},
			expectedTenantID: "",
		},
		{
			name: "RegularTenantID",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Authorization", "Bearer "+regularTenantToken)
				return req
			},
			expectedTenantID: "tenant456",
		},
		{
			name: "FirebaseTenant",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Authorization", "Bearer "+firebaseTenantToken)
				return req
			},
			expectedTenantID: "firebase789",
		},
		{
			name: "BothTenants_PreferRegular",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Authorization", "Bearer "+bothTenantsToken)
				return req
			},
			expectedTenantID: "tenant456", // Should prefer TenantID over Firebase.Tenant
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.setupRequest()
			tenantID := ExtractTenantID(req)
			assert.Equal(t, tc.expectedTenantID, tenantID)
		})
	}
}

// TestPublicKeyRefresh tests the key refresh functionality
func TestPublicKeyRefresh(t *testing.T) {
	// We'll set up two different servers for the two different sets of keys
	var keyRotationMutex sync.Mutex
	keyRotation := 0

	// Generate two different key pairs
	privateKey1, publicKeyPem1, err := generateTestRSAKey()
	require.NoError(t, err, "Failed to generate first test key")

	_, publicKeyPem2, err := generateTestRSAKey()
	require.NoError(t, err, "Failed to generate second test key")

	// Setup a mock server that returns different keys on subsequent calls
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyRotationMutex.Lock()
		currentRotation := keyRotation
		keyRotation++
		keyRotationMutex.Unlock()

		var keys map[string]string

		// First call returns the first key
		if currentRotation == 0 {
			keys = map[string]string{
				"key-id-1": publicKeyPem1,
			}
		} else {
			// Subsequent calls return a different key
			keys = map[string]string{
				"key-id-2": publicKeyPem2,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=21600")
		json.NewEncoder(w).Encode(keys)
	}))
	defer server.Close()

	// Save original HTTP client and restore after test
	originalClient := http.DefaultClient
	defer func() { http.DefaultClient = originalClient }()

	// Create a custom client that redirects to our test server
	http.DefaultClient = &http.Client{
		Transport: &mockTransport{
			server: server,
		},
	}

	// Initialize JWT verification with the first key
	err = InitJWTVerification()
	require.NoError(t, err, "Failed to initialize JWT verification")

	// Capture the initial state
	publicKeysMutex.RLock()
	initialKeys := make(map[string]bool)
	for kid := range publicKeys {
		initialKeys[kid] = true
	}
	publicKeysMutex.RUnlock()

	// Force a key refresh to get the second key
	err = fetchFirebasePublicKeys()
	assert.NoError(t, err, "Key refresh should not fail")

	// Verify keys have changed
	publicKeysMutex.RLock()
	newKeys := make(map[string]bool)
	for kid := range publicKeys {
		newKeys[kid] = true
	}
	publicKeysMutex.RUnlock()

	// Check that the keys have actually changed
	assert.NotEqual(t, initialKeys, newKeys, "Keys should have changed after refresh")
	assert.Equal(t, 2, keyRotation, "Server should have been called twice")

	// Create a valid token with the first key to verify it's still working
	validClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	// This token uses key-id-1, which should no longer be in the keys after refresh
	// So verification should fail
	tokenWithOldKey := generateTestToken(t, privateKey1, "key-id-1", validClaims)
	_, err = VerifyToken(tokenWithOldKey)
	assert.Error(t, err, "Token with old key should fail verification after key rotation")
}
