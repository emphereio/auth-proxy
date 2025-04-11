package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

const (
	// FirebasePublicKeysURL is firebase's public key URL
	FirebasePublicKeysURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
)

// Store for the public keys with mutex for thread-safe access
var (
	publicKeys      map[string]interface{} = make(map[string]interface{})
	publicKeysMutex                        = &sync.RWMutex{}
)

// CustomClaims defines the claims we expect in Firebase tokens
type CustomClaims struct {
	jwt.RegisteredClaims
	TenantID string `json:"tenantId,omitempty"`
	Firebase struct {
		Tenant string `json:"tenant,omitempty"`
	} `json:"firebase,omitempty"`
}

// InitJWTVerification initializes the JWT verification system
func InitJWTVerification() error {
	// Fetch public keys immediately on startup
	if err := fetchFirebasePublicKeys(); err != nil {
		return err
	}

	// Start a background goroutine to refresh keys periodically
	go refreshKeysWorker()

	return nil
}

// refreshKeysWorker periodically refreshes the public keys
func refreshKeysWorker() {
	ticker := time.NewTicker(6 * time.Hour) // Refresh every 6 hours
	defer ticker.Stop()

	for range ticker.C {
		if err := fetchFirebasePublicKeys(); err != nil {
			log.Error().Err(err).Msg("Failed to refresh Firebase public keys")
		} else {
			log.Info().Msg("Successfully refreshed Firebase public keys")
		}
	}
}

// fetchFirebasePublicKeys fetches the latest public keys from Firebase
func fetchFirebasePublicKeys() error {
	resp, err := http.Get(FirebasePublicKeysURL)
	if err != nil {
		return fmt.Errorf("failed to fetch Firebase public keys: %w", err)
	}
	defer resp.Body.Close()

	// Parse the response
	var keys map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return fmt.Errorf("failed to parse Firebase public keys: %w", err)
	}

	// Convert the string keys to crypto objects
	newKeys := make(map[string]interface{})
	for kid, cert := range keys {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		if err != nil {
			log.Warn().Err(err).Str("kid", kid).Msg("Failed to parse public key, skipping")
			continue
		}
		newKeys[kid] = publicKey
	}

	// Update keys with a write lock
	publicKeysMutex.Lock()
	publicKeys = newKeys
	publicKeysMutex.Unlock()

	log.Info().Int("keyCount", len(newKeys)).Msg("Loaded Firebase public keys")
	return nil
}

// ExtractTokenFromHeader extracts a JWT token from an Authorization header
func ExtractTokenFromHeader(authHeader string) string {
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return authHeader
}

// VerifyToken verifies a Firebase ID token
func VerifyToken(tokenString string) (*CustomClaims, error) {
	// Parse the token
	publicKeysMutex.RLock()
	currentKeys := publicKeys
	publicKeysMutex.RUnlock()

	if len(currentKeys) == 0 {
		return nil, fmt.Errorf("no public keys available for verification")
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Make sure the algorithm is as expected
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get the key ID
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing key ID")
		}

		// Get the public key for this kid
		publicKeysMutex.RLock()
		key, exists := publicKeys[kid]
		publicKeysMutex.RUnlock()

		if !exists {
			// If the key doesn't exist, try refreshing once
			if err := fetchFirebasePublicKeys(); err != nil {
				return nil, fmt.Errorf("key ID not found and refresh failed: %w", err)
			}

			// Check again after refresh
			publicKeysMutex.RLock()
			key, exists = publicKeys[kid]
			publicKeysMutex.RUnlock()

			if !exists {
				return nil, fmt.Errorf("key ID not found after refresh")
			}
		}

		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract custom claims")
	}

	return claims, nil
}

// ExtractTenantID extracts the tenant ID from the request
func ExtractTenantID(r *http.Request) string {
	log.Debug().
		Str("authorization", r.Header.Get("Authorization")).
		Msg("Extracting tenant ID")

	// Get the authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Warn().Msg("Authorization header is empty")
		return ""
	}

	// Extract token from Authorization header
	token := ExtractTokenFromHeader(authHeader)

	// Verify the token
	claims, err := VerifyToken(token)
	if err != nil {
		log.Error().
			Err(err).
			Str("token", token).
			Msg("Failed to verify token")
		return ""
	}

	// Check tenantId field first
	if claims.TenantID != "" {
		log.Debug().
			Str("source", "token.tenantId").
			Str("tenantID", claims.TenantID).
			Msg("Found tenant ID")
		return claims.TenantID
	}

	// Try Firebase tenant
	if claims.Firebase.Tenant != "" {
		log.Debug().
			Str("source", "token.firebase.tenant").
			Str("tenantID", claims.Firebase.Tenant).
			Msg("Found tenant ID")
		return claims.Firebase.Tenant
	}

	log.Warn().Msg("No tenant ID found in claims")
	return ""
}
