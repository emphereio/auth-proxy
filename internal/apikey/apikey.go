package apikey

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// KeyManager defines the interface for retrieving API keys for tenants
type KeyManager interface {
	GetKeyForTenant(tenantID string) string
}

// EnvKeyManager retrieves API keys from environment variables
// Keys are expected to be in the format: API_KEY_{TENANT_ID}
type EnvKeyManager struct{}

// NewEnvKeyManager creates a new environment variable-based key manager
func NewEnvKeyManager() *EnvKeyManager {
	return &EnvKeyManager{}
}

// GetKeyForTenant retrieves the API key for a tenant from environment variables
func (m *EnvKeyManager) GetKeyForTenant(tenantID string) string {
	// Format: API_KEY_{TENANT_ID}
	envVar := fmt.Sprintf("API_KEY_%s", strings.ToUpper(tenantID))
	apiKey := os.Getenv(envVar)

	if apiKey == "" {
		log.Debug().Str("tenantID", tenantID).Str("envVar", envVar).Msg("No API key found for tenant")
		return ""
	}

	log.Debug().Str("tenantID", tenantID).Msg("Found API key for tenant")
	return apiKey
}

// StaticKeyManager uses a predefined map of tenant IDs to API keys
type StaticKeyManager struct {
	keys map[string]string
	mu   sync.RWMutex
}

// NewStaticKeyManager creates a new static key manager with the given mapping
func NewStaticKeyManager(keys map[string]string) *StaticKeyManager {
	return &StaticKeyManager{
		keys: keys,
	}
}

// GetKeyForTenant retrieves the API key for a tenant from the static mapping
func (m *StaticKeyManager) GetKeyForTenant(tenantID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	apiKey, exists := m.keys[tenantID]
	if !exists {
		log.Debug().Str("tenantID", tenantID).Msg("No API key found for tenant in static mapping")
		return ""
	}

	log.Debug().Str("tenantID", tenantID).Msg("Found API key for tenant in static mapping")
	return apiKey
}

// SetKeyForTenant sets the API key for a tenant in the static mapping
func (m *StaticKeyManager) SetKeyForTenant(tenantID, apiKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[tenantID] = apiKey
	log.Debug().Str("tenantID", tenantID).Msg("Set API key for tenant in static mapping")
}

// DefaultManager provides a fallback API key manager that always returns the same key
type DefaultManager struct {
	defaultKey string
}

// NewDefaultManager creates a key manager that always returns the same key
func NewDefaultManager(defaultKey string) *DefaultManager {
	return &DefaultManager{
		defaultKey: defaultKey,
	}
}

// GetKeyForTenant always returns the default API key
func (m *DefaultManager) GetKeyForTenant(tenantID string) string {
	log.Debug().Str("tenantID", tenantID).Msg("Using default API key for tenant")
	return m.defaultKey
}

// ChainedKeyManager tries multiple key managers in sequence
type ChainedKeyManager struct {
	managers []KeyManager
}

// NewChainedKeyManager creates a key manager that tries multiple managers in sequence
func NewChainedKeyManager(managers ...KeyManager) *ChainedKeyManager {
	return &ChainedKeyManager{
		managers: managers,
	}
}

// GetKeyForTenant tries each manager in sequence until a key is found
func (m *ChainedKeyManager) GetKeyForTenant(tenantID string) string {
	for _, manager := range m.managers {
		if key := manager.GetKeyForTenant(tenantID); key != "" {
			return key
		}
	}

	log.Debug().Str("tenantID", tenantID).Msg("No API key found in any manager")
	return ""
}
