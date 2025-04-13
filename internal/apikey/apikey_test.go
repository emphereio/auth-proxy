package apikey

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvKeyManager(t *testing.T) {
	// Setup test environment variables
	os.Setenv("API_KEY_TEST", "test-api-key")
	os.Setenv("API_KEY_DEV", "dev-api-key")
	defer func() {
		os.Unsetenv("API_KEY_TEST")
		os.Unsetenv("API_KEY_DEV")
	}()

	manager := NewEnvKeyManager()

	t.Run("ValidTenantID", func(t *testing.T) {
		key := manager.GetKeyForTenant("test")
		assert.Equal(t, "test-api-key", key)

		key = manager.GetKeyForTenant("dev")
		assert.Equal(t, "dev-api-key", key)
	})

	t.Run("CaseInsensitivity", func(t *testing.T) {
		key := manager.GetKeyForTenant("TEST")
		assert.Equal(t, "test-api-key", key)

		key = manager.GetKeyForTenant("Dev")
		assert.Equal(t, "dev-api-key", key)
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		key := manager.GetKeyForTenant("nonexistent")
		assert.Empty(t, key)
	})
}

func TestStaticKeyManager(t *testing.T) {
	// Setup test keys
	keys := map[string]string{
		"test": "test-api-key",
		"dev":  "dev-api-key",
	}

	manager := NewStaticKeyManager(keys)

	t.Run("ValidTenantID", func(t *testing.T) {
		key := manager.GetKeyForTenant("test")
		assert.Equal(t, "test-api-key", key)

		key = manager.GetKeyForTenant("dev")
		assert.Equal(t, "dev-api-key", key)
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		key := manager.GetKeyForTenant("nonexistent")
		assert.Empty(t, key)
	})

	t.Run("SetKeyForTenant", func(t *testing.T) {
		manager.SetKeyForTenant("new-tenant", "new-api-key")
		key := manager.GetKeyForTenant("new-tenant")
		assert.Equal(t, "new-api-key", key)

		// Update existing key
		manager.SetKeyForTenant("test", "updated-key")
		key = manager.GetKeyForTenant("test")
		assert.Equal(t, "updated-key", key)
	})

	t.Run("CaseSensitivity", func(t *testing.T) {
		// Static key manager should be case-sensitive
		key := manager.GetKeyForTenant("TEST")
		assert.Empty(t, key)
	})
}

func TestDefaultManager(t *testing.T) {
	manager := NewDefaultManager("global-api-key")

	t.Run("AnyTenantID", func(t *testing.T) {
		key := manager.GetKeyForTenant("test")
		assert.Equal(t, "global-api-key", key)

		key = manager.GetKeyForTenant("dev")
		assert.Equal(t, "global-api-key", key)

		key = manager.GetKeyForTenant("nonexistent")
		assert.Equal(t, "global-api-key", key)

		key = manager.GetKeyForTenant("")
		assert.Equal(t, "global-api-key", key)
	})
}

func TestChainedKeyManager(t *testing.T) {
	// Setup test environment variables
	os.Setenv("API_KEY_ENV", "env-api-key")
	defer os.Unsetenv("API_KEY_ENV")

	// Setup static keys
	staticKeys := map[string]string{
		"static": "static-api-key",
		"both":   "static-both-key", // This one should be overridden by env
	}

	// Create individual managers
	envManager := NewEnvKeyManager()
	staticManager := NewStaticKeyManager(staticKeys)
	defaultManager := NewDefaultManager("default-api-key")

	// Create chained manager with env taking precedence
	chainedManager := NewChainedKeyManager(envManager, staticManager, defaultManager)

	t.Run("FirstManagerMatch", func(t *testing.T) {
		// This should come from env manager
		key := chainedManager.GetKeyForTenant("env")
		assert.Equal(t, "env-api-key", key)
	})

	t.Run("SecondManagerMatch", func(t *testing.T) {
		// This should come from static manager
		key := chainedManager.GetKeyForTenant("static")
		assert.Equal(t, "static-api-key", key)
	})

	t.Run("ThirdManagerMatch", func(t *testing.T) {
		// This should fall through to the default manager
		key := chainedManager.GetKeyForTenant("nonexistent")
		assert.Equal(t, "default-api-key", key)
	})

	t.Run("EmptyChain", func(t *testing.T) {
		emptyManager := NewChainedKeyManager()
		key := emptyManager.GetKeyForTenant("test")
		assert.Empty(t, key)
	})
}

func TestEmptyKeys(t *testing.T) {
	t.Run("EmptyEnvKey", func(t *testing.T) {
		os.Setenv("API_KEY_EMPTY", "")
		defer os.Unsetenv("API_KEY_EMPTY")

		manager := NewEnvKeyManager()
		key := manager.GetKeyForTenant("empty")
		assert.Empty(t, key)
	})

	t.Run("EmptyStaticKey", func(t *testing.T) {
		manager := NewStaticKeyManager(map[string]string{
			"empty": "",
		})
		key := manager.GetKeyForTenant("empty")
		assert.Empty(t, key)
	})

	t.Run("EmptyDefaultKey", func(t *testing.T) {
		manager := NewDefaultManager("")
		key := manager.GetKeyForTenant("test")
		assert.Empty(t, key)
	})
}
