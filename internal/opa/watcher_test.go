package opa

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatcher(t *testing.T) {
	// Create a temporary directory for test policies
	tmpDir, err := os.MkdirTemp("", "opa-watcher-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create initial policy file
	initialPolicy := `
	package http.authz
	default allow = false
	allow { input.user == "admin" }
	`

	policyFile := filepath.Join(tmpDir, "test.rego")
	err = os.WriteFile(policyFile, []byte(initialPolicy), 0644)
	require.NoError(t, err)

	// Create OPA engine
	engine, err := NewEngine(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, engine)

	// Test file modification detection
	t.Run("DetectFileModification", func(t *testing.T) {
		// Create and start the watcher with a short interval for testing
		watcher, err := NewWatcher(engine, tmpDir)
		require.NoError(t, err)
		require.NotNil(t, watcher)

		// Set a very short interval for testing
		watcher.SetInterval(500 * time.Millisecond)

		// Start the watcher
		go watcher.Start()
		defer watcher.Stop()

		// Get initial policies
		time.Sleep(100 * time.Millisecond) // Let watcher initialize
		_ = engine.GetPolicies()

		// Modify the policy file
		modifiedPolicy := `
package http.authz
default allow = false
allow { input.user == "superuser" }
`
		// Wait a moment to ensure file timestamp changes
		time.Sleep(1 * time.Second)

		err = os.WriteFile(policyFile, []byte(modifiedPolicy), 0644)
		require.NoError(t, err)

		// Wait for the watcher to detect changes
		time.Sleep(1 * time.Second)

		// Get updated policies
		updatedPolicies := engine.GetPolicies()

		// Verify the policy was updated
		assert.Contains(t, updatedPolicies, "test.rego")
		assert.Contains(t, updatedPolicies["test.rego"], "superuser")
	})

	// Test new file detection
	t.Run("DetectNewFile", func(t *testing.T) {
		// Create a new watcher for this test to avoid interference
		watcher, err := NewWatcher(engine, tmpDir)
		require.NoError(t, err)
		require.NotNil(t, watcher)
		watcher.SetInterval(500 * time.Millisecond)

		// Start the watcher
		go watcher.Start()
		defer watcher.Stop()
		time.Sleep(100 * time.Millisecond) // Let watcher initialize

		// Get initial policy count
		initialPolicies := engine.GetPolicies()
		initialCount := len(initialPolicies)

		// Create a new policy file
		newPolicy := `
		package http.authz
		allow { input.role == "manager" }
		`

		newPolicyFile := filepath.Join(tmpDir, "new_policy.rego")
		err = os.WriteFile(newPolicyFile, []byte(newPolicy), 0644)
		require.NoError(t, err)

		// Wait for the watcher to detect changes
		time.Sleep(1 * time.Second)

		// Get updated policies
		updatedPolicies := engine.GetPolicies()

		// Verify the new policy was added
		assert.Equal(t, initialCount+1, len(updatedPolicies))
		assert.Contains(t, updatedPolicies, "new_policy.rego")
		assert.Contains(t, updatedPolicies["new_policy.rego"], "manager")
	})

	// Test file deletion detection
	t.Run("DetectFileDeletion", func(t *testing.T) {
		// Create a new watcher for this test
		watcher, err := NewWatcher(engine, tmpDir)
		require.NoError(t, err)
		require.NotNil(t, watcher)
		watcher.SetInterval(500 * time.Millisecond)

		// Start the watcher
		go watcher.Start()
		defer watcher.Stop()
		time.Sleep(100 * time.Millisecond) // Let watcher initialize

		// Get initial policies
		initialPolicies := engine.GetPolicies()
		initialCount := len(initialPolicies)

		// Verify new_policy.rego exists from previous test
		assert.Contains(t, initialPolicies, "new_policy.rego")

		// Delete the policy file
		err = os.Remove(filepath.Join(tmpDir, "new_policy.rego"))
		require.NoError(t, err)

		// Wait for the watcher to detect changes
		time.Sleep(1 * time.Second)

		// Get updated policies
		updatedPolicies := engine.GetPolicies()

		// Verify the policy was removed
		assert.Equal(t, initialCount-1, len(updatedPolicies))
		assert.NotContains(t, updatedPolicies, "new_policy.rego")
	})

	// Test stopping the watcher
	t.Run("StopWatcher", func(t *testing.T) {
		// Create a new watcher
		watcher, err := NewWatcher(engine, tmpDir)
		require.NoError(t, err)
		require.NotNil(t, watcher)
		watcher.SetInterval(500 * time.Millisecond)

		// Start the watcher
		go watcher.Start()
		time.Sleep(100 * time.Millisecond)
		assert.True(t, watcher.IsRunning())

		// Stop the watcher
		watcher.Stop()
		time.Sleep(100 * time.Millisecond)
		assert.False(t, watcher.IsRunning())

		// Create a new policy file while watcher is stopped
		ignoredPolicy := `
		package http.authz
		allow { input.special == true }
		`

		ignoredFile := filepath.Join(tmpDir, "ignored.rego")
		err = os.WriteFile(ignoredFile, []byte(ignoredPolicy), 0644)
		require.NoError(t, err)

		// Wait longer than the poll interval
		time.Sleep(1 * time.Second)

		// Get policies
		policies := engine.GetPolicies()

		// Verify the file wasn't detected (watcher was stopped)
		assert.NotContains(t, policies, "ignored.rego")
	})
}
