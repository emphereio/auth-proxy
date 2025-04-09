package opa

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEngine(t *testing.T) {
	// Create a temporary directory for test policies
	tmpDir, err := os.MkdirTemp("", "opa-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test with empty directory (should load default policy)
	t.Run("EmptyDirectory", func(t *testing.T) {
		engine, err := NewEngine(tmpDir)
		assert.NoError(t, err)
		assert.NotNil(t, engine)
	})

	// Test with a valid policy
	t.Run("ValidPolicy", func(t *testing.T) {
		// Create a simple valid policy
		policyContent := `
		package http.authz
		default allow = false
		allow { true }
		`

		policyFile := filepath.Join(tmpDir, "test.rego")
		err = os.WriteFile(policyFile, []byte(policyContent), 0644)
		require.NoError(t, err)

		engine, err := NewEngine(tmpDir)
		assert.NoError(t, err)
		assert.NotNil(t, engine)
	})

	// Test with an invalid policy
	t.Run("InvalidPolicy", func(t *testing.T) {
		// Create a syntactically invalid policy
		invalidContent := `
		package http.authz
		default allow = 
		allow { true
		`

		invalidFile := filepath.Join(tmpDir, "invalid.rego")
		err = os.WriteFile(invalidFile, []byte(invalidContent), 0644)
		require.NoError(t, err)

		// Cleanup the valid policy to ensure we only have the invalid one
		err = os.Remove(filepath.Join(tmpDir, "test.rego"))
		require.NoError(t, err)

		// This should still work, as it will fall back to the default policy
		engine, err := NewEngine(tmpDir)
		// We've changed the behavior to handle errors internally and not return them
		assert.NoError(t, err)
		assert.NotNil(t, engine)
	})

	// Test with non-existent directory
	t.Run("NonExistentDirectory", func(t *testing.T) {
		nonExistentDir := filepath.Join(tmpDir, "non-existent")
		engine, err := NewEngine(nonExistentDir)
		assert.NoError(t, err) // Should fall back to default policy
		assert.NotNil(t, engine)
	})
}

func TestEvaluate(t *testing.T) {
	// Create a temporary directory for test policies
	tmpDir, err := os.MkdirTemp("", "opa-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a test policy that grants access if tenant matches
	policyContent := `
	package http.authz
	
	default allow = false
	
	allow {
		input.attributes.request.http.headers["x-tenant-id"] == input.expected_tenant_id
	}
	`

	policyFile := filepath.Join(tmpDir, "tenant_policy.rego")
	err = os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	// Create the engine
	engine, err := NewEngine(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, engine)

	// Test cases for policy evaluation
	testCases := []struct {
		name     string
		input    map[string]interface{}
		expected bool
	}{
		{
			name: "AllowedRequest",
			input: map[string]interface{}{
				"attributes": map[string]interface{}{
					"request": map[string]interface{}{
						"http": map[string]interface{}{
							"headers": map[string]interface{}{
								"x-tenant-id": "tenant123",
							},
						},
					},
				},
				"expected_tenant_id": "tenant123",
			},
			expected: true,
		},
		{
			name: "DeniedRequest",
			input: map[string]interface{}{
				"attributes": map[string]interface{}{
					"request": map[string]interface{}{
						"http": map[string]interface{}{
							"headers": map[string]interface{}{
								"x-tenant-id": "tenant123",
							},
						},
					},
				},
				"expected_tenant_id": "tenant456", // Different tenant
			},
			expected: false,
		},
		{
			name: "MissingTenantID",
			input: map[string]interface{}{
				"attributes": map[string]interface{}{
					"request": map[string]interface{}{
						"http": map[string]interface{}{
							"headers": map[string]interface{}{},
						},
					},
				},
				"expected_tenant_id": "tenant123",
			},
			expected: false,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := engine.Evaluate(ctx, tc.input)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestUpdateRemovePolicy(t *testing.T) {
	// Create a temporary directory for test policies
	tmpDir, err := os.MkdirTemp("", "opa-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a simple default policy
	policyContent := `
	package http.authz
	default allow = false
	allow { input.allow == true }
	`

	policyFile := filepath.Join(tmpDir, "default.rego")
	err = os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	// Create the engine
	engine, err := NewEngine(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, engine)

	// Test updating a policy
	t.Run("UpdatePolicy", func(t *testing.T) {
		// Update the policy to always allow
		updatedPolicy := `
		package http.authz
		default allow = true
		`

		err = engine.UpdatePolicy("default.rego", updatedPolicy)
		assert.NoError(t, err)

		// Test that evaluation now returns true for any input
		ctx := context.Background()
		result, err := engine.Evaluate(ctx, map[string]interface{}{})
		assert.NoError(t, err)
		assert.True(t, result)
	})

	// Test adding a new policy
	t.Run("AddPolicy", func(t *testing.T) {
		// Add a new policy with deny rule
		newPolicy := `
		package http.authz
		
		deny { input.deny == true }
		
		# Override the default allow rule when deny is true
		allow = false {
			deny
		}
		`

		err = engine.UpdatePolicy("new_policy.rego", newPolicy)
		assert.NoError(t, err)

		// Test with input that should trigger deny rule
		ctx := context.Background()
		result, err := engine.Evaluate(ctx, map[string]interface{}{"deny": true})
		assert.NoError(t, err)
		assert.False(t, result, "Request should be denied when input.deny is true")

		// And verify that other requests still pass
		result, err = engine.Evaluate(ctx, map[string]interface{}{"deny": false})
		assert.NoError(t, err)
		assert.True(t, result, "Request should be allowed when input.deny is false")
	})

	// Test removing a policy
	t.Run("RemovePolicy", func(t *testing.T) {
		// Remove the new policy
		err = engine.RemovePolicy("new_policy.rego")
		assert.NoError(t, err)

		// Test that deny rule no longer applies
		ctx := context.Background()
		result, err := engine.Evaluate(ctx, map[string]interface{}{"deny": true})
		assert.NoError(t, err)
		assert.True(t, result) // Should be true because we're back to the "allow = true" default
	})
}

func TestGetPolicies(t *testing.T) {
	// Create a temporary directory for test policies
	tmpDir, err := os.MkdirTemp("", "opa-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create multiple policies
	policies := map[string]string{
		"policy1.rego": `package http.authz
		default allow = false
		allow { input.user == "admin" }`,
		"policy2.rego": `package http.authz
		allow { input.role == "superuser" }`,
	}

	for name, content := range policies {
		err = os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644)
		require.NoError(t, err)
	}

	// Create the engine
	engine, err := NewEngine(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, engine)

	// Get policies
	retrievedPolicies := engine.GetPolicies()

	// Check that we have the expected policies
	assert.Len(t, retrievedPolicies, 2)
	for name, content := range policies {
		assert.Contains(t, retrievedPolicies, name)
		assert.Contains(t, retrievedPolicies[name], content)
	}
}
