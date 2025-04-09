package opa

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyManagement(t *testing.T) {
	// Create a temporary directory for test policies
	tmpDir, err := os.MkdirTemp("", "opa-management-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test CreatePolicy
	t.Run("CreatePolicy", func(t *testing.T) {
		policyName := "test_policy.rego"
		policyContent := `
		package http.authz
		default allow = false
		allow { input.user == "admin" }
		`

		err := CreatePolicy(tmpDir, policyName, policyContent)
		assert.NoError(t, err)

		// Verify file was created
		content, err := os.ReadFile(filepath.Join(tmpDir, policyName))
		assert.NoError(t, err)
		assert.Contains(t, string(content), "package http.authz")
	})

	// Test CreatePolicy adds .rego extension if missing
	t.Run("CreatePolicyWithoutExtension", func(t *testing.T) {
		policyName := "policy_without_extension"
		policyContent := `package http.authz
		allow { true }`

		err := CreatePolicy(tmpDir, policyName, policyContent)
		assert.NoError(t, err)

		// Verify file was created with .rego extension
		content, err := os.ReadFile(filepath.Join(tmpDir, policyName+".rego"))
		assert.NoError(t, err)
		assert.Contains(t, string(content), "package http.authz")
	})

	// Test GetPolicyContent
	t.Run("GetPolicyContent", func(t *testing.T) {
		policyName := "get_policy_test.rego"
		policyContent := `package http.authz
		default allow = false
		allow { input.role == "admin" }`

		// Create policy file
		err := os.WriteFile(filepath.Join(tmpDir, policyName), []byte(policyContent), 0644)
		require.NoError(t, err)

		// Get policy content
		content, err := GetPolicyContent(tmpDir, policyName)
		assert.NoError(t, err)
		assert.Equal(t, policyContent, content)
	})

	// Test GetPolicyContent adds .rego extension if missing
	t.Run("GetPolicyContentWithoutExtension", func(t *testing.T) {
		policyName := "extension_test.rego"
		policyContent := `package http.authz
		allow { input.authenticated }`

		// Create policy file
		err := os.WriteFile(filepath.Join(tmpDir, policyName), []byte(policyContent), 0644)
		require.NoError(t, err)

		// Get policy content without providing .rego extension
		content, err := GetPolicyContent(tmpDir, "extension_test")
		assert.NoError(t, err)
		assert.Equal(t, policyContent, content)
	})

	// Test GetPolicyContent with non-existent file
	t.Run("GetNonExistentPolicy", func(t *testing.T) {
		_, err := GetPolicyContent(tmpDir, "non_existent.rego")
		assert.Error(t, err)
	})

	// Test ListPolicies
	t.Run("ListPolicies", func(t *testing.T) {
		// We already have created several policies in previous tests
		policies, err := ListPolicies(tmpDir)
		assert.NoError(t, err)

		// Check that all created policies are listed
		expectedPolicies := []string{
			"test_policy.rego",
			"policy_without_extension.rego",
			"get_policy_test.rego",
			"extension_test.rego",
		}

		for _, expected := range expectedPolicies {
			assert.Contains(t, policies, expected)
		}
	})

	// Test DeletePolicy
	t.Run("DeletePolicy", func(t *testing.T) {
		policyName := "to_delete.rego"
		policyContent := `package http.authz
		default allow = true`

		// Create policy file
		err := os.WriteFile(filepath.Join(tmpDir, policyName), []byte(policyContent), 0644)
		require.NoError(t, err)

		// Delete policy
		err = DeletePolicy(tmpDir, policyName)
		assert.NoError(t, err)

		// Verify file was deleted
		_, err = os.Stat(filepath.Join(tmpDir, policyName))
		assert.True(t, os.IsNotExist(err))
	})

	// Test DeletePolicy adds .rego extension if missing
	t.Run("DeletePolicyWithoutExtension", func(t *testing.T) {
		policyName := "delete_without_extension.rego"
		policyContent := `package http.authz
		default allow = true`

		// Create policy file
		err := os.WriteFile(filepath.Join(tmpDir, policyName), []byte(policyContent), 0644)
		require.NoError(t, err)

		// Delete policy without providing .rego extension
		err = DeletePolicy(tmpDir, "delete_without_extension")
		assert.NoError(t, err)

		// Verify file was deleted
		_, err = os.Stat(filepath.Join(tmpDir, policyName))
		assert.True(t, os.IsNotExist(err))
	})

	// Test ListPolicies with non-existent directory
	t.Run("ListPoliciesNonExistentDir", func(t *testing.T) {
		nonExistentDir := filepath.Join(tmpDir, "non-existent")
		policies, err := ListPolicies(nonExistentDir)
		assert.NoError(t, err) // Should not error, just return empty list
		assert.Nil(t, policies)
	})
}
