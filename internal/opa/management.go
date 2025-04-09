// Package opa provides OPA policy evaluation and management
package opa

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// loadPoliciesFromDir loads Rego policies from a directory
func loadPoliciesFromDir(engine *Engine, policyDir string) error {
	// Check if policy directory exists
	info, err := os.Stat(policyDir)
	if os.IsNotExist(err) {
		log.Warn().Str("dir", policyDir).Msg("Policy directory does not exist, using default policy")
		return loadDefaultPolicy(engine)
	}

	// Check if the path is a directory
	if err == nil && !info.IsDir() {
		log.Warn().Str("path", policyDir).Msg("Policy path is not a directory, using default policy")
		return loadDefaultPolicy(engine)
	}

	// Read all files in the directory
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		log.Warn().Err(err).Str("dir", policyDir).Msg("Failed to read policy directory, using default policy")
		return loadDefaultPolicy(engine)
	}

	// No policies found, use default
	if len(entries) == 0 {
		log.Warn().Str("dir", policyDir).Msg("No policies found in directory, using default policy")
		return loadDefaultPolicy(engine)
	}

	// Load each .rego file
	policyCount := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}

		filePath := filepath.Join(policyDir, entry.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			log.Error().Err(err).Str("file", filePath).Msg("Failed to read policy file")
			continue
		}

		// Store policy content
		engine.mutex.Lock()
		engine.policies[entry.Name()] = string(content)
		engine.mutex.Unlock()

		policyCount++
		log.Info().Str("file", filePath).Msg("Loaded policy file")
	}

	// If no valid policies were loaded, use default
	if policyCount == 0 {
		log.Warn().Str("dir", policyDir).Msg("No valid policies found in directory, using default policy")
		return loadDefaultPolicy(engine)
	}

	// Compile policies
	return engine.recompilePolicies()
}

// loadDefaultPolicy loads a default policy that grants authorization only if tenant IDs match
func loadDefaultPolicy(engine *Engine) error {
	defaultPolicy := `
package http.authz

# Default deny
default allow = false

# Allow if the tenant ID in the token matches the tenant ID in the request header
allow {
    # Get tenant ID from request header
    input.attributes.request.http.headers["x-tenant-id"] != ""
    
    # Check if tenant IDs match
    input.attributes.request.http.headers["x-tenant-id"] == input.attributes.request.http.headers["authorization"]
}

# Additional allow rule for OPTIONS requests (CORS preflight)
allow {
    input.attributes.request.http.method == "OPTIONS"
}

# Health check and metrics endpoints are always allowed
allow {
    path := input.attributes.request.http.path
    startswith(path, "/health")
}

allow {
    path := input.attributes.request.http.path
    startswith(path, "/metrics")
}
`

	engine.mutex.Lock()
	engine.policies["default.rego"] = defaultPolicy
	engine.mutex.Unlock()

	log.Warn().Msg("Loaded default policy")
	return engine.recompilePolicies()
}

// CreatePolicy creates a new policy file
func CreatePolicy(policyDir string, name string, content string) error {
	// Ensure policy directory exists
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		return fmt.Errorf("failed to create policy directory: %w", err)
	}

	// Ensure file name has .rego extension
	if !strings.HasSuffix(name, ".rego") {
		name += ".rego"
	}

	// Create policy file
	filePath := filepath.Join(policyDir, name)
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	log.Info().Str("file", filePath).Msg("Created policy file")
	return nil
}

// DeletePolicy deletes a policy file
func DeletePolicy(policyDir string, name string) error {
	// Ensure file name has .rego extension
	if !strings.HasSuffix(name, ".rego") {
		name += ".rego"
	}

	// Delete policy file
	filePath := filepath.Join(policyDir, name)
	err := os.Remove(filePath)
	if err != nil {
		return fmt.Errorf("failed to delete policy file: %w", err)
	}

	log.Info().Str("file", filePath).Msg("Deleted policy file")
	return nil
}

// GetPolicyContent reads a policy file
func GetPolicyContent(policyDir string, name string) (string, error) {
	// Ensure file name has .rego extension
	if !strings.HasSuffix(name, ".rego") {
		name += ".rego"
	}

	// Read policy file
	filePath := filepath.Join(policyDir, name)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read policy file: %w", err)
	}

	return string(content), nil
}

// ListPolicies returns a list of policy files in the directory
func ListPolicies(policyDir string) ([]string, error) {
	// Check if policy directory exists
	_, err := os.Stat(policyDir)
	if os.IsNotExist(err) {
		return nil, nil
	}

	// Read all files in the directory
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy directory: %w", err)
	}

	// Filter for .rego files
	policies := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}
		policies = append(policies, entry.Name())
	}

	return policies, nil
}
