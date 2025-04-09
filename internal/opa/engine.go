// Package opa provides OPA policy evaluation and management
package opa

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/rs/zerolog/log"
)

// Engine represents the OPA policy engine
type Engine struct {
	store    storage.Store
	compiler *ast.Compiler
	mutex    sync.RWMutex
	policies map[string]string
}

// NewEngine creates a new OPA engine and loads policies from the specified directory
func NewEngine(policyDir string) (*Engine, error) {
	// Create OPA engine
	engine := &Engine{
		store:    inmem.New(),
		policies: make(map[string]string),
	}

	// Load policies from directory
	if err := loadPoliciesFromDir(engine, policyDir); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return engine, nil
}

// Evaluate evaluates a policy query with the given input
func (e *Engine) Evaluate(ctx context.Context, input map[string]interface{}) (bool, error) {
	e.mutex.RLock()
	compiler := e.compiler
	e.mutex.RUnlock()

	if compiler == nil {
		return false, fmt.Errorf("OPA compiler not initialized")
	}

	// Create evaluation context with timeout
	evalCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	// Create rego query
	query := rego.New(
		rego.Query("data.http.authz.allow"),
		rego.Compiler(compiler),
		rego.Input(input),
	)

	// Evaluate policy
	rs, err := query.Eval(evalCtx)
	if err != nil {
		return false, fmt.Errorf("policy evaluation error: %w", err)
	}

	// Check results
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false, fmt.Errorf("no results from policy evaluation")
	}

	// Extract boolean result
	allowed, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("policy did not return a boolean")
	}

	return allowed, nil
}

// UpdatePolicy updates a policy in the engine
func (e *Engine) UpdatePolicy(name string, content string) error {
	e.mutex.Lock()
	e.policies[name] = content
	e.mutex.Unlock()

	return e.recompilePolicies()
}

// RemovePolicy removes a policy from the engine
func (e *Engine) RemovePolicy(name string) error {
	e.mutex.Lock()
	delete(e.policies, name)
	e.mutex.Unlock()

	return e.recompilePolicies()
}

// GetPolicies returns a copy of all policies
func (e *Engine) GetPolicies() map[string]string {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	policies := make(map[string]string, len(e.policies))
	for name, content := range e.policies {
		policies[name] = content
	}

	return policies
}

// recompilePolicies recompiles all policies
func (e *Engine) recompilePolicies() error {
	e.mutex.RLock()
	policies := make(map[string]string, len(e.policies))
	for name, content := range e.policies {
		policies[name] = content
	}
	e.mutex.RUnlock()

	// Compile modules
	compiler := ast.NewCompiler()
	modules := map[string]*ast.Module{}

	for name, content := range policies {
		module, err := ast.ParseModule(name, content)
		if err != nil {
			return fmt.Errorf("failed to parse module %s: %w", name, err)
		}
		modules[name] = module
	}

	if compiler.Compile(modules); compiler.Failed() {
		return fmt.Errorf("policy compilation failed: %v", compiler.Errors)
	}

	// Update compiler
	e.mutex.Lock()
	e.compiler = compiler
	e.mutex.Unlock()

	log.Info().Int("policyCount", len(policies)).Msg("OPA policies compiled successfully")
	return nil
}
