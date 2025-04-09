// Package server provides HTTP server setup and handler registration
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/emphereio/auth-proxy/internal/middleware"
	"github.com/emphereio/auth-proxy/internal/opa"
	"github.com/emphereio/auth-proxy/internal/proxy"
	"github.com/rs/zerolog/log"
)

// Server represents the HTTP server
type Server struct {
	server       *http.Server
	router       *http.ServeMux
	cfg          *config.Config
	opaEngine    *opa.Engine
	reverseProxy *proxy.ReverseProxy
}

// New creates a new server instance
func New(cfg *config.Config, reverseProxy *proxy.ReverseProxy, opaEngine *opa.Engine) *Server {
	// Create server
	server := &Server{
		router:       http.NewServeMux(),
		cfg:          cfg,
		opaEngine:    opaEngine,
		reverseProxy: reverseProxy,
	}

	// Register routes
	server.registerRoutes()

	// Create HTTP server
	server.server = &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      server.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server
}

// Start starts the HTTP server
func (s *Server) Start() error {
	log.Info().Str("port", s.cfg.Port).Msg("Server listening")
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// registerRoutes registers all HTTP routes
func (s *Server) registerRoutes() {
	// Create middleware chain
	chain := createMiddlewareChain(s.opaEngine, s.cfg)

	// Register health check endpoint
	s.router.HandleFunc("GET /health", healthCheckHandler())

	// Register metrics endpoint
	s.router.HandleFunc("GET /metrics", middleware.MetricsHandler())

	// Register debug endpoints (only in debug mode)
	s.registerDebugRoutes()

	// Register main proxy handler with middleware
	s.router.Handle("/", chain(s.reverseProxy))

	log.Info().Msg("Routes registered")
}

// registerDebugRoutes registers routes for debugging
func (s *Server) registerDebugRoutes() {
	// Policies debug endpoint (only in debug mode)
	s.router.HandleFunc("GET /debug/policies", func(w http.ResponseWriter, r *http.Request) {
		policies := s.opaEngine.GetPolicies()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(policies)
	})
}

// createMiddlewareChain creates a chain of middleware
func createMiddlewareChain(opaEngine *opa.Engine, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Apply middleware in reverse order (last added is executed first)
		handler := next

		// Add request context middleware (if needed)

		// Add tenant authorization middleware
		handler = middleware.Auth(opaEngine, cfg)(handler)

		// Add metrics collection middleware
		handler = middleware.Metrics()(handler)

		// Add request logging middleware
		handler = middleware.Logging()(handler)

		// Add recovery middleware
		handler = middleware.Recovery()(handler)

		return handler
	}
}

// healthCheckHandler returns a handler for the health check endpoint
func healthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"version": getVersion(),
		})
	}
}

// getVersion returns the current version of the application
func getVersion() string {
	// In a real application, this would come from build info
	return "1.0.0"
}
