package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/emphereio/auth-proxy/internal/opa"
	"github.com/emphereio/auth-proxy/internal/proxy"
	"github.com/emphereio/auth-proxy/internal/server"
	"github.com/emphereio/auth-proxy/pkg/logging"
	"github.com/rs/zerolog/log"
)

func main() {
	// Initialize logging
	logging.Setup()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	log.Info().
		Str("port", cfg.Port).
		Str("backend", cfg.BackendHost+":"+cfg.BackendPort).
		Str("policyDir", cfg.PolicyDir).
		Msg("Starting auth proxy with embedded OPA")

	// Initialize OPA engine
	opaEngine, err := opa.NewEngine(cfg.PolicyDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize OPA engine")
	}

	// Start policy watcher in background
	watcher, err := opa.NewWatcher(opaEngine, cfg.PolicyDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize policy watcher")
	}
	go watcher.Start()
	defer watcher.Stop()

	// Create reverse proxy
	reverseProxy, err := proxy.NewReverseProxy(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create reverse proxy")
	}

	// Create and start HTTP server
	srv := server.New(cfg, reverseProxy, opaEngine)
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatal().Err(err).Msg("Server failed to start")
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("Shutting down server...")

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	// Shutdown the server
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server exited properly")
}
