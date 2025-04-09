// Package proxy provides reverse proxy implementation
package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/emphereio/auth-proxy/internal/config"
	"github.com/rs/zerolog/log"
)

// ReverseProxy wraps httputil.ReverseProxy with additional functionality
type ReverseProxy struct {
	proxy *httputil.ReverseProxy
	cfg   *config.Config
}

// NewReverseProxy creates a new reverse proxy instance
func NewReverseProxy(cfg *config.Config) (*ReverseProxy, error) {
	// Construct backend URL
	backend := fmt.Sprintf("http://%s:%s", cfg.BackendHost, cfg.BackendPort)
	backendURL, err := url.Parse(backend)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL: %w", err)
	}

	// Create standard reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	// Customize director to modify requests
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		customizeRequest(req)
	}

	// Add error handler
	proxy.ErrorHandler = createErrorHandler()

	// Add response modifier
	proxy.ModifyResponse = createResponseModifier()

	return &ReverseProxy{
		proxy: proxy,
		cfg:   cfg,
	}, nil
}

// ServeHTTP implements the http.Handler interface
func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

// customizeRequest modifies the request before sending to backend
func customizeRequest(req *http.Request) {
	// Set appropriate headers for proxying
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If X-Forwarded-For exists, append the client IP
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	// Set other X-Forwarded headers
	req.Header.Set("X-Forwarded-Proto", "http") // Use "https" if TLS
	req.Header.Set("X-Forwarded-Host", req.Host)

	// Remove connection-related headers as recommended in httputil docs
	for _, h := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		if req.Header.Get(h) != "" {
			req.Header.Del(h)
		}
	}

	// Add custom headers if needed
	req.Header.Set("X-Proxy-Version", "1.0")

	log.Debug().
		Str("method", req.Method).
		Str("path", req.URL.Path).
		Str("remote", req.RemoteAddr).
		Msg("Proxying request to backend")
}

// createErrorHandler returns a function to handle proxy errors
func createErrorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		// Log the error
		log.Error().
			Err(err).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote", r.RemoteAddr).
			Msg("Proxy error")

		// Determine appropriate status code
		statusCode := http.StatusBadGateway // Default for proxy errors
		message := "Backend service error"

		if strings.Contains(err.Error(), "context deadline exceeded") {
			statusCode = http.StatusGatewayTimeout
			message = "Backend service timeout"
		} else if strings.Contains(err.Error(), "connection refused") {
			statusCode = http.StatusServiceUnavailable
			message = "Backend service unavailable"
		}

		// Return error as JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		fmt.Fprintf(w, `{"error":%q}`, message)
	}
}

// createResponseModifier returns a function to modify backend responses
func createResponseModifier() func(*http.Response) error {
	return func(resp *http.Response) error {
		// Log response details
		log.Debug().
			Int("status", resp.StatusCode).
			Str("contentType", resp.Header.Get("Content-Type")).
			Str("method", resp.Request.Method).
			Str("path", resp.Request.URL.Path).
			Msg("Received response from backend")

		// Remove hop-by-hop headers
		for _, h := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
			resp.Header.Del(h)
		}

		// Add custom headers to response if needed
		resp.Header.Set("X-Served-By", "auth-proxy")

		return nil
	}
}
