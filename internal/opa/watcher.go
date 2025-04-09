// Package opa provides OPA policy evaluation and management
package opa

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Watcher monitors the policy directory for changes
type Watcher struct {
	engine       *Engine
	policyDir    string
	interval     time.Duration
	stopChan     chan struct{}
	lastModified map[string]time.Time
	mutex        sync.RWMutex
	running      bool
}

// NewWatcher creates a new policy watcher
func NewWatcher(engine *Engine, policyDir string) (*Watcher, error) {
	watcher := &Watcher{
		engine:       engine,
		policyDir:    policyDir,
		interval:     30 * time.Second, // Default interval
		stopChan:     make(chan struct{}),
		lastModified: make(map[string]time.Time),
		running:      false,
	}

	// Initialize last modified times
	if err := watcher.updateLastModifiedTimes(); err != nil {
		log.Warn().Err(err).Str("dir", policyDir).Msg("Failed to initialize last modified times")
	}

	return watcher, nil
}

// SetInterval changes the polling interval
func (w *Watcher) SetInterval(interval time.Duration) {
	w.interval = interval
}

// Start begins watching for policy changes
func (w *Watcher) Start() {
	w.mutex.Lock()
	if w.running {
		w.mutex.Unlock()
		return
	}
	w.running = true
	w.mutex.Unlock()

	log.Info().Str("dir", w.policyDir).Dur("interval", w.interval).Msg("Starting policy watcher")

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.checkForChanges()
		case <-w.stopChan:
			w.mutex.Lock()
			w.running = false
			w.mutex.Unlock()
			log.Info().Msg("Policy watcher stopped")
			return
		}
	}
}

// Stop terminates the watcher
func (w *Watcher) Stop() {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if !w.running {
		return
	}

	close(w.stopChan)
	w.running = false
}

// IsRunning returns whether the watcher is currently running
func (w *Watcher) IsRunning() bool {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	return w.running
}

// checkForChanges looks for changes in policy files
func (w *Watcher) checkForChanges() {
	// Check if policy directory exists
	_, err := os.Stat(w.policyDir)
	if os.IsNotExist(err) {
		return
	}

	// Track changes
	changed := false
	deleted := []string{}
	added := []string{}
	modified := []string{}

	// Get current files and their modification times
	currentFiles := make(map[string]time.Time)
	entries, err := os.ReadDir(w.policyDir)
	if err != nil {
		log.Error().Err(err).Str("dir", w.policyDir).Msg("Failed to read policy directory")
		return
	}

	// Process each file
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}

		filePath := filepath.Join(w.policyDir, entry.Name())
		info, err := os.Stat(filePath)
		if err != nil {
			log.Error().Err(err).Str("file", filePath).Msg("Failed to stat policy file")
			continue
		}

		currentFiles[entry.Name()] = info.ModTime()

		// Check if file is new or modified
		w.mutex.RLock()
		lastMod, exists := w.lastModified[entry.Name()]
		w.mutex.RUnlock()

		if !exists {
			// New file
			content, err := os.ReadFile(filePath)
			if err != nil {
				log.Error().Err(err).Str("file", filePath).Msg("Failed to read new policy file")
				continue
			}

			err = w.engine.UpdatePolicy(entry.Name(), string(content))
			if err != nil {
				log.Error().Err(err).Str("file", filePath).Msg("Failed to update engine with new policy")
				continue
			}

			added = append(added, entry.Name())
			changed = true
		} else if info.ModTime().After(lastMod) {
			// Modified file
			content, err := os.ReadFile(filePath)
			if err != nil {
				log.Error().Err(err).Str("file", filePath).Msg("Failed to read modified policy file")
				continue
			}

			err = w.engine.UpdatePolicy(entry.Name(), string(content))
			if err != nil {
				log.Error().Err(err).Str("file", filePath).Msg("Failed to update engine with modified policy")
				continue
			}

			modified = append(modified, entry.Name())
			changed = true
		}
	}

	// Check for deleted files
	w.mutex.RLock()
	for name := range w.lastModified {
		if _, exists := currentFiles[name]; !exists {
			deleted = append(deleted, name)
			changed = true
			w.engine.RemovePolicy(name)
		}
	}
	w.mutex.RUnlock()

	// Update last modified times if changes were detected
	if changed {
		w.mutex.Lock()
		w.lastModified = currentFiles
		w.mutex.Unlock()

		log.Info().
			Strs("added", added).
			Strs("modified", modified).
			Strs("deleted", deleted).
			Msg("Policy changes detected and applied")
	}
}

// updateLastModifiedTimes initializes the last modified times for all policies
func (w *Watcher) updateLastModifiedTimes() error {
	// Check if policy directory exists
	_, err := os.Stat(w.policyDir)
	if os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to do
	}

	// Get current files and their modification times
	currentFiles := make(map[string]time.Time)
	entries, err := os.ReadDir(w.policyDir)
	if err != nil {
		return err
	}

	// Process each file
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}

		filePath := filepath.Join(w.policyDir, entry.Name())
		info, err := os.Stat(filePath)
		if err != nil {
			log.Error().Err(err).Str("file", filePath).Msg("Failed to stat policy file")
			continue
		}

		currentFiles[entry.Name()] = info.ModTime()
	}

	// Update last modified times
	w.mutex.Lock()
	w.lastModified = currentFiles
	w.mutex.Unlock()

	return nil
}
