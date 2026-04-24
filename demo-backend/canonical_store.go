package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type canonicalStore struct {
	path string

	mu       sync.Mutex
	loaded   bool
	entries  map[string]string
	writeErr error
}

func newCanonicalStore(path string) *canonicalStore {
	return &canonicalStore{
		path:    strings.TrimSpace(path),
		entries: map[string]string{},
	}
}

func (s *canonicalStore) resolveOrCreate(key string, fallbackSeed string, providedCanonical string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return normalizeCanonical(providedCanonical)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureLoaded()
	if existing := normalizeCanonical(s.entries[key]); existing != "" {
		if provided := normalizeCanonical(providedCanonical); provided != "" && provided != existing {
			s.entries[key] = provided
			s.persistLocked()
			return provided
		}
		return existing
	}

	resolved := firstNonBlank(
		normalizeCanonical(providedCanonical),
		deriveCanonicalID(fallbackSeed),
	)
	if resolved == "" {
		return ""
	}
	s.entries[key] = resolved
	s.persistLocked()
	return resolved
}

func (s *canonicalStore) ensureLoaded() {
	if s.loaded {
		return
	}
	s.loaded = true
	if s.path == "" {
		return
	}
	body, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(body, &s.entries)
}

func (s *canonicalStore) persistLocked() {
	if s.path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		s.writeErr = err
		return
	}
	body, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		s.writeErr = err
		return
	}
	if err := os.WriteFile(s.path, body, 0o644); err != nil {
		s.writeErr = err
		return
	}
	s.writeErr = nil
}

func canonicalLookupKey(appID string, fingerprint string, deviceID string, installID string) string {
	return strings.TrimSpace(firstNonBlank(
		keyPart("fp", appID, fingerprint),
		keyPart("dev", appID, deviceID),
		keyPart("install", appID, installID),
	))
}

func canonicalFallbackSeed(appID string, fingerprint string, deviceID string, installID string, remoteAddr string) string {
	return firstNonBlank(
		strings.TrimSpace(appID)+"|"+strings.TrimSpace(fingerprint),
		strings.TrimSpace(appID)+"|"+strings.TrimSpace(deviceID),
		strings.TrimSpace(appID)+"|"+strings.TrimSpace(installID),
		strings.TrimSpace(appID)+"|"+strings.TrimSpace(remoteAddr),
	)
}

func keyPart(kind string, appID string, value string) string {
	appID = strings.TrimSpace(appID)
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return kind + "|" + appID + "|" + value
}

func deriveCanonicalID(seed string) string {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(seed))
	return "L" + hex.EncodeToString(sum[:])[:31]
}

func normalizeCanonical(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "L") {
		return value
	}
	return "L" + strings.TrimLeft(value, "L")
}
