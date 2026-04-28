package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const canonicalStoreVersion = 1

type canonicalLookup struct {
	TenantID string
	AppID    string
	Kind     string
	Value    string
}

type canonicalResolveInput struct {
	TenantID          string
	AppID             string
	Fingerprint       string
	DeviceID          string
	InstallID         string
	FallbackSeed      string
	ProvidedCanonical string
}

type canonicalRecord struct {
	TenantID          string `json:"tenantId,omitempty"`
	AppID             string `json:"appId,omitempty"`
	LookupKind        string `json:"lookupKind"`
	LookupValue       string `json:"lookupValue"`
	CanonicalDeviceID string `json:"canonicalDeviceId"`
	Source            string `json:"source,omitempty"`
	CreatedAt         string `json:"createdAt,omitempty"`
	UpdatedAt         string `json:"updatedAt,omitempty"`
}

type canonicalStoreFile struct {
	Version int               `json:"version"`
	Records []canonicalRecord `json:"records"`
}

type canonicalStore struct {
	path string

	mu       sync.Mutex
	loaded   bool
	records  map[string]canonicalRecord
	writeErr error
}

func newCanonicalStore(path string) *canonicalStore {
	return &canonicalStore{
		path:    strings.TrimSpace(path),
		records: map[string]canonicalRecord{},
	}
}

func (s *canonicalStore) resolveOrCreate(input canonicalResolveInput) string {
	provided := normalizeCanonical(input.ProvidedCanonical)
	lookups := canonicalLookupKeys(input.TenantID, input.AppID, input.Fingerprint, input.DeviceID, input.InstallID)
	fallback := deriveCanonicalID(input.FallbackSeed)

	if len(lookups) == 0 {
		return firstNonBlank(provided, fallback)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureLoaded()

	if provided != "" {
		if s.upsertLookupsLocked(lookups, provided, "provided_header") {
			s.persistLocked()
		}
		return provided
	}

	for _, lookup := range lookups {
		if existing := s.lookupCanonicalLocked(lookup); existing != "" {
			if s.upsertLookupsLocked(lookups, existing, "lookup_backfill") {
				s.persistLocked()
			}
			return existing
		}
	}

	if fallback == "" {
		return ""
	}
	if s.upsertLookupsLocked(lookups, fallback, "derived") {
		s.persistLocked()
	}
	return fallback
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
	if err != nil || len(body) == 0 {
		return
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return
	}
	if _, ok := probe["records"]; ok || probe["version"] != nil {
		var file canonicalStoreFile
		if err := json.Unmarshal(body, &file); err == nil {
			s.loadStructured(file)
			return
		}
	}

	var legacy map[string]string
	if err := json.Unmarshal(body, &legacy); err == nil {
		s.loadLegacy(legacy)
	}
}

func (s *canonicalStore) loadStructured(file canonicalStoreFile) {
	for _, record := range file.Records {
		record = normalizeRecord(record)
		if record.LookupKind == "" || record.LookupValue == "" || record.CanonicalDeviceID == "" {
			continue
		}
		s.records[canonicalRecordKey(record.TenantID, record.AppID, record.LookupKind, record.LookupValue)] = record
	}
}

func (s *canonicalStore) loadLegacy(entries map[string]string) {
	for key, canonical := range entries {
		record, ok := canonicalRecordFromLegacyEntry(key, canonical)
		if !ok {
			continue
		}
		s.records[canonicalRecordKey(record.TenantID, record.AppID, record.LookupKind, record.LookupValue)] = record
	}
}

func (s *canonicalStore) lookupCanonicalLocked(lookup canonicalLookup) string {
	record, ok := s.records[lookup.key()]
	if !ok {
		return ""
	}
	return normalizeCanonical(record.CanonicalDeviceID)
}

func (s *canonicalStore) upsertLookupsLocked(lookups []canonicalLookup, canonical string, source string) bool {
	canonical = normalizeCanonical(canonical)
	source = strings.TrimSpace(source)
	if canonical == "" {
		return false
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	changed := false
	seen := map[string]struct{}{}
	for _, lookup := range lookups {
		if !lookup.valid() {
			continue
		}
		key := lookup.key()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		record, ok := s.records[key]
		if !ok {
			record = canonicalRecord{
				TenantID:          strings.TrimSpace(lookup.TenantID),
				AppID:             strings.TrimSpace(lookup.AppID),
				LookupKind:        strings.TrimSpace(lookup.Kind),
				LookupValue:       strings.TrimSpace(lookup.Value),
				CanonicalDeviceID: canonical,
				Source:            strings.TrimSpace(source),
				CreatedAt:         now,
				UpdatedAt:         now,
			}
			s.records[key] = record
			changed = true
			continue
		}

		updated := false
		if normalizeCanonical(record.CanonicalDeviceID) != canonical {
			record.CanonicalDeviceID = canonical
			updated = true
		}
		if source != "" && record.Source != source {
			record.Source = source
			updated = true
		}
		if strings.TrimSpace(record.CreatedAt) == "" {
			record.CreatedAt = now
			updated = true
		}
		if updated {
			record.UpdatedAt = now
			s.records[key] = normalizeRecord(record)
			changed = true
		}
	}
	return changed
}

func (s *canonicalStore) persistLocked() {
	if s.path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		s.writeErr = err
		return
	}

	file := canonicalStoreFile{
		Version: canonicalStoreVersion,
		Records: make([]canonicalRecord, 0, len(s.records)),
	}
	for _, record := range s.records {
		record = normalizeRecord(record)
		if record.LookupKind == "" || record.LookupValue == "" || record.CanonicalDeviceID == "" {
			continue
		}
		file.Records = append(file.Records, record)
	}
	sort.Slice(file.Records, func(i, j int) bool {
		left := file.Records[i]
		right := file.Records[j]
		return canonicalRecordKey(left.TenantID, left.AppID, left.LookupKind, left.LookupValue) < canonicalRecordKey(right.TenantID, right.AppID, right.LookupKind, right.LookupValue)
	})

	body, err := json.MarshalIndent(file, "", "  ")
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

func canonicalLookupKeys(tenantID string, appID string, fingerprint string, deviceID string, installID string) []canonicalLookup {
	lookups := make([]canonicalLookup, 0, 3)
	for _, lookup := range []canonicalLookup{
		{Kind: "fp", Value: fingerprint},
		{Kind: "dev", Value: deviceID},
		{TenantID: tenantID, AppID: appID, Kind: "install", Value: installID},
	} {
		if lookup.valid() {
			lookups = append(lookups, lookup)
		}
	}
	return lookups
}

func canonicalFallbackSeed(tenantID string, appID string, fingerprint string, deviceID string, installID string, remoteAddr string) string {
	return firstNonBlank(
		strings.TrimSpace(fingerprint),
		strings.TrimSpace(deviceID),
		canonicalSeedPart(tenantID, appID, installID),
		canonicalSeedPart(tenantID, appID, remoteAddr),
	)
}

func canonicalSeedPart(tenantID string, appID string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := make([]string, 0, 3)
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		parts = append(parts, tenantID)
	}
	if appID = strings.TrimSpace(appID); appID != "" {
		parts = append(parts, appID)
	}
	parts = append(parts, value)
	return strings.Join(parts, "|")
}

func canonicalRecordFromLegacyEntry(key string, canonical string) (canonicalRecord, bool) {
	parts := strings.SplitN(strings.TrimSpace(key), "|", 3)
	if len(parts) != 3 {
		return canonicalRecord{}, false
	}
	record := canonicalRecord{
		LookupKind:        strings.TrimSpace(parts[0]),
		LookupValue:       strings.TrimSpace(parts[2]),
		CanonicalDeviceID: normalizeCanonical(canonical),
		Source:            "legacy_migration",
	}
	if record.LookupKind == "install" {
		record.AppID = strings.TrimSpace(parts[1])
	}
	record = normalizeRecord(record)
	return record, record.LookupKind != "" && record.LookupValue != "" && record.CanonicalDeviceID != ""
}

func normalizeRecord(record canonicalRecord) canonicalRecord {
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.AppID = strings.TrimSpace(record.AppID)
	record.LookupKind = strings.TrimSpace(record.LookupKind)
	record.LookupValue = strings.TrimSpace(record.LookupValue)
	record.CanonicalDeviceID = normalizeCanonical(record.CanonicalDeviceID)
	record.Source = strings.TrimSpace(record.Source)
	record.CreatedAt = strings.TrimSpace(record.CreatedAt)
	record.UpdatedAt = strings.TrimSpace(record.UpdatedAt)
	return record
}

func canonicalRecordKey(tenantID string, appID string, kind string, value string) string {
	return strings.Join([]string{
		strings.TrimSpace(tenantID),
		strings.TrimSpace(appID),
		strings.TrimSpace(kind),
		strings.TrimSpace(value),
	}, "\x1f")
}

func (l canonicalLookup) valid() bool {
	return strings.TrimSpace(l.Kind) != "" && strings.TrimSpace(l.Value) != ""
}

func (l canonicalLookup) key() string {
	return canonicalRecordKey(l.TenantID, l.AppID, l.Kind, l.Value)
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
