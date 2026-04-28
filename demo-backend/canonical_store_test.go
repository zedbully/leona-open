package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalStorePersistsStructuredRecordsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canonical-store.json")
	storeA := newCanonicalStore(path)
	first := storeA.resolveOrCreate(canonicalResolveInput{
		TenantID:    "tenant-a",
		AppID:       "sample-app",
		Fingerprint: "fingerprint-a",
		DeviceID:    "Tdevice-a",
		InstallID:   "install-a",
		FallbackSeed: canonicalFallbackSeed(
			"tenant-a",
			"sample-app",
			"fingerprint-a",
			"Tdevice-a",
			"install-a",
			"127.0.0.1:12345",
		),
	})
	if first == "" || first[0] != 'L' {
		t.Fatalf("expected canonical id, got %q", first)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	var file canonicalStoreFile
	if err := json.Unmarshal(body, &file); err != nil {
		t.Fatalf("unmarshal store: %v", err)
	}
	if file.Version != canonicalStoreVersion {
		t.Fatalf("unexpected store version: %d", file.Version)
	}
	if len(file.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(file.Records))
	}

	storeB := newCanonicalStore(path)
	second := storeB.resolveOrCreate(canonicalResolveInput{
		TenantID:    "tenant-a",
		AppID:       "sample-app",
		Fingerprint: "fingerprint-a",
		FallbackSeed: canonicalFallbackSeed(
			"tenant-a",
			"sample-app",
			"fingerprint-a",
			"",
			"",
			"127.0.0.1:23456",
		),
	})
	if first != second {
		t.Fatalf("expected persisted canonical, got %q != %q", first, second)
	}
}

func TestCanonicalLookupKeysPrefersFingerprintThenDeviceThenInstall(t *testing.T) {
	lookups := canonicalLookupKeys("tenant-a", "sample-app", "fp-1", "Tdevice", "install-1")
	if len(lookups) != 3 {
		t.Fatalf("unexpected lookup count: %d", len(lookups))
	}
	if got := lookups[0].key(); got != canonicalRecordKey("", "", "fp", "fp-1") {
		t.Fatalf("unexpected fingerprint key: %q", got)
	}
	if got := lookups[1].key(); got != canonicalRecordKey("", "", "dev", "Tdevice") {
		t.Fatalf("unexpected device key: %q", got)
	}
	if got := lookups[2].key(); got != canonicalRecordKey("tenant-a", "sample-app", "install", "install-1") {
		t.Fatalf("unexpected install key: %q", got)
	}
}

func TestResolveCanonicalDeviceIDBackfillsProvidedCanonicalAcrossIdentifiers(t *testing.T) {
	previous := cloudCanonicalStore
	cloudCanonicalStore = newCanonicalStore(filepath.Join(t.TempDir(), "canonical-store.json"))
	defer func() { cloudCanonicalStore = previous }()

	req := httptest.NewRequest("GET", "/v1/mobile-config", nil)
	req.Header.Set("X-Leona-Tenant", "tenant-a")
	req.Header.Set("X-Leona-App-Id", "sample-app")
	req.Header.Set("X-Leona-Fingerprint", "fp-1")
	req.Header.Set("X-Leona-Device-Id", "Tdevice-1")
	req.Header.Set("X-Leona-Install-Id", "install-1")
	req.Header.Set("X-Leona-Canonical-Device-Id", "Lserver-issued")

	first := resolveCanonicalDeviceID(req)
	if first != "Lserver-issued" {
		t.Fatalf("expected provided canonical, got %q", first)
	}

	req2 := httptest.NewRequest("GET", "/v1/mobile-config", nil)
	req2.Header.Set("X-Leona-Tenant", "tenant-a")
	req2.Header.Set("X-Leona-App-Id", "sample-app")
	req2.Header.Set("X-Leona-Device-Id", "Tdevice-1")

	second := resolveCanonicalDeviceID(req2)
	if second != "Lserver-issued" {
		t.Fatalf("expected persisted canonical via device fallback, got %q", second)
	}
}

func TestResolveCanonicalDeviceIDStableAcrossTenantAndApp(t *testing.T) {
	previous := cloudCanonicalStore
	cloudCanonicalStore = newCanonicalStore(filepath.Join(t.TempDir(), "canonical-store.json"))
	defer func() { cloudCanonicalStore = previous }()

	base := func(tenant string, app string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/v1/mobile-config", nil)
		req.Header.Set("X-Leona-Tenant", tenant)
		req.Header.Set("X-Leona-App-Id", app)
		req.Header.Set("X-Leona-Fingerprint", "shared-fp")
		rec := httptest.NewRecorder()
		mobileConfig(rec, req)
		return rec
	}

	tenantA := resolveCanonicalFromBody(t, base("tenant-a", "sample-app").Body.Bytes())
	tenantB := resolveCanonicalFromBody(t, base("tenant-b", "sample-app").Body.Bytes())
	appB := resolveCanonicalFromBody(t, base("tenant-a", "sample-app-b").Body.Bytes())

	if tenantA != tenantB {
		t.Fatalf("expected tenant-independent canonical, got %q != %q", tenantA, tenantB)
	}
	if tenantA != appB {
		t.Fatalf("expected app-independent canonical, got %q != %q", tenantA, appB)
	}
}

func TestCanonicalStoreLoadsLegacyFlatMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canonical-store.json")
	legacy := map[string]string{
		"fp|sample-app|fp-1": "Llegacy-1",
	}
	body, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	store := newCanonicalStore(path)
	resolved := store.resolveOrCreate(canonicalResolveInput{
		AppID:       "sample-app",
		Fingerprint: "fp-1",
		FallbackSeed: canonicalFallbackSeed(
			"",
			"sample-app",
			"fp-1",
			"",
			"",
			"127.0.0.1:12345",
		),
	})
	if resolved != "Llegacy-1" {
		t.Fatalf("expected legacy canonical, got %q", resolved)
	}
}

func resolveCanonicalFromBody(t *testing.T, body []byte) string {
	t.Helper()
	var response mobileConfigResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return response.CanonicalDeviceID
}
