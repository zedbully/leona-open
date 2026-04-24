package main

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestCanonicalStorePersistsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canonical-store.json")
	storeA := newCanonicalStore(path)
	first := storeA.resolveOrCreate("fp|sample-app|fingerprint-a", "sample-app|fingerprint-a", "")
	if first == "" || first[0] != 'L' {
		t.Fatalf("expected canonical id, got %q", first)
	}

	storeB := newCanonicalStore(path)
	second := storeB.resolveOrCreate("fp|sample-app|fingerprint-a", "sample-app|fingerprint-a", "")
	if first != second {
		t.Fatalf("expected persisted canonical, got %q != %q", first, second)
	}
}

func TestCanonicalLookupKeyPrefersFingerprintThenDeviceThenInstall(t *testing.T) {
	if got := canonicalLookupKey("sample-app", "fp-1", "Tdevice", "install-1"); got != "fp|sample-app|fp-1" {
		t.Fatalf("unexpected fingerprint key: %q", got)
	}
	if got := canonicalLookupKey("sample-app", "", "Tdevice", "install-1"); got != "dev|sample-app|Tdevice" {
		t.Fatalf("unexpected device key: %q", got)
	}
	if got := canonicalLookupKey("sample-app", "", "", "install-1"); got != "install|sample-app|install-1" {
		t.Fatalf("unexpected install key: %q", got)
	}
}

func TestResolveCanonicalDeviceIDBackfillsProvidedCanonical(t *testing.T) {
	previous := cloudCanonicalStore
	cloudCanonicalStore = newCanonicalStore(filepath.Join(t.TempDir(), "canonical-store.json"))
	defer func() { cloudCanonicalStore = previous }()

	req := httptest.NewRequest("GET", "/v1/mobile-config", nil)
	req.Header.Set("X-Leona-App-Id", "sample-app")
	req.Header.Set("X-Leona-Fingerprint", "fp-1")
	req.Header.Set("X-Leona-Canonical-Device-Id", "Lserver-issued")

	first := resolveCanonicalDeviceID(req)
	if first != "Lserver-issued" {
		t.Fatalf("expected provided canonical, got %q", first)
	}

	req2 := httptest.NewRequest("GET", "/v1/mobile-config", nil)
	req2.Header.Set("X-Leona-App-Id", "sample-app")
	req2.Header.Set("X-Leona-Fingerprint", "fp-1")

	second := resolveCanonicalDeviceID(req2)
	if second != "Lserver-issued" {
		t.Fatalf("expected persisted canonical, got %q", second)
	}
}
