package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFixedDryRunSignature(t *testing.T) {
	signed, err := buildSignedRequest(
		"test_secret_do_not_use",
		"123e4567-e89b-42d3-a456-426614174000",
		defaultEndpoint,
		"1700000000000",
		"nonce_for_dry_run",
	)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Body != `{"boxId":"123e4567-e89b-42d3-a456-426614174000"}` {
		t.Fatalf("body mismatch: %s", signed.Body)
	}
	if signed.BodySHA256 != "7ce622a9473ffbe7ed390c57efa3705747981e316ace1fa56000072f20ac7958" {
		t.Fatalf("body hash mismatch: %s", signed.BodySHA256)
	}
	if signed.Headers["X-Leona-Signature"] != "flTDOGc3Xu5CXjzgeMWnyd1GF0O5X6VXtMbhSgsLU7Y" {
		t.Fatalf("signature mismatch: %s", signed.Headers["X-Leona-Signature"])
	}
}

func TestDryRunRedactionContract(t *testing.T) {
	signed, err := buildSignedRequest(
		"test_secret_do_not_use",
		"123e4567-e89b-42d3-a456-426614174000",
		defaultEndpoint,
		"1700000000000",
		"nonce_for_dry_run",
	)
	if err != nil {
		t.Fatal(err)
	}
	redacted := signed
	redacted.Body = "[REDACTED]"
	redacted.Headers = cloneHeaders(signed.Headers)
	redacted.Headers["Authorization"] = "Bearer [REDACTED]"
	redacted.Headers["X-Leona-Signature"] = "[REDACTED]"
	out, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"test_secret_do_not_use",
		"123e4567-e89b-42d3-a456-426614174000",
		signed.Headers["X-Leona-Signature"],
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("dry-run output contains sensitive material")
		}
	}
}

func TestEndpointValidation(t *testing.T) {
	invalid := []string{
		"file:///etc/passwd",
		"https://user:password@example.invalid/v1/verdict",
		"https://example.invalid/v1/verdict?secret=value",
		"https://example.invalid/other",
		"http://example.invalid/v1/verdict",
	}
	for _, endpoint := range invalid {
		if _, err := validateEndpoint(endpoint, false); err == nil {
			t.Fatalf("expected endpoint rejection: %s", endpoint)
		}
	}
	loopback := "http://127.0.0.1:18080/v1/verdict"
	if _, err := validateEndpoint(loopback, false); err == nil {
		t.Fatal("loopback HTTP must require explicit opt-in")
	}
	if got, err := validateEndpoint(loopback, true); err != nil || got != loopback {
		t.Fatalf("explicit loopback endpoint rejected: %v", err)
	}
}
