package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var cloudCanonicalStore = newCanonicalStore(
	env("DEMO_CLOUD_STORE_PATH", filepath.Join(os.TempDir(), "leona-demo-cloud-store.json")),
)

type demoRequest struct {
	BoxID string `json:"boxId"`
}

type mobileConfigResponse struct {
	DisabledSignals           []string       `json:"disabledSignals,omitempty"`
	DisableCollectionWindowMs int64          `json:"disableCollectionWindowMs,omitempty"`
	CanonicalDeviceID         string         `json:"canonicalDeviceId,omitempty"`
	Device                    identityEcho   `json:"device,omitempty"`
	Identity                  identityEcho   `json:"identity,omitempty"`
	DeviceIdentity            identityEcho   `json:"deviceIdentity,omitempty"`
	Policy                    policyEcho     `json:"policy,omitempty"`
	Config                    policyEcho     `json:"config,omitempty"`
	Debug                     map[string]any `json:"debug,omitempty"`
}

type identityEcho struct {
	CanonicalDeviceID string `json:"canonicalDeviceId,omitempty"`
	DeviceID          string `json:"deviceId,omitempty"`
	ResolvedDeviceID  string `json:"resolvedDeviceId,omitempty"`
	ID                string `json:"id,omitempty"`
}

type policyEcho struct {
	DisabledSignals           []string `json:"disabledSignals,omitempty"`
	DisabledCollectors        []string `json:"disabledCollectors,omitempty"`
	DisableCollectionWindowMs int64    `json:"disableCollectionWindowMs,omitempty"`
}

type verdictRequest struct {
	BoxID string `json:"boxId"`
}

type verdictResponse struct {
	BoxID             string `json:"boxId"`
	DeviceFingerprint string `json:"deviceFingerprint"`
	Risk              struct {
		Level string `json:"level"`
		Score int    `json:"score"`
	} `json:"risk"`
}

type demoResponse struct {
	BoxID             string       `json:"boxId"`
	CanonicalDeviceID string       `json:"canonicalDeviceId,omitempty"`
	Device            identityEcho `json:"device,omitempty"`
	Identity          identityEcho `json:"identity,omitempty"`
	DeviceIdentity    identityEcho `json:"deviceIdentity,omitempty"`
	Decision          string       `json:"decision"`
	RiskLevel         string       `json:"riskLevel"`
	RiskScore         int          `json:"riskScore"`
	HoneypotSuggested bool         `json:"honeypotSuggested"`
}

func main() {
	addr := env("DEMO_BACKEND_ADDR", ":8090")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/v1/mobile-config", mobileConfig)
	mux.HandleFunc("/demo/verdict", demoVerdict)

	log.Printf("demo-backend listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, logging(mux)))
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"time": time.Now().UTC().Format(time.RFC3339),
	})
}

func mobileConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	disabledSignals := splitCSV(env("DEMO_CLOUD_DISABLED_SIGNALS", "androidId"))
	disableWindowMs := envInt64("DEMO_CLOUD_DISABLE_COLLECTION_WINDOW_MS", 120000)
	canonicalDeviceID := resolveCanonicalDeviceID(r)
	if canonicalDeviceID != "" {
		w.Header().Set("X-Leona-Canonical-Device-Id", canonicalDeviceID)
	}
	if len(disabledSignals) > 0 {
		w.Header().Set("X-Leona-Disabled-Signals", strings.Join(disabledSignals, ","))
	}
	if disableWindowMs >= 0 {
		w.Header().Set("X-Leona-Disable-Collection-Window-Ms", fmt.Sprintf("%d", disableWindowMs))
	}

	response := mobileConfigResponse{
		DisabledSignals:           disabledSignals,
		DisableCollectionWindowMs: disableWindowMs,
		CanonicalDeviceID:         canonicalDeviceID,
		Device: identityEcho{
			CanonicalDeviceID: canonicalDeviceID,
			DeviceID:          canonicalDeviceID,
			ID:                canonicalDeviceID,
		},
		Identity: identityEcho{
			CanonicalDeviceID: canonicalDeviceID,
			DeviceID:          canonicalDeviceID,
		},
		DeviceIdentity: identityEcho{
			CanonicalDeviceID: canonicalDeviceID,
			DeviceID:          canonicalDeviceID,
			ResolvedDeviceID:  canonicalDeviceID,
		},
		Policy: policyEcho{
			DisabledSignals:           disabledSignals,
			DisabledCollectors:        disabledSignals,
			DisableCollectionWindowMs: disableWindowMs,
		},
		Config: policyEcho{
			DisabledSignals:           disabledSignals,
			DisabledCollectors:        disabledSignals,
			DisableCollectionWindowMs: disableWindowMs,
		},
		Debug: map[string]any{
			"received": map[string]string{
				"tenant":            strings.TrimSpace(r.Header.Get("X-Leona-Tenant")),
				"appId":             strings.TrimSpace(r.Header.Get("X-Leona-App-Id")),
				"deviceId":          strings.TrimSpace(r.Header.Get("X-Leona-Device-Id")),
				"installId":         strings.TrimSpace(r.Header.Get("X-Leona-Install-Id")),
				"fingerprint":       strings.TrimSpace(r.Header.Get("X-Leona-Fingerprint")),
				"canonicalDeviceId": strings.TrimSpace(r.Header.Get("X-Leona-Canonical-Device-Id")),
				"riskSignals":       strings.TrimSpace(r.Header.Get("X-Leona-Risk-Signals")),
			},
		},
	}
	writeJSON(w, http.StatusOK, response)
}

func demoVerdict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req demoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.BoxID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "boxId is required"})
		return
	}

	verdict, err := queryLeona(req.BoxID, resolveLeonaSecret(r))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	response := demoResponse{
		BoxID:             verdict.BoxID,
		Decision:          decisionOf(verdict.Risk.Level),
		RiskLevel:         verdict.Risk.Level,
		RiskScore:         verdict.Risk.Score,
		HoneypotSuggested: honeypotSuggested(verdict.Risk.Level),
	}
	if canonicalDeviceID := resolveVerdictCanonicalDeviceID(r, verdict); canonicalDeviceID != "" {
		response.CanonicalDeviceID = canonicalDeviceID
		response.Device = identityEcho{
			CanonicalDeviceID: canonicalDeviceID,
			DeviceID:          canonicalDeviceID,
			ID:                canonicalDeviceID,
		}
		response.Identity = identityEcho{
			CanonicalDeviceID: canonicalDeviceID,
			DeviceID:          canonicalDeviceID,
		}
		response.DeviceIdentity = identityEcho{
			CanonicalDeviceID: canonicalDeviceID,
			DeviceID:          canonicalDeviceID,
			ResolvedDeviceID:  canonicalDeviceID,
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func resolveLeonaSecret(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Leona-Demo-Secret-Key")); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv("LEONA_SECRET_KEY"))
}

func queryLeona(boxID string, secret string) (*verdictResponse, error) {
	baseURL := strings.TrimRight(env("LEONA_BASE_URL", "http://localhost:8080"), "/")
	if secret == "" {
		return nil, fmt.Errorf("LEONA_SECRET_KEY is not set")
	}

	reqBody, err := json.Marshal(verdictRequest{BoxID: boxID})
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().UnixMilli()
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	signature := sign([]byte(secret), timestamp, nonce, reqBody)

	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/verdict", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Leona-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Leona-Nonce", nonce)
	req.Header.Set("X-Leona-Signature", signature)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("leona verdict failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	generatedAt := resp.Header.Get("X-Leona-Verdict-Generated-At")
	verdictSignature := resp.Header.Get("X-Leona-Verdict-Signature")
	if generatedAt == "" || verdictSignature == "" {
		return nil, fmt.Errorf("leona verdict signature headers missing")
	}
	if !verifyVerdictSignature([]byte(secret), generatedAt, body, verdictSignature) {
		return nil, fmt.Errorf("leona verdict signature verification failed")
	}

	var verdict verdictResponse
	if err := json.Unmarshal(body, &verdict); err != nil {
		return nil, err
	}
	return &verdict, nil
}

func sign(secret []byte, timestamp int64, nonce string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	canonical := fmt.Sprintf("%d\n%s\n%s", timestamp, nonce, hex.EncodeToString(bodyHash[:]))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyVerdictSignature(secret []byte, generatedAt string, body []byte, provided string) bool {
	bodyHash := sha256.Sum256(body)
	canonical := fmt.Sprintf("%s\n%s", generatedAt, hex.EncodeToString(bodyHash[:]))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(provided))
}

func randomNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func decisionOf(level string) string {
	switch strings.ToUpper(level) {
	case "CLEAN", "LOW":
		return "allow"
	case "MEDIUM":
		return "challenge"
	case "HIGH", "CRITICAL":
		return "deny"
	default:
		return "unknown"
	}
}

func honeypotSuggested(level string) bool {
	switch strings.ToUpper(level) {
	case "HIGH", "CRITICAL":
		return true
	default:
		return false
	}
}

func resolveCanonicalDeviceID(r *http.Request) string {
	if explicit := strings.TrimSpace(env("DEMO_CLOUD_CANONICAL_DEVICE_ID", "")); explicit != "" {
		return normalizeCanonical(explicit)
	}
	input := canonicalResolveInput{
		TenantID:          strings.TrimSpace(r.Header.Get("X-Leona-Tenant")),
		AppID:             strings.TrimSpace(r.Header.Get("X-Leona-App-Id")),
		Fingerprint:       strings.TrimSpace(r.Header.Get("X-Leona-Fingerprint")),
		DeviceID:          strings.TrimSpace(r.Header.Get("X-Leona-Device-Id")),
		InstallID:         strings.TrimSpace(r.Header.Get("X-Leona-Install-Id")),
		ProvidedCanonical: strings.TrimSpace(r.Header.Get("X-Leona-Canonical-Device-Id")),
	}
	input.FallbackSeed = canonicalFallbackSeed(input.TenantID, input.AppID, input.Fingerprint, input.DeviceID, input.InstallID, r.RemoteAddr)
	return cloudCanonicalStore.resolveOrCreate(input)
}

func resolveVerdictCanonicalDeviceID(r *http.Request, verdict *verdictResponse) string {
	if verdict == nil {
		return ""
	}
	input := canonicalResolveInput{
		TenantID:          strings.TrimSpace(r.Header.Get("X-Leona-Demo-Tenant")),
		AppID:             strings.TrimSpace(r.Header.Get("X-Leona-Demo-App-Id")),
		Fingerprint:       strings.TrimSpace(verdict.DeviceFingerprint),
		DeviceID:          strings.TrimSpace(r.Header.Get("X-Leona-Demo-Device-Id")),
		ProvidedCanonical: strings.TrimSpace(r.Header.Get("X-Leona-Demo-Canonical-Device-Id")),
	}
	input.FallbackSeed = canonicalFallbackSeed(input.TenantID, input.AppID, input.Fingerprint, input.DeviceID, "", "")
	return cloudCanonicalStore.resolveOrCreate(input)
}

func splitCSV(raw string) []string {
	seen := map[string]struct{}{}
	values := make([]string, 0)
	for _, item := range strings.Split(raw, ",") {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func envInt64(key string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	var value int64
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil {
		return fallback
	}
	return value
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
