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
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultEndpoint = "https://leona.xiyanshan.com/v1/verdict"

type signedRequest struct {
	Endpoint   string            `json:"endpoint"`
	Body       string            `json:"body"`
	BodySHA256 string            `json:"bodySha256"`
	Headers    map[string]string `json:"headers"`
}

func main() {
	secret := requireEnv("LEONA_SECRET_KEY")
	boxID := requireEnv("BOX_ID")
	endpoint := os.Getenv("LEONA_ENDPOINT")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	endpoint, err := validateEndpoint(endpoint, os.Getenv("LEONA_ALLOW_LOOPBACK_HTTP") == "1")
	must(err)
	timestamp := os.Getenv("LEONA_TIMESTAMP")
	if timestamp == "" {
		timestamp = fmt.Sprintf("%d", time.Now().UnixMilli())
	}
	nonce := os.Getenv("LEONA_NONCE")
	if nonce == "" {
		nonce = randomBase64URL(16)
	}

	signed, err := buildSignedRequest(secret, boxID, endpoint, timestamp, nonce)
	must(err)

	if os.Getenv("LEONA_DRY_RUN") == "1" {
		redacted := signed
		redacted.Body = "[REDACTED]"
		redacted.Headers = cloneHeaders(signed.Headers)
		redacted.Headers["Authorization"] = "Bearer [REDACTED]"
		redacted.Headers["X-Leona-Signature"] = "[REDACTED]"
		out, err := json.MarshalIndent(redacted, "", "  ")
		must(err)
		fmt.Println(string(out))
		return
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader([]byte(signed.Body)))
	must(err)
	for name, value := range signed.Headers {
		req.Header.Set(name, value)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirects are forbidden for signed Leona requests")
		},
	}
	resp, err := client.Do(req)
	must(err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	must(err)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "Leona query failed: HTTP %d\n%s\n", resp.StatusCode, respBody)
		os.Exit(1)
	}
	fmt.Println(string(respBody))
}

func validateEndpoint(endpoint string, allowLoopbackHTTP bool) (string, error) {
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("LEONA_ENDPOINT must be an absolute /v1/verdict URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/v1/verdict" {
		return "", fmt.Errorf("LEONA_ENDPOINT must not contain credentials, query, fragment, or another path")
	}
	host := strings.ToLower(parsed.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if parsed.Scheme == "https" || (parsed.Scheme == "http" && loopback && allowLoopbackHTTP) {
		return endpoint, nil
	}
	return "", fmt.Errorf("LEONA_ENDPOINT must use HTTPS (or explicit loopback HTTP for local tests)")
}

func cloneHeaders(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func buildSignedRequest(secret, boxID, endpoint, timestamp, nonce string) (signedRequest, error) {
	body, err := json.Marshal(map[string]string{"boxId": boxID})
	if err != nil {
		return signedRequest{}, err
	}
	bodyHash := sha256.Sum256(body)
	bodySHA256 := hex.EncodeToString(bodyHash[:])
	signingText := fmt.Sprintf("%s\n%s\n%s", timestamp, nonce, bodySHA256)
	signature := hmacBase64URL(secret, signingText)
	return signedRequest{
		Endpoint:   endpoint,
		Body:       string(body),
		BodySHA256: bodySHA256,
		Headers: map[string]string{
			"Authorization":     "Bearer " + secret,
			"Content-Type":      "application/json",
			"X-Leona-Timestamp": timestamp,
			"X-Leona-Nonce":     nonce,
			"X-Leona-Signature": signature,
		},
	}, nil
}

func requireEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		fmt.Fprintf(os.Stderr, "Missing required environment variable: %s\n", name)
		os.Exit(2)
	}
	return value
}

func randomBase64URL(size int) string {
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	must(err)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func hmacBase64URL(secret, text string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write([]byte(text))
	must(err)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
