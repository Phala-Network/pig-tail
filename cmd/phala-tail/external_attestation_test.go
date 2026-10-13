package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Phala-Network/pig-tail/internal/app/tail"
	"github.com/Phala-Network/pig-tail/internal/runtime/attestation"
)

func TestExternalTLSReportWaitsForCertificateAndTracksRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ingress.pem"), filepath.Join(dir, "ingress.key")
	t.Setenv("TLS_CERT_PATH", certPath)
	t.Setenv("TLS_KEY_PATH", "")
	transport, fingerprint, err := loadTLSConfig(certPath, "")
	if err != nil || transport != nil || fingerprint != nil {
		t.Fatalf("certificate-only mode must keep the private listener on HTTP: %v", err)
	}
	config := attestationConfigFromEnv(nil)
	if !config.RequireNVIDIAEvidence {
		t.Fatal("production NVIDIA evidence requirement was lost")
	}
	// CPU wiring fixture only; no hardware-attestation claim.
	config.RequireNVIDIAEvidence = false
	config.NVIDIAPayload = `{"nonce":"${nonce}","arch":"HOPPER","evidence_list":[]}`
	collector := &listenerQuoteFixture{}
	report, err := attestation.NewService(config, collector)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := tail.New(tail.Config{Token: "fixture-token", Upstream: "http://127.0.0.1:1", RequestTimeout: time.Second}, report)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	server := httptest.NewServer(handler)
	defer server.Close()
	t.Setenv("LISTEN", strings.TrimPrefix(server.URL, "http://"))
	if err := runHealthcheck(); err != nil {
		t.Fatalf("external certificate must not switch healthcheck to TLS: %v", err)
	}
	call := func(nonce string, status int) map[string]any {
		t.Helper()
		request, _ := http.NewRequest("GET", server.URL+"/v1/attestation/report?version=2&signing_algo=ed25519&nonce="+nonce, nil)
		request.Header.Set("Authorization", "Bearer fixture-token")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status {
			t.Fatalf("HTTP %d, want %d: %v", response.StatusCode, status, body)
		}
		return body
	}
	call(strings.Repeat("10", 32), http.StatusBadRequest)
	var previous string
	for _, nonce := range []string{strings.Repeat("12", 32), strings.Repeat("34", 32)} {
		leaf := writeTLSFixture(t, certPath, keyPath)
		fingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		body := call(nonce, http.StatusOK)
		if body["tls_cert_fingerprint"] != hex.EncodeToString(fingerprint[:]) || body["request_nonce"] != nonce {
			t.Fatal("external TLS key or nonce binding mismatch")
		}
		if body["tls_cert_fingerprint"] == previous {
			t.Fatal("renewed external certificate was not reread")
		}
		previous = body["tls_cert_fingerprint"].(string)
		address, err := hex.DecodeString(strings.TrimPrefix(body["signing_address"].(string), "0x"))
		if err != nil {
			t.Fatal(err)
		}
		binding := sha256.Sum256(append(address, fingerprint[:]...))
		data := collector.data()
		if len(data) != 64 || !bytes.Equal(data[:32], binding[:]) || hex.EncodeToString(data[32:]) != nonce {
			t.Fatal("quote data does not bind external certificate and fresh nonce")
		}
	}
}
