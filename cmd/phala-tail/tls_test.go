package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Phala-Network/pig-tail/internal/runtime/attestation"
)

func writeTLSFixture(t *testing.T, certPath, keyPath string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "TAIL local TLS fixture"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestTLSConfigurationRequiresCompleteMatchingPair(t *testing.T) {
	config, fingerprint, err := loadTLSConfig("", "")
	if err != nil || config != nil || fingerprint != nil {
		t.Fatalf("plain local mode: config=%v fingerprint=%x error=%v", config, fingerprint, err)
	}
	dir := t.TempDir()
	certA, keyA := filepath.Join(dir, "a.pem"), filepath.Join(dir, "a.key")
	certB, keyB := filepath.Join(dir, "b.pem"), filepath.Join(dir, "b.key")
	writeTLSFixture(t, certA, keyA)
	writeTLSFixture(t, certB, keyB)
	for _, test := range []struct{ name, cert, key string }{
		{"missing_key", certA, ""}, {"missing_certificate", "", keyA},
		{"mismatched_pair", certA, keyB}, {"missing_file", filepath.Join(dir, "absent.pem"), keyA},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := loadTLSConfig(test.cert, test.key); err == nil {
				t.Fatal("invalid TLS configuration was accepted")
			}
		})
	}
}

// This collector proves the report-data wiring only, not a hardware quote.
type listenerQuoteFixture struct {
	mu         sync.Mutex
	reportData []byte
}

func (q *listenerQuoteFixture) GetQuote(_ context.Context, data []byte) (attestation.QuoteResponse, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reportData = append([]byte(nil), data...)
	return attestation.QuoteResponse{Quote: "cpu-fixture-only", ReportData: hex.EncodeToString(data)}, nil
}

func (q *listenerQuoteFixture) Info(context.Context) (map[string]any, error) {
	return map[string]any{"fixture": true}, nil
}

func (q *listenerQuoteFixture) data() []byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]byte(nil), q.reportData...)
}

func TestActualTLSListenerUsesSameCertificateSnapshotAsReport(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "listener.pem"), filepath.Join(dir, "listener.key")
	leaf := writeTLSFixture(t, certPath, keyPath)
	config, fingerprint, err := loadTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	expectedFingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	collector := &listenerQuoteFixture{}
	report, err := attestation.NewService(attestation.Config{
		TLSCertPath: certPath, TLSCertSPKISHA256: fingerprint,
		NVIDIAPayload: `{"nonce":"${nonce}","arch":"HOPPER","evidence_list":[]}`,
	}, collector)
	if err != nil {
		t.Fatal(err)
	}

	// A caller's mutation must not alter the report service's stored key.
	fingerprint[0] ^= 0xff
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("report request did not use TLS")
		}
		response, err := report.Generate(r.Context(), attestation.ReportRequest{
			Version: 2, SigningAlgo: attestation.AlgoEd25519, NonceHex: r.URL.Query().Get("nonce"),
		})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	for index, nonceHex := range []string{strings.Repeat("12", 32), strings.Repeat("34", 32)} {
		if index == 1 {
			replacement := writeTLSFixture(t, certPath, keyPath)
			if bytes.Equal(replacement.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
				t.Fatal("fixture keys repeated")
			}
		}
		response, err := client.Get(server.URL + "/?nonce=" + nonceHex)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			response.Body.Close()
			t.Fatalf("HTTP %d", response.StatusCode)
		}
		var body map[string]any
		err = json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		peerFingerprint := sha256.Sum256(response.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if peerFingerprint != expectedFingerprint || body["tls_cert_fingerprint"] != hex.EncodeToString(peerFingerprint[:]) {
			t.Fatal("report key differs from actual TLS peer")
		}
		if body["request_nonce"] != nonceHex {
			t.Fatal("report nonce differs from challenge")
		}
		address, err := hex.DecodeString(strings.TrimPrefix(body["signing_address"].(string), "0x"))
		if err != nil {
			t.Fatal(err)
		}
		expectedBinding := sha256.Sum256(append(address, peerFingerprint[:]...))
		data := collector.data()
		nonce, _ := hex.DecodeString(nonceHex)
		if len(data) != 64 || !bytes.Equal(data[:32], expectedBinding[:]) || !bytes.Equal(data[32:], nonce) {
			t.Fatal("quote report_data does not bind the actual TLS key and fresh nonce")
		}
	}
}

func TestReportRejectsInvalidBoundSPKILength(t *testing.T) {
	for _, size := range []int{1, 31, 33} {
		if _, err := attestation.NewService(attestation.Config{TLSCertSPKISHA256: make([]byte, size)}, &listenerQuoteFixture{}); err == nil {
			t.Fatalf("accepted fingerprint length %d", size)
		}
	}
}
