package tail

import (
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

type quoteCapture struct {
	mu   sync.Mutex
	data [][]byte
}

func (q *quoteCapture) GetQuote(_ context.Context, data []byte) (attestation.QuoteResponse, error) {
	q.mu.Lock()
	q.data = append(q.data, append([]byte(nil), data...))
	q.mu.Unlock()
	return attestation.QuoteResponse{Quote: "CPU-test-fixture-not-hardware-evidence"}, nil
}
func (*quoteCapture) Info(context.Context) (map[string]any, error) {
	return map[string]any{"app_id": "fixture"}, nil
}

func TestReportV2BindsTheActualTLSConnectionAndFreshNonce(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TAIL test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "tls.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	quotes := &quoteCapture{}
	report, err := attestation.NewService(attestation.Config{TLSCertPath: certPath,
		NVIDIAPayload: `{"arch":"HOPPER","evidences":[]}`}, quotes)
	if err != nil {
		t.Fatal(err)
	}
	h := setup(t, http.NotFoundHandler(), report, time.Second)
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	for i, nonce := range []string{strings.Repeat("12", 32), strings.Repeat("34", 32)} {
		req, _ := http.NewRequest("GET", server.URL+"/v1/attestation/report?version=2&signing_algo=ed25519&nonce="+nonce, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		err = json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			t.Fatal(response.StatusCode, body)
		}
		spki, err := x509.MarshalPKIXPublicKey(response.TLS.PeerCertificates[0].PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := sha256.Sum256(spki)
		if body["tls_cert_fingerprint"] != hex.EncodeToString(fingerprint[:]) || body["request_nonce"] != nonce {
			t.Fatal("TLS/nonce mismatch", body)
		}
		address, err := hex.DecodeString(body["signing_address"].(string))
		if err != nil {
			t.Fatal(err)
		}
		expected := sha256.Sum256(append(append([]byte(nil), address...), fingerprint[:]...))
		quotes.mu.Lock()
		captured := append([]byte(nil), quotes.data[i]...)
		quotes.mu.Unlock()
		if len(captured) != 64 || hex.EncodeToString(captured[:32]) != hex.EncodeToString(expected[:]) || hex.EncodeToString(captured[32:]) != nonce {
			t.Fatal("quote report_data binding differs")
		}
	}
}
