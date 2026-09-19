package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testHealthcheckConfig(t *testing.T, address string) healthcheckConfig {
	t.Helper()
	return healthcheckConfig{listen: address, timeout: time.Second}
}

func TestHealthcheckSuccessUsesLoopbackAndDoesNotNeedToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("healthcheck sent authorization")
		}
		_, _ = w.Write([]byte("ok\n"))
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TOKEN", "")
	t.Setenv("UPSTREAM", "")
	t.Setenv("LISTEN", net.JoinHostPort("0.0.0.0", port))
	t.Setenv("TLS_CERT_PATH", "")
	t.Setenv("TLS_KEY_PATH", "")
	if err := runHealthcheck(); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
}

func TestHealthcheckMapsWildcardBindsToLoopback(t *testing.T) {
	for listen, want := range map[string]string{
		"0.0.0.0:31081": "127.0.0.1:31081",
		"[::]:31081":    "[::1]:31081",
	} {
		got, err := healthcheckDialAddress(listen)
		if err != nil || got != want {
			t.Fatalf("LISTEN %q mapped to %q, %v; want %q", listen, got, err, want)
		}
	}
}

func TestHealthcheckRejectsNon2xx(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/ready" {
					w.WriteHeader(http.StatusOK)
					return
				}
				if status == http.StatusFound {
					w.Header().Set("Location", "/ready")
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			err := runHealthcheckWithConfig(testHealthcheckConfig(t, server.Listener.Addr().String()))
			if err == nil || !strings.Contains(err.Error(), "HTTP "+strconv.Itoa(status)) {
				t.Fatalf("HTTP %d error = %v", status, err)
			}
		})
	}
}

func TestHealthcheckTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	config := testHealthcheckConfig(t, server.Listener.Addr().String())
	config.timeout = 30 * time.Millisecond
	start := time.Now()
	err := runHealthcheckWithConfig(config)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout error=%v elapsed=%s", err, time.Since(start))
	}
}

func TestHealthcheckRejectsBadConfiguration(t *testing.T) {
	for _, config := range []healthcheckConfig{
		{listen: "not-a-listen-address", timeout: time.Second},
		{listen: "127.0.0.1:31081", certPath: "only-cert", timeout: time.Second},
		{listen: "127.0.0.1:31081", keyPath: "only-key", timeout: time.Second},
		{listen: "127.0.0.1:31081", timeout: 0},
	} {
		if err := runHealthcheckWithConfig(config); err == nil {
			t.Fatalf("bad configuration accepted: %+v", config)
		}
	}
	if _, err := healthcheckTLSConfig(&tls.Config{Certificates: []tls.Certificate{{Leaf: &x509.Certificate{}}}}); err == nil {
		t.Fatal("TLS certificate without SAN was accepted")
	}
}

func TestHealthcheckTLSVerifiesConfiguredCertificateAndSAN(t *testing.T) {
	directory := t.TempDir()
	trustedCert := filepath.Join(directory, "trusted.pem")
	trustedKey := filepath.Join(directory, "trusted.key")
	writeTLSFixture(t, trustedCert, trustedKey)
	serverTLS, _, err := loadTLSConfig(trustedCert, trustedKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		_, _ = w.Write([]byte("ok\n"))
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	config := testHealthcheckConfig(t, server.Listener.Addr().String())
	config.certPath, config.keyPath = trustedCert, trustedKey
	if err := runHealthcheckWithConfig(config); err != nil {
		t.Fatalf("trusted TLS healthcheck: %v", err)
	}

	untrustedCert := filepath.Join(directory, "untrusted.pem")
	untrustedKey := filepath.Join(directory, "untrusted.key")
	writeTLSFixture(t, untrustedCert, untrustedKey)
	config.certPath, config.keyPath = untrustedCert, untrustedKey
	if err := runHealthcheckWithConfig(config); err == nil {
		t.Fatal("untrusted TLS peer was accepted")
	}
}

func TestHealthcheckDispatchSkipsServerInitialization(t *testing.T) {
	called := false
	err := runCommand(
		[]string{"phala-tail", "healthcheck"},
		func() error {
			t.Fatal("server initialization ran for healthcheck")
			return nil
		},
		func() error {
			called = true
			return nil
		},
	)
	if err != nil || !called {
		t.Fatalf("healthcheck dispatch: called=%t error=%v", called, err)
	}
	if err := runCommand([]string{"phala-tail", "unexpected"}, func() error { return nil }, func() error { return nil }); err == nil {
		t.Fatal("unknown command was accepted")
	}
}
