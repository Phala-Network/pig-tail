package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultListenAddress      = "127.0.0.1:31081"
	defaultHealthcheckTimeout = 5 * time.Second
)

type healthcheckConfig struct {
	listen   string
	certPath string
	keyPath  string
	timeout  time.Duration
}

func healthcheckConfigFromEnv() healthcheckConfig {
	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = defaultListenAddress
	}
	return healthcheckConfig{
		listen:   listen,
		certPath: os.Getenv("TLS_CERT_PATH"),
		keyPath:  os.Getenv("TLS_KEY_PATH"),
		timeout:  defaultHealthcheckTimeout,
	}
}

// runHealthcheck is a local listener liveness probe. It intentionally does
// not read TOKEN, UPSTREAM, Dstack, or NVIDIA state and does not establish
// backend readiness.
func runHealthcheck() error {
	return runHealthcheckWithConfig(healthcheckConfigFromEnv())
}

func runHealthcheckWithConfig(config healthcheckConfig) error {
	if config.timeout <= 0 {
		return fmt.Errorf("healthcheck timeout must be positive")
	}
	dialAddress, err := healthcheckDialAddress(config.listen)
	if err != nil {
		return err
	}

	serverTLS, _, err := loadTLSConfig(config.certPath, config.keyPath)
	if err != nil {
		return fmt.Errorf("healthcheck TLS configuration: %w", err)
	}

	scheme := "http"
	var clientTLS *tls.Config
	if serverTLS != nil {
		clientTLS, err = healthcheckTLSConfig(serverTLS)
		if err != nil {
			return err
		}
		scheme = "https"
	}

	dialer := &net.Dialer{Timeout: config.timeout}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", dialAddress)
		},
		TLSClientConfig:       clientTLS,
		TLSHandshakeTimeout:   config.timeout,
		ResponseHeaderTimeout: config.timeout,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()
	endpoint := (&url.URL{Scheme: scheme, Host: dialAddress, Path: "/healthz"}).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build healthcheck request: %w", err)
	}
	response, err := (&http.Client{
		Transport: transport,
		Timeout:   config.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}).Do(request)
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("healthcheck /healthz returned HTTP %d", response.StatusCode)
	}
	return nil
}

func healthcheckDialAddress(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return "", fmt.Errorf("healthcheck LISTEN must be host:port")
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	default:
		if address := net.ParseIP(host); address != nil && address.IsUnspecified() {
			if address.To4() != nil {
				host = "127.0.0.1"
			} else {
				host = "::1"
			}
		}
	}
	return net.JoinHostPort(host, port), nil
}

func healthcheckTLSConfig(serverTLS *tls.Config) (*tls.Config, error) {
	if len(serverTLS.Certificates) == 0 {
		return nil, fmt.Errorf("healthcheck TLS configuration has no certificate")
	}
	certificate := serverTLS.Certificates[0]
	leaf := certificate.Leaf
	if leaf == nil {
		if len(certificate.Certificate) == 0 {
			return nil, fmt.Errorf("healthcheck TLS certificate is empty")
		}
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse healthcheck TLS certificate: %w", err)
		}
	}
	serverName, err := healthcheckServerName(leaf)
	if err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname(serverName); err != nil {
		return nil, fmt.Errorf("healthcheck TLS certificate SAN: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	for _, rawCertificate := range certificate.Certificate {
		configuredCertificate, err := x509.ParseCertificate(rawCertificate)
		if err != nil {
			return nil, fmt.Errorf("parse configured healthcheck TLS certificate: %w", err)
		}
		roots.AddCert(configuredCertificate)
	}
	expectedLeaf := append([]byte(nil), leaf.Raw...)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: serverName,
		VerifyConnection: func(connection tls.ConnectionState) error {
			if len(connection.PeerCertificates) == 0 || !bytes.Equal(connection.PeerCertificates[0].Raw, expectedLeaf) {
				return fmt.Errorf("healthcheck TLS peer does not match configured certificate")
			}
			return nil
		},
	}, nil
}

func healthcheckServerName(leaf *x509.Certificate) (string, error) {
	for _, name := range leaf.DNSNames {
		name = strings.TrimSpace(name)
		if name != "" && !strings.HasPrefix(name, "*.") {
			return name, nil
		}
	}
	for _, name := range leaf.DNSNames {
		name = strings.TrimPrefix(strings.TrimSpace(name), "*.")
		if name != "" {
			return "healthcheck." + name, nil
		}
	}
	for _, address := range leaf.IPAddresses {
		if address != nil {
			return address.String(), nil
		}
	}
	return "", fmt.Errorf("healthcheck TLS certificate needs a DNS or IP SAN")
}
