package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// loadTLSConfig returns the same certificate snapshot used by the listener and
// the report service. Changing a PEM file after startup cannot change the report
// key while the listener continues serving the previously loaded certificate.
func loadTLSConfig(certPath, keyPath string) (*tls.Config, []byte, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, nil, fmt.Errorf("TAIL TLS requires both TLS_CERT_PATH and TLS_KEY_PATH")
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load TAIL TLS key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse TAIL TLS certificate: %w", err)
	}
	certificate.Leaf = leaf
	fingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}, fingerprint[:], nil
}
