// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	ErrAppendServerCA = errors.New("failed to append server ca to tls.Config")
	ErrAppendClientCA = errors.New("failed to append client ca to tls.Config")
)

// TLSSetupResult contains the result of TLS configuration setup.
type TLSSetupResult struct {
	Config *tls.Config
	MTLS   bool
}

// LoadCertFile loads certificate data from file path or returns empty byte slice if path is empty.
func LoadCertFile(certFile string) ([]byte, error) {
	if certFile != "" {
		return ReadFileOrData(certFile)
	}
	return []byte{}, nil
}

// ReadFileOrData reads data from file if input looks like a file path,
// otherwise treats input as raw data.
func ReadFileOrData(input string) ([]byte, error) {
	if len(input) < 1000 && !strings.Contains(input, "\n") {
		data, err := os.ReadFile(input)
		if err == nil {
			return data, nil
		}
		return nil, err
	}
	return []byte(input), nil
}

// LoadX509KeyPair loads X.509 key pair from certificate and key files or data.
func LoadX509KeyPair(certfile, keyfile string) (tls.Certificate, error) {
	cert, err := ReadFileOrData(certfile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read cert: %w", err)
	}

	key, err := ReadFileOrData(keyfile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read key: %w", err)
	}

	return tls.X509KeyPair(cert, key)
}

// ConfigureRootCA configures the root CA certificates for the TLS config.
func ConfigureRootCA(tlsConfig *tls.Config, serverCAFile string) error {
	rootCA, err := LoadCertFile(serverCAFile)
	if err != nil {
		return fmt.Errorf("failed to load server ca file: %w", err)
	}

	if len(rootCA) == 0 {
		return nil
	}

	if tlsConfig.RootCAs == nil {
		tlsConfig.RootCAs = x509.NewCertPool()
	}

	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCA) {
		return ErrAppendServerCA
	}

	return nil
}

// ConfigureClientCA configures the client CA certificates for the TLS config
// Returns true if client CA was configured, false otherwise.
func ConfigureClientCA(tlsConfig *tls.Config, clientCAFile string) (bool, error) {
	clientCA, err := LoadCertFile(clientCAFile)
	if err != nil {
		return false, fmt.Errorf("failed to load client ca file: %w", err)
	}

	if len(clientCA) == 0 {
		return false, nil
	}

	if tlsConfig.ClientCAs == nil {
		tlsConfig.ClientCAs = x509.NewCertPool()
	}

	if !tlsConfig.ClientCAs.AppendCertsFromPEM(clientCA) {
		return false, ErrAppendClientCA
	}

	return true, nil
}

// ConfigureCertificateAuthorities configures both root and client CAs for the TLS config
// Returns true if mTLS should be enabled (client CA is configured).
func ConfigureCertificateAuthorities(tlsConfig *tls.Config, serverCAFile, clientCAFile string) (bool, error) {
	// Configure root CA
	if err := ConfigureRootCA(tlsConfig, serverCAFile); err != nil {
		return false, err
	}

	// Configure client CA
	hasClientCA, err := ConfigureClientCA(tlsConfig, clientCAFile)
	if err != nil {
		return false, err
	}

	return hasClientCA, nil
}

// SetupRegularTLS sets up TLS configuration using regular certificates.
func SetupRegularTLS(certFile, keyFile, serverCAFile, clientCAFile string) (*TLSSetupResult, error) {
	certificate, err := LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load auth certificates: %w", err)
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{certificate},
	}

	mtls, err := ConfigureCertificateAuthorities(tlsConfig, serverCAFile, clientCAFile)
	if err != nil {
		return nil, err
	}

	if mtls {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &TLSSetupResult{Config: tlsConfig, MTLS: mtls}, nil
}

// BuildMTLSDescription builds a description string for mTLS configuration.
func BuildMTLSDescription(serverCAFile, clientCAFile string) string {
	var parts []string

	if serverCAFile != "" {
		parts = append(parts, fmt.Sprintf("root ca %s", serverCAFile))
	}

	if clientCAFile != "" {
		parts = append(parts, fmt.Sprintf("client ca %s", clientCAFile))
	}

	return strings.Join(parts, " ")
}
