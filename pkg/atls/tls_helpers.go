// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

type tlsSetupResult struct {
	config *tls.Config
	mtls   bool
}

func readFileOrData(input string) ([]byte, error) {
	if len(input) < 1000 && !strings.Contains(input, "\n") {
		data, err := os.ReadFile(input)
		if err == nil {
			return data, nil
		}
		return nil, err
	}
	return []byte(input), nil
}

func loadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := readFileOrData(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read cert: %w", err)
	}

	key, err := readFileOrData(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read key: %w", err)
	}

	return tls.X509KeyPair(cert, key)
}

func loadCertFile(certFile string) ([]byte, error) {
	if certFile == "" {
		return []byte{}, nil
	}
	return readFileOrData(certFile)
}

func configureCertificateAuthorities(tlsConfig *tls.Config, serverCAFile, clientCAFile string) (bool, error) {
	rootCA, err := loadCertFile(serverCAFile)
	if err != nil {
		return false, fmt.Errorf("failed to load server ca file: %w", err)
	}
	if len(rootCA) > 0 {
		if tlsConfig.RootCAs == nil {
			tlsConfig.RootCAs = x509.NewCertPool()
		}
		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCA) {
			return false, fmt.Errorf("failed to append server ca to tls.Config")
		}
	}

	clientCA, err := loadCertFile(clientCAFile)
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
		return false, fmt.Errorf("failed to append client ca to tls.Config")
	}

	return true, nil
}

func setupRegularTLS(certFile, keyFile, serverCAFile, clientCAFile string) (*tlsSetupResult, error) {
	certificate, err := loadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load auth certificates: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{certificate},
	}

	mtls, err := configureCertificateAuthorities(tlsConfig, serverCAFile, clientCAFile)
	if err != nil {
		return nil, err
	}
	if mtls {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &tlsSetupResult{config: tlsConfig, mtls: mtls}, nil
}
