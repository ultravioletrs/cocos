// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation"
)

type security int

const (
	withoutTLS security = iota
	withTLS
	withmTLS
	withaTLS
	withmaTLS
)

const (
	AttestationReportSize = 0x4A0
	WithMATLS             = "with maTLS"
	WithATLS              = "with aTLS"
	WithTLS               = "with TLS"
)

var (
	errFailedToLoadClientCertKey  = errors.New("failed to load client certificate and key")
	errFailedToLoadRootCA         = errors.New("failed to load root ca file")
	errCertificateParse           = errors.New("failed to parse x509 certificate")
	errAttVerification            = errors.New("certificate is not self signed")
	errAttestationPolicyIrregular = errors.New("attestation policy file is not a regular file")
)

type ClientConfiguration interface {
	Configuration() Config
}

type Config struct {
	URL          string        `env:"URL"             envDefault:"localhost:8080"`
	Timeout      time.Duration `env:"TIMEOUT"         envDefault:"60s"`
	ClientCert   string        `env:"CLIENT_CERT"     envDefault:""`
	ClientKey    string        `env:"CLIENT_KEY"      envDefault:""`
	ServerCAFile string        `env:"SERVER_CA_CERTS" envDefault:""`
}

type AgentClientConfig struct {
	Config

	AttestationPolicy string `env:"ATTESTATION_POLICY" envDefault:""`
	AttestedTLS       bool   `env:"ATTESTED_TLS"       envDefault:"false"`
	ProductName       string `env:"PRODUCT_NAME"       envDefault:"Milan"`
}

type ProxyClientConfig struct {
	Config
}

func (c Config) Configuration() Config {
	return c
}

func (a *AgentClientConfig) Configuration() Config {
	return a.Config
}

func (a ProxyClientConfig) Configuration() Config {
	return a.Config
}

type Client interface {
	Transport() *http.Transport
	Secure() string
	Timeout() time.Duration
}

type client struct {
	transport *http.Transport
	cfg       ClientConfiguration
	secure    security
}

var _ Client = (*client)(nil)

func NewClient(cfg ClientConfiguration) (Client, error) {
	transport, secure, err := createTransport(cfg)
	if err != nil {
		return nil, err
	}

	return &client{
		transport: transport,
		cfg:       cfg,
		secure:    secure,
	}, nil
}

func (c *client) Transport() *http.Transport {
	return c.transport
}

func (c *client) Secure() string {
	switch c.secure {
	case withTLS:
		return WithTLS
	case withmTLS:
		return "with mTLS"
	case withaTLS:
		return WithATLS
	case withmaTLS:
		return WithMATLS
	case withoutTLS:
		return "without TLS"
	default:
		return "without TLS"
	}
}

func (c *client) Timeout() time.Duration {
	return c.cfg.Configuration().Timeout
}

func createTransport(cfg ClientConfiguration) (*http.Transport, security, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	secure := withoutTLS

	if agcfg, ok := cfg.(*AgentClientConfig); ok && agcfg.AttestedTLS {
		tlsConfig, sec, err := setupATLS(agcfg)
		if err != nil {
			return nil, secure, err
		}

		transport.TLSClientConfig = tlsConfig
		secure = sec
	} else {
		conf := cfg.Configuration()

		tlsConfig, sec, err := loadTLSConfig(conf.ServerCAFile, conf.ClientCert, conf.ClientKey)
		if err != nil {
			return nil, secure, err
		}

		if sec != withoutTLS {
			transport.TLSClientConfig = tlsConfig
		}

		secure = sec
	}

	return transport, secure, nil
}

func loadTLSConfig(serverCAFile, clientCert, clientKey string) (*tls.Config, security, error) {
	tlsConfig := &tls.Config{}
	secure := withoutTLS

	// If no TLS configuration is provided, return nil config (no TLS)
	if serverCAFile == "" && clientCert == "" && clientKey == "" {
		return nil, secure, nil
	}

	if serverCAFile != "" {
		rootCA, err := os.ReadFile(serverCAFile)
		if err != nil {
			return nil, secure, errors.Wrap(errFailedToLoadRootCA, err)
		}

		if len(rootCA) > 0 {
			capool := x509.NewCertPool()
			if !capool.AppendCertsFromPEM(rootCA) {
				return nil, secure, errors.New("failed to append root ca to tls.Config")
			}

			tlsConfig.RootCAs = capool
			secure = withTLS
		}
	}

	if clientCert != "" || clientKey != "" {
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, secure, errors.Wrap(errFailedToLoadClientCertKey, err)
		}

		tlsConfig.Certificates = []tls.Certificate{certificate}
		secure = withmTLS
	}

	return tlsConfig, secure, nil
}

// setupATLS configures Attested TLS for the HTTP client.
func setupATLS(cfg *AgentClientConfig) (*tls.Config, security, error) {
	security := withaTLS

	info, err := os.Stat(cfg.AttestationPolicy)
	if err != nil {
		return nil, withoutTLS, errors.Wrap(errors.New("failed to stat attestation policy file"), err)
	}

	if !info.Mode().IsRegular() {
		return nil, withoutTLS, errAttestationPolicyIrregular
	}

	attestation.AttestationPolicyPath = cfg.AttestationPolicy

	var rootCAs *x509.CertPool

	if cfg.ServerCAFile != "" {
		// Read the certificate file
		certPEM, err := os.ReadFile(cfg.ServerCAFile)
		if err != nil {
			return nil, withoutTLS, errors.Wrap(errors.New("failed to read certificate file"), err)
		}

		// Decode the PEM block
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, withoutTLS, errors.New("failed to decode PEM block")
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, withoutTLS, errors.Wrap(errors.New("failed to parse certificate"), err)
		}

		rootCAs = x509.NewCertPool()
		rootCAs.AddCert(cert)

		security = withmaTLS
	}

	nonce := make([]byte, 64)
	if _, err := rand.Read(nonce); err != nil {
		return nil, withoutTLS, errors.Wrap(errors.New("failed to generate nonce"), err)
	}

	encoded := hex.EncodeToString(nonce)
	sni := encoded + ".nonce"

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            rootCAs,
		ServerName:         sni,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyPeerCertificateATLS(rawCerts, verifiedChains, nonce, rootCAs)
		},
	}

	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, withoutTLS, errors.Wrap(errFailedToLoadClientCertKey, err)
		}

		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return tlsConfig, security, nil
}

func verifyPeerCertificateATLS(rawCerts [][]byte, _ [][]*x509.Certificate, nonce []byte, rootCAs *x509.CertPool) error {
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return errors.Wrap(errCertificateParse, err)
	}

	err = checkSignature(cert, rootCAs)
	if err != nil {
		return errors.Wrap(errAttVerification, err)
	}

	for _, ext := range cert.Extensions {
		pType, err := atls.GetPlatformTypeFromOID(ext.Id)
		if err == nil {
			pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to marshal public key to DER format: %w", err)
			}

			return atls.VerifyCertificateExtension(ext.Value, pubKeyDER, nonce, pType)
		}
	}

	return errors.New("attestation extension not found in certificate")
}

func checkSignature(cert *x509.Certificate, rootCAs *x509.CertPool) error {
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
		rootCAs.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:       rootCAs,
		CurrentTime: time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}
