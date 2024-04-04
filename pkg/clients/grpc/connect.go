// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/ultravioletrs/cocos/agent"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type security int

const (
	withoutTLS security = iota
	withTLS
	withmTLS
)

var (
	errGrpcConnect = errors.New("failed to connect to grpc server")
	errGrpcClose   = errors.New("failed to close grpc connection")
)

var (
	customSEVSNPExtensionOID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}
	computation              = agent.Computation{}
	timeout                  = time.Minute * 2
	maxTryDelay              = time.Second * 30
)

type Config struct {
	ClientCert   string        `env:"CLIENT_CERT"     envDefault:""`
	ClientKey    string        `env:"CLIENT_KEY"      envDefault:""`
	ServerCAFile string        `env:"SERVER_CA_CERTS" envDefault:""`
	URL          string        `env:"URL"             envDefault:"localhost:7001"`
	Timeout      time.Duration `env:"TIMEOUT"         envDefault:"60s"`
	AttestedTLS  bool          `env:"ATTESTED_TLS"    envDefault:"false"`
	Manifest     string        `env:"MANIFEST"        envDefault:""`
}

type Client interface {
	// Close closes gRPC connection.
	Close() error

	// Secure is used for pretty printing TLS info.
	Secure() string

	// Connection returns the gRPC connection.
	Connection() *grpc.ClientConn
}

type client struct {
	*grpc.ClientConn
	cfg    Config
	secure security
}

var _ Client = (*client)(nil)

func NewClient(cfg Config) (Client, error) {
	conn, secure, err := connect(cfg)
	if err != nil {
		return nil, err
	}

	return &client{
		ClientConn: conn,
		cfg:        cfg,
		secure:     secure,
	}, nil
}

func (c *client) Close() error {
	if err := c.ClientConn.Close(); err != nil {
		return errors.Wrap(errGrpcClose, err)
	}

	return nil
}

func (c *client) Secure() string {
	switch c.secure {
	case withTLS:
		return "with TLS"
	case withmTLS:
		return "with mTLS"
	case withoutTLS:
		fallthrough
	default:
		return "without TLS"
	}
}

func (c *client) Connection() *grpc.ClientConn {
	return c.ClientConn
}

// connect creates new gRPC client and connect to gRPC server.
func connect(cfg Config) (*grpc.ClientConn, security, error) {
	opts := []grpc.DialOption{
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
	secure := withoutTLS
	tc := insecure.NewCredentials()

	if cfg.AttestedTLS {
		err := readManifest(cfg)
		if err != nil {
			return nil, secure, fmt.Errorf("failed to read Manifest %w", err)
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: verifyAttestationReportTLS,
		}
		tc = credentials.NewTLS(tlsConfig)
	} else {
		if cfg.ServerCAFile != "" {
			tlsConfig := &tls.Config{}

			// Loading root ca certificates file
			rootCA, err := os.ReadFile(cfg.ServerCAFile)
			if err != nil {
				return nil, secure, fmt.Errorf("failed to load root ca file: %w", err)
			}
			if len(rootCA) > 0 {
				capool := x509.NewCertPool()
				if !capool.AppendCertsFromPEM(rootCA) {
					return nil, secure, fmt.Errorf("failed to append root ca to tls.Config")
				}
				tlsConfig.RootCAs = capool
				secure = withTLS
			}

			// Loading mtls certificates file
			if cfg.ClientCert != "" || cfg.ClientKey != "" {
				certificate, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
				if err != nil {
					return nil, secure, fmt.Errorf("failed to client certificate and key %w", err)
				}
				tlsConfig.Certificates = []tls.Certificate{certificate}
				secure = withmTLS
			}

			tc = credentials.NewTLS(tlsConfig)
		}
	}

	opts = append(opts, grpc.WithTransportCredentials(tc))

	conn, err := grpc.Dial(cfg.URL, opts...)
	if err != nil {
		return nil, secure, errors.Wrap(errGrpcConnect, err)
	}
	return conn, secure, nil
}

func readManifest(cfg Config) error {
	if cfg.Manifest != "" {
		manifest, err := os.Open(cfg.Manifest)
		if err != nil {
			return fmt.Errorf("failed to open manifest %w", err)
		}
		defer manifest.Close()

		decoder := json.NewDecoder(manifest)
		err = decoder.Decode(&computation)
		if err != nil {
			return fmt.Errorf("manifest file is malformed %w", err)
		}

		return nil
	}

	return fmt.Errorf("manifest does not exist")
}

func verifyAttestationReportTLS(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse certficate %w", err)
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(customSEVSNPExtensionOID) {
			// Check if the certificate is self-signed
			err := checkIfCertificateSelfSigned(cert)
			if err != nil {
				return fmt.Errorf("attestation verification failed, certificate is not self-signed %w", err)
			}

			publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return fmt.Errorf("attestation verification failed, PublicKey marshaling failed %w", err)
			}

			expectedReportData := sha3.Sum512(publicKeyBytes)
			computation.SNPPolicy.ReportData = expectedReportData[:]

			// Attestation verification and validation
			sopts, err := verify.RootOfTrustToOptions(computation.RootOFTrust)
			if err != nil {
				return fmt.Errorf("attestation verification failed, root of trust to options failed %w", err)
			}

			sopts.Product = computation.SNPPolicy.Product
			sopts.Getter = &trust.RetryHTTPSGetter{
				Timeout:       timeout,
				MaxRetryDelay: maxTryDelay,
				Getter:        &trust.SimpleHTTPSGetter{},
			}

			attestationPB, err := abi.ReportCertsToProto(ext.Value)
			if err != nil {
				return fmt.Errorf("attestation verification failed, certs to proto failed %w", err)
			}

			if err = verify.SnpAttestation(attestationPB, sopts); err != nil {
				return fmt.Errorf("attestation verification failed: %w", err)
			}

			opts, err := validate.PolicyToOptions(computation.SNPPolicy)
			if err != nil {
				return fmt.Errorf("attestation verification failed, policy to options failed %w", err)
			}

			if err = validate.SnpAttestation(attestationPB, opts); err != nil {
				return fmt.Errorf("attestation validation failed %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("custom extension for SEV-SNP not found")
}

func checkIfCertificateSelfSigned(cert *x509.Certificate) error {
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	opts := x509.VerifyOptions{
		Roots:       certPool,
		CurrentTime: time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}
