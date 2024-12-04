// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

type security int

const (
	withoutTLS security = iota
	withTLS
	withmTLS
	withaTLS
)

const (
	AttestationReportSize = 0x4A0
	WithATLS              = "with aTLS"
	WithTLS               = "with TLS"
)

var (
	errGrpcConnect               = errors.New("failed to connect to grpc server")
	errGrpcClose                 = errors.New("failed to close grpc connection")
	errAttestationPolicyOpen     = errors.New("failed to open Attestation Policy file")
	ErrAttestationPolicyMissing  = errors.New("failed due to missing Attestation Policy file")
	ErrAttestationPolicyDecode   = errors.New("failed to decode Attestation Policy file")
	errCertificateParse          = errors.New("failed to parse x509 certificate")
	errAttVerification           = errors.New("certificat is not sefl signed")
	errFailedToLoadClientCertKey = errors.New("failed to load client certificate and key")
	errFailedToLoadRootCA        = errors.New("failed to load root ca file")
)

type Config struct {
	ClientCert        string        `env:"CLIENT_CERT"        envDefault:""`
	ClientKey         string        `env:"CLIENT_KEY"         envDefault:""`
	ServerCAFile      string        `env:"SERVER_CA_CERTS"    envDefault:""`
	URL               string        `env:"URL"                envDefault:"localhost:7001"`
	Timeout           time.Duration `env:"TIMEOUT"            envDefault:"60s"`
	AttestedTLS       bool          `env:"ATTESTED_TLS"       envDefault:"false"`
	AttestationPolicy string        `env:"ATTESTATION_POLICY" envDefault:""`
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
		return WithTLS
	case withmTLS:
		return "with mTLS"
	case withaTLS:
		return WithATLS
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
		err := ReadAttestationPolicy(cfg.AttestationPolicy, &quoteprovider.AttConfigurationSEVSNP)
		if err != nil {
			return nil, secure, errors.Wrap(fmt.Errorf("failed to read Attestation Policy"), err)
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: verifyPeerCertificateATLS,
		}
		tc = credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.WithContextDialer(CustomDialer))
		secure = withaTLS
	} else {
		if cfg.ServerCAFile != "" {
			tlsConfig := &tls.Config{}

			// Loading root ca certificates file
			rootCA, err := os.ReadFile(cfg.ServerCAFile)
			if err != nil {
				return nil, secure, errors.Wrap(errFailedToLoadRootCA, err)
			}
			if len(rootCA) > 0 {
				capool := x509.NewCertPool()
				if !capool.AppendCertsFromPEM(rootCA) {
					return nil, secure, fmt.Errorf("failed to append root ca to tls.Config")
				}
				tlsConfig.RootCAs = capool
				secure = withTLS
			}

			// Loading mTLS certificates file
			if cfg.ClientCert != "" || cfg.ClientKey != "" {
				certificate, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
				if err != nil {
					return nil, secure, errors.Wrap(errFailedToLoadClientCertKey, err)
				}
				tlsConfig.Certificates = []tls.Certificate{certificate}
				secure = withmTLS
			}

			tc = credentials.NewTLS(tlsConfig)
		}
	}

	opts = append(opts, grpc.WithTransportCredentials(tc))

	conn, err := grpc.NewClient(cfg.URL, opts...)
	if err != nil {
		return nil, secure, errors.Wrap(errGrpcConnect, err)
	}
	return conn, secure, nil
}

func ReadAttestationPolicy(manifestPath string, attestationConfiguration *check.Config) error {
	if manifestPath != "" {
		manifest, err := os.ReadFile(manifestPath)
		if err != nil {
			return errors.Wrap(errAttestationPolicyOpen, err)
		}

		if err := protojson.Unmarshal(manifest, attestationConfiguration); err != nil {
			return errors.Wrap(ErrAttestationPolicyDecode, err)
		}

		return nil
	}

	return ErrAttestationPolicyMissing
}

func CustomDialer(ctx context.Context, addr string) (net.Conn, error) {
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("could not create a custom dialer")
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bad format of IP address: %v", err)
	}

	conn, err := atls.DialTLSClient(ip, p)
	if err != nil {
		return nil, fmt.Errorf("could not create TLS connection")
	}

	return conn, nil
}

func verifyPeerCertificateATLS(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return errors.Wrap(errCertificateParse, err)
	}

	err = checkIfCertificateSelfSigned(cert)
	if err != nil {
		return errors.Wrap(errAttVerification, err)
	}

	return nil
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
