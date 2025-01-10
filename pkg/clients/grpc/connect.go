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

type ClientConfiguration interface {
	GetBaseConfig() BaseConfig
}

type BaseConfig struct {
	URL          string        `env:"URL"             envDefault:"localhost:7001"`
	Timeout      time.Duration `env:"TIMEOUT"         envDefault:"60s"`
	ClientCert   string        `env:"CLIENT_CERT"     envDefault:""`
	ClientKey    string        `env:"CLIENT_KEY"      envDefault:""`
	ServerCAFile string        `env:"SERVER_CA_CERTS"    envDefault:""`
}

type AgentClientConfig struct {
	BaseConfig
	AttestationPolicy string `env:"ATTESTATION_POLICY" envDefault:""`
	AttestedTLS       bool   `env:"ATTESTED_TLS"       envDefault:"false"`
}

type ManagerClientConfig struct {
	BaseConfig
}

type CVMClientConfig struct {
	BaseConfig
}

func (a BaseConfig) GetBaseConfig() BaseConfig {
	return a
}

func (a AgentClientConfig) GetBaseConfig() BaseConfig {
	return a.BaseConfig
}

func (a CVMClientConfig) GetBaseConfig() BaseConfig {
	return a.BaseConfig
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
	cfg    ClientConfiguration
	secure security
}

var _ Client = (*client)(nil)

func NewClient(cfg ClientConfiguration) (Client, error) {
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
func connect(cfg ClientConfiguration) (*grpc.ClientConn, security, error) {
	opts := []grpc.DialOption{
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
	secure := withoutTLS
	var tc credentials.TransportCredentials

	if agcfg, ok := cfg.(AgentClientConfig); ok && agcfg.AttestedTLS {
		err := ReadAttestationPolicy(agcfg.AttestationPolicy, &quoteprovider.AttConfigurationSEVSNP)
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
		conf := cfg.GetBaseConfig()
		transportCreds, err, sec := loadTLSConfig(conf.ServerCAFile, conf.ClientCert, conf.ClientKey)
		if err != nil {
			return nil, secure, err
		}
		tc = transportCreds
		secure = sec
	}

	opts = append(opts, grpc.WithTransportCredentials(tc))

	conn, err := grpc.NewClient(cfg.GetBaseConfig().URL, opts...)
	if err != nil {
		return nil, secure, errors.Wrap(errGrpcConnect, err)
	}
	return conn, secure, nil
}

func loadTLSConfig(serverCAFile, clientCert, clientKey string) (credentials.TransportCredentials, error, security) {
	tlsConfig := &tls.Config{}
	secure := withoutTLS
	tc := insecure.NewCredentials()

	// Load Root CA certificates
	if serverCAFile != "" {
		rootCA, err := os.ReadFile(serverCAFile)
		if err != nil {
			return nil, errors.Wrap(errFailedToLoadRootCA, err), secure
		}
		if len(rootCA) > 0 {
			capool := x509.NewCertPool()
			if !capool.AppendCertsFromPEM(rootCA) {
				return nil, fmt.Errorf("failed to append root ca to tls.Config"), secure
			}
			tlsConfig.RootCAs = capool
			secure = withTLS
			tc = credentials.NewTLS(tlsConfig)
		}
	}

	// Load mTLS certificates
	if clientCert != "" || clientKey != "" {
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, errors.Wrap(errFailedToLoadClientCertKey, err), secure
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
		secure = withmTLS
		tc = credentials.NewTLS(tlsConfig)
	}

	return tc, nil, secure
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
