// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	atls "github.com/ultravioletrs/cocos/pkg/tls_extensions"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
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

const (
	cocosDirectory        = ".cocos"
	caBundleName          = "ask_ark.pem"
	productNameMilan      = "Milan"
	productNameGenoa      = "Genoa"
	attestationReportSize = 0x4A0
)

var (
	errGrpcConnect  = errors.New("failed to connect to grpc server")
	errGrpcClose    = errors.New("failed to close grpc connection")
	errManifestOpen = errors.New("failed to open Manifest")
	// errManifestMissing = errors.New("failed due to missing Manifest")
	errManifestDecode = errors.New("failed to decode Manifest json")
	// errCertificateParse = errors.New("failed to parse x509 certificate")
	errAttVerification = errors.New("attestation verification failed")
	errAttValidation   = errors.New("attestation validation failed")
	// errCustomExtension  = errors.New("failed due to missing custom extension")
)

var (
	// customSEVSNPExtensionOID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}
	attestationConfiguration = AttestationConfiguration{}
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
	BackendInfo  string        `env:"BACKEND_INFO"    envDefault:""`
}

type AttestationConfiguration struct {
	SNPPolicy   *check.Policy      `json:"snp_policy,omitempty"`
	RootOfTrust *check.RootOfTrust `json:"root_of_trust,omitempty"`
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
		err := ReadBackendInfo(cfg.BackendInfo, &attestationConfiguration)
		if err != nil {
			return nil, secure, errors.Wrap(fmt.Errorf("failed to read Backend Info"), err)
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: verifyPeerCertificateATLS,
		}
		tc = credentials.NewTLS(tlsConfig)
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
	opts = append(opts, grpc.WithContextDialer(CustomDialer))

	conn, err := grpc.NewClient(cfg.URL, opts...)
	if err != nil {
		return nil, secure, errors.Wrap(errGrpcConnect, err)
	}
	return conn, secure, nil
}

func ReadBackendInfo(manifestPath string, attestationConfiguration *AttestationConfiguration) error {
	if manifestPath != "" {
		manifest, err := os.Open(manifestPath)
		if err != nil {
			return errors.Wrap(errBackendInfoOpen, err)
		}
		defer manifest.Close()

		decoder := json.NewDecoder(manifest)
		err = decoder.Decode(attestationConfiguration)
		if err != nil {
			return errors.Wrap(ErrBackendInfoDecode, err)
		}

		return nil
	}

	return ErrBackendInfoMissing
}

func CustomDialer(ctx context.Context, addr string) (net.Conn, error) {
	fmt.Printf("CustomDialer - Addr is: %s\n", addr)
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("could not create a custom dialer")
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bad format of IP address: %v", err)
	}

	vvHandle := atls.RegisterGoVVCallback(VerifyAttestationReportTLS)
	conn, err := atls.DialTLSClient(ip, p, vvHandle)
	if err != nil {
		return nil, fmt.Errorf("could not create TLS connection")
	}

	return conn, nil
}

func VerifyAttestationReportTLS(attestationBytes []byte, reportData []byte) int {
	attestationConfiguration.SNPPolicy.ReportData = reportData[:]

	// Attestation verification and validation
	sopts, err := verify.RootOfTrustToOptions(attestationConfiguration.RootOfTrust)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttVerification, err))
		return -1
	}

	sopts.Product = attestationConfiguration.SNPPolicy.Product
	sopts.Getter = &trust.RetryHTTPSGetter{
		Timeout:       timeout,
		MaxRetryDelay: maxTryDelay,
		Getter:        &trust.SimpleHTTPSGetter{},
	}

	attestationPB, err := abi.ReportCertsToProto(attestationBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttVerification, err))
		return -1
	}

	if err := fillInAttestationLocal(attestationPB); err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		return -1
	}

	if err = verify.SnpAttestation(attestationPB, sopts); err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttVerification, err))
		return -1
	}

	opts, err := validate.PolicyToOptions(attestationConfiguration.SNPPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttVerification, err))
		return -1
	}

	if err = validate.SnpAttestation(attestationPB, opts); err != nil {
		fmt.Fprintf(os.Stderr, "%v", errors.Wrap(errAttValidation, err))
		return -1
	}

	return 0
}

func verifyPeerCertificateATLS(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	fmt.Println("verifyPeerCertificateATLS called!")
	// cert, err := x509.ParseCertificate(rawCerts[0])
	// if err != nil {
	// 	return errors.Wrap(errCertificateParse, err)
	// }

	// for _, ext := range cert.Extensions {
	// 	if ext.Id.Equal(customSEVSNPExtensionOID) {
	// 		// Check if the certificate is self-signed
	// 		err := checkIfCertificateSelfSigned(cert)
	// 		if err != nil {
	// 			return errors.Wrap(errAttVerification, err)
	// 		}

	// 		publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	// 		if err != nil {
	// 			return errors.Wrap(errAttVerification, err)
	// 		}

	// 		expectedReportData := sha3.Sum512(publicKeyBytes)
	// 		attestationConfiguration.SNPPolicy.ReportData = expectedReportData[:]

	// 		return nil
	// 	}
	// }

	return nil
	// return errCustomExtension
}

// func checkIfCertificateSelfSigned(cert *x509.Certificate) error {
// 	certPool := x509.NewCertPool()
// 	certPool.AddCert(cert)

// 	opts := x509.VerifyOptions{
// 		Roots:       certPool,
// 		CurrentTime: time.Now(),
// 	}

// 	if _, err := cert.Verify(opts); err != nil {
// 		return err
// 	}

// 	return nil
// }

func fillInAttestationLocal(attestation *sevsnp.Attestation) error {
	product := attestationConfiguration.RootOfTrust.ProductLine

	chain := attestation.GetCertificateChain()
	if chain == nil {
		chain = &sevsnp.CertificateChain{}
		attestation.CertificateChain = chain
	}
	if len(chain.GetAskCert()) == 0 || len(chain.GetArkCert()) == 0 {
		homePath, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		bundleFilePath := path.Join(homePath, cocosDirectory, product, caBundleName)
		if _, err := os.Stat(bundleFilePath); err == nil {
			amdRootCerts := trust.AMDRootCerts{}
			if err := amdRootCerts.FromKDSCert(bundleFilePath); err != nil {
				return err
			}

			chain.ArkCert = amdRootCerts.ProductCerts.Ark.Raw
			chain.AskCert = amdRootCerts.ProductCerts.Ask.Raw
		}
	}

	return nil
}
