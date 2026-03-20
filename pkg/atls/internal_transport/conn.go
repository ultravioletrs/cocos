package internaltransport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/ultravioletrs/cocos/pkg/atls/ea"
	eaattestation "github.com/ultravioletrs/cocos/pkg/atls/eaattestation"
)

type Conn struct {
	*tls.Conn
	Request          *ea.AuthenticatorRequest
	ValidationResult *ea.ValidationResult
}

type ClientConfig struct {
	TLSConfig         *tls.Config
	Session           *ea.Session
	VerifyOptions     *x509.VerifyOptions
	AttestationPolicy eaattestation.VerificationPolicy
	Request           *ea.AuthenticatorRequest
	RequestBuilder    func() (*ea.AuthenticatorRequest, error)
}

type ServerConfig struct {
	TLSConfig           *tls.Config
	Session             *ea.Session
	Identity            tls.Certificate
	BuildLeafExtensions func(*tls.ConnectionState, *ea.AuthenticatorRequest, *x509.Certificate) ([]ea.Extension, error)
}

func Dial(network, address string, cfg *ClientConfig) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, address, cfg)
}

func DialWithDialer(d *net.Dialer, network, address string, cfg *ClientConfig) (*Conn, error) {
	if cfg == nil || cfg.TLSConfig == nil {
		return nil, fmt.Errorf("atls: missing client TLS config")
	}
	rawConn, err := d.Dial(network, address)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, cfg.TLSConfig.Clone())
	conn, err := Client(tlsConn, cfg)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return conn, nil
}

func Client(tlsConn *tls.Conn, cfg *ClientConfig) (*Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("atls: missing client config")
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	req, err := buildRequest(cfg)
	if err != nil {
		return nil, err
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	if err := writeFrame(tlsConn, frameTypeRequest, reqBytes); err != nil {
		return nil, err
	}
	frameType, authBytes, err := readFrame(tlsConn)
	if err != nil {
		return nil, err
	}
	if frameType != frameTypeAuthenticator {
		return nil, fmt.Errorf("atls: unexpected frame type %d", frameType)
	}

	st := tlsConn.ConnectionState()
	var res *ea.ValidationResult
	if cfg.Session != nil {
		res, err = cfg.Session.ValidateAuthenticatorWithAttestation(&st, ea.RoleServer, req, authBytes, cfg.VerifyOptions, cfg.AttestationPolicy)
	} else {
		res, err = ea.ValidateAuthenticatorWithAttestation(&st, ea.RoleServer, req, authBytes, cfg.VerifyOptions, cfg.AttestationPolicy)
	}
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: tlsConn, Request: req, ValidationResult: res}, nil
}

func Server(tlsConn *tls.Conn, cfg *ServerConfig) (*Conn, error) {
	if cfg == nil || cfg.TLSConfig == nil {
		return nil, fmt.Errorf("atls: missing server config")
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	frameType, reqBytes, err := readFrame(tlsConn)
	if err != nil {
		return nil, err
	}
	if frameType != frameTypeRequest {
		return nil, fmt.Errorf("atls: unexpected frame type %d", frameType)
	}
	req, rest, err := ea.UnmarshalAuthenticatorRequest(reqBytes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("atls: trailing request bytes")
	}

	st := tlsConn.ConnectionState()
	identity, err := resolveIdentity(cfg)
	if err != nil {
		return nil, err
	}
	exts, err := buildServerExtensions(cfg, &st, &req, identity)
	if err != nil {
		return nil, err
	}

	var authBytes []byte
	if cfg.Session != nil {
		authBytes, err = cfg.Session.CreateAuthenticator(&st, ea.RoleServer, &req, identity, exts)
	} else {
		authBytes, err = ea.CreateAuthenticator(&st, ea.RoleServer, &req, identity, exts)
	}
	if err != nil {
		return nil, err
	}
	if err := writeFrame(tlsConn, frameTypeAuthenticator, authBytes); err != nil {
		return nil, err
	}
	return &Conn{Conn: tlsConn, Request: &req}, nil
}

func buildRequest(cfg *ClientConfig) (*ea.AuthenticatorRequest, error) {
	if cfg.RequestBuilder != nil {
		return cfg.RequestBuilder()
	}
	if cfg.Request != nil {
		return cfg.Request, nil
	}
	ctx, err := ea.NewRandomContext(32)
	if err != nil {
		return nil, err
	}
	sigExt, err := ea.SignatureAlgorithmsExtension([]uint16{uint16(tls.ECDSAWithP256AndSHA256)})
	if err != nil {
		return nil, err
	}
	return &ea.AuthenticatorRequest{
		Type:    ea.HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []ea.Extension{
			sigExt,
			ea.CMWAttestationOfferExtension(),
		},
	}, nil
}

func resolveIdentity(cfg *ServerConfig) (tls.Certificate, error) {
	if len(cfg.Identity.Certificate) > 0 && cfg.Identity.PrivateKey != nil {
		return cfg.Identity, nil
	}
	if cfg.TLSConfig != nil && len(cfg.TLSConfig.Certificates) > 0 {
		return cfg.TLSConfig.Certificates[0], nil
	}
	return tls.Certificate{}, fmt.Errorf("atls: missing server identity")
}

func buildServerExtensions(cfg *ServerConfig, st *tls.ConnectionState, req *ea.AuthenticatorRequest, identity tls.Certificate) ([]ea.Extension, error) {
	if cfg.BuildLeafExtensions == nil {
		return nil, nil
	}
	if len(identity.Certificate) == 0 {
		return nil, fmt.Errorf("atls: missing server leaf certificate")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return nil, err
	}
	return cfg.BuildLeafExtensions(st, req, leaf)
}
