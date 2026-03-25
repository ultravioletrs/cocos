// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/ultravioletrs/cocos/pkg/atls/ea"
	eaattestation "github.com/ultravioletrs/cocos/pkg/atls/eaattestation"
	internaltransport "github.com/ultravioletrs/cocos/pkg/atls/internal_transport"
)

type Conn = internaltransport.Conn

type Listener = internaltransport.Listener

type ClientConfig = internaltransport.ClientConfig

type ServerConfig = internaltransport.ServerConfig

func Dial(network, address string, cfg *ClientConfig) (*Conn, error) {
	return internaltransport.Dial(network, address, cfg)
}

func DialContext(ctx context.Context, network, address string, cfg *ClientConfig) (*Conn, error) {
	return internaltransport.DialContext(ctx, network, address, cfg)
}

func DialWithDialer(dialer *net.Dialer, network, address string, cfg *ClientConfig) (*Conn, error) {
	return internaltransport.DialWithDialer(dialer, network, address, cfg)
}

func Client(tlsConn *tls.Conn, cfg *ClientConfig) (*Conn, error) {
	return internaltransport.Client(tlsConn, cfg)
}

func Server(tlsConn *tls.Conn, cfg *ServerConfig) (*Conn, error) {
	return internaltransport.Server(tlsConn, cfg)
}

func Listen(network, address string, cfg *ServerConfig) (*Listener, error) {
	return internaltransport.Listen(network, address, cfg)
}

func NewRequest(context []byte) (*ea.AuthenticatorRequest, error) {
	sigExt, err := ea.SignatureAlgorithmsExtension([]uint16{uint16(tls.ECDSAWithP256AndSHA256)})
	if err != nil {
		return nil, err
	}
	return &ea.AuthenticatorRequest{
		Type:    ea.HandshakeTypeClientCertificateRequest,
		Context: context,
		Extensions: []ea.Extension{
			sigExt,
			ea.CMWAttestationOfferExtension(),
		},
	}, nil
}

func VerifyOptionsFromTLSConfig(cfg *tls.Config) *x509.VerifyOptions {
	if cfg == nil || cfg.InsecureSkipVerify || cfg.RootCAs == nil {
		return nil
	}
	return &x509.VerifyOptions{Roots: cfg.RootCAs}
}

func VerificationPolicyFromEvidenceVerifier(v eaattestation.EvidenceVerifier) eaattestation.VerificationPolicy {
	return eaattestation.VerificationPolicy{EvidenceVerifier: v}
}
