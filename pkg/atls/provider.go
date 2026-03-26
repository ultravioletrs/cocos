// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/absmach/certs/sdk"
	"github.com/ultravioletrs/cocos/pkg/atls/ea"
	eaattestation "github.com/ultravioletrs/cocos/pkg/atls/eaattestation"
	cocosattestation "github.com/ultravioletrs/cocos/pkg/attestation"
	attestationclient "github.com/ultravioletrs/cocos/pkg/clients/grpc/attestation"
)

// CertificateProvider is kept for compatibility with existing cocos call sites.
// In the EA-based implementation it provides the leaf certificate-entry extensions
// carried in the exported authenticator instead of generating TLS certificates.
type CertificateProvider interface {
	BuildLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate) ([]ea.Extension, error)
}

type provider struct {
	attClient    attestationclient.Client
	platformType cocosattestation.PlatformType
}

func NewProvider(attClient attestationclient.Client, platformType cocosattestation.PlatformType, _ string, _ string, _ sdk.SDK) (CertificateProvider, error) {
	if attClient == nil {
		return nil, fmt.Errorf("atls: missing attestation client")
	}
	if platformType == cocosattestation.NoCC {
		return nil, fmt.Errorf("atls: confidential computing platform not available")
	}
	return &provider{
		attClient:    attClient,
		platformType: platformType,
	}, nil
}

func (p *provider) BuildLeafExtensions(st *tls.ConnectionState, req *ea.AuthenticatorRequest, leaf *x509.Certificate) ([]ea.Extension, error) {
	if st == nil || req == nil || leaf == nil {
		return nil, fmt.Errorf("atls: missing state, request, or leaf certificate")
	}
	exportedValue, aikPubHash, binding, err := eaattestation.ComputeBinding(st, eaattestation.ExporterLabelAttestation, req.Context, leaf)
	if err != nil {
		return nil, err
	}

	reportData := sha512.Sum512(binding)
	nonceBytes := sha256.Sum256(exportedValue)
	var nonce [32]byte
	copy(nonce[:], nonceBytes[:])

	evidence, err := p.attClient.GetAttestation(context.Background(), reportData, nonce, p.platformType)
	if err != nil {
		return nil, fmt.Errorf("atls: failed to fetch attestation evidence: %w", err)
	}

	payloadBytes, err := eaattestation.MarshalPayload(eaattestation.Payload{
		Version:   1,
		MediaType: "application/eat+cwt",
		Evidence:  evidence,
		Binder: eaattestation.AttestationBinder{
			ExporterLabel: eaattestation.ExporterLabelAttestation,
			AIKPubHash:    aikPubHash,
			Binding:       binding,
		},
	})
	if err != nil {
		return nil, err
	}

	ext, err := ea.CMWAttestationDataExtension(payloadBytes)
	if err != nil {
		return nil, err
	}
	return []ea.Extension{ext}, nil
}
