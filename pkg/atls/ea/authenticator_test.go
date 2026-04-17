// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ea

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"

	attestation "github.com/ultravioletrs/cocos/pkg/atls/eaattestation"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ea-phase3"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func tlsPair(t *testing.T, cert tls.Certificate) (srv, cli *tls.Conn) {
	t.Helper()
	srvConf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	cliConf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	a, b := net.Pipe()
	srv = tls.Server(a, srvConf)
	cli = tls.Client(b, cliConf)
	errCh := make(chan error, 2)
	go func() { errCh <- srv.Handshake() }()
	go func() { errCh <- cli.Handshake() }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
	return srv, cli
}

type acceptEvidenceVerifier struct{}

func (acceptEvidenceVerifier) VerifyEvidence(evidence []byte) error { return nil }

const alternateExporterLabel = "Attestation Binding"

func TestDummyAttestationRoundTrip(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	ctx, _ := NewRandomContext(16)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
			CMWAttestationOfferExtension(),
		},
	}

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	srvState := srv.ConnectionState()
	_, aikPubHash, binding, err := attestation.ComputeBinding(&srvState, attestation.ExporterLabelAttestation, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := attestation.MarshalPayload(attestation.Payload{
		Version:   1,
		Evidence:  []byte("dummy-attestation-report"),
		MediaType: "application/eat+cwt",
		Binder: attestation.AttestationBinder{
			ExporterLabel: attestation.ExporterLabelAttestation,
			AIKPubHash:    aikPubHash,
			Binding:       binding,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := CMWAttestationDataExtension(payloadBytes)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := CreateAuthenticator(&srvState, RoleServer, req, cert, []Extension{ext})
	if err != nil {
		t.Fatal(err)
	}

	cliState := cli.ConnectionState()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	res, err := ValidateAuthenticatorWithAttestation(&cliState, RoleServer, req, auth, &x509.VerifyOptions{Roots: roots}, attestation.VerificationPolicy{
		EvidenceVerifier: acceptEvidenceVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.CMWAttestation, payloadBytes) {
		t.Fatalf("cmw mismatch")
	}
	if res.Attestation == nil || !res.Attestation.BindingVerified || !res.Attestation.EvidenceVerified {
		t.Fatalf("expected verified attestation result")
	}
}

func TestDummyAttestationRoundTripRejectsAlternateExporterLabel(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	ctx, _ := NewRandomContext(16)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
			CMWAttestationOfferExtension(),
		},
	}

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	srvState := srv.ConnectionState()
	_, aikPubHash, binding, err := attestation.ComputeBinding(&srvState, alternateExporterLabel, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := attestation.MarshalPayload(attestation.Payload{
		Version:   1,
		Evidence:  []byte("dummy-attestation-report"),
		MediaType: "application/eat+cwt",
		Binder: attestation.AttestationBinder{
			ExporterLabel: alternateExporterLabel,
			AIKPubHash:    aikPubHash,
			Binding:       binding,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := CMWAttestationDataExtension(payloadBytes)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := CreateAuthenticator(&srvState, RoleServer, req, cert, []Extension{ext})
	if err != nil {
		t.Fatal(err)
	}

	cliState := cli.ConnectionState()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	_, err = ValidateAuthenticatorWithAttestation(&cliState, RoleServer, req, auth, &x509.VerifyOptions{Roots: roots}, attestation.VerificationPolicy{
		EvidenceVerifier: acceptEvidenceVerifier{},
	})
	if err != attestation.ErrUnexpectedExporterLabel {
		t.Fatalf("got %v, want %v", err, attestation.ErrUnexpectedExporterLabel)
	}
}

func TestRejectIfNotOffered(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	ctx, _ := NewRandomContext(8)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
		},
	}

	ext, _ := CMWAttestationDataExtension([]byte("dummy"))
	srvState := srv.ConnectionState()
	if _, err := CreateAuthenticator(&srvState, RoleServer, req, cert, []Extension{ext}); err == nil {
		t.Fatalf("expected error when cmw_attestation not offered")
	}
}

func TestAttestationFailsClosedWithoutVerifier(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	ctx, _ := NewRandomContext(16)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
			CMWAttestationOfferExtension(),
		},
	}

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	srvState := srv.ConnectionState()
	_, aikPubHash, binding, err := attestation.ComputeBinding(&srvState, attestation.ExporterLabelAttestation, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := attestation.MarshalPayload(attestation.Payload{
		Version:  1,
		Evidence: []byte("dummy-attestation-report"),
		Binder: attestation.AttestationBinder{
			ExporterLabel: attestation.ExporterLabelAttestation,
			AIKPubHash:    aikPubHash,
			Binding:       binding,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := CMWAttestationDataExtension(payloadBytes)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := CreateAuthenticator(&srvState, RoleServer, req, cert, []Extension{ext})
	if err != nil {
		t.Fatal(err)
	}

	cliState := cli.ConnectionState()
	if _, err := ValidateAuthenticator(&cliState, RoleServer, req, auth, nil); err != attestation.ErrEvidenceVerificationMissing {
		t.Fatalf("got %v, want %v", err, attestation.ErrEvidenceVerificationMissing)
	}
}

func TestValidateAuthenticatorRejectsMissingOfferedAttestation(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	ctx, _ := NewRandomContext(16)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
			CMWAttestationOfferExtension(),
		},
	}

	srvState := srv.ConnectionState()
	auth, err := CreateAuthenticator(&srvState, RoleServer, req, cert, nil)
	if err != nil {
		t.Fatal(err)
	}

	cliState := cli.ConnectionState()
	roots := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(leaf)

	_, err = ValidateAuthenticatorWithAttestation(&cliState, RoleServer, req, auth, &x509.VerifyOptions{Roots: roots}, attestation.VerificationPolicy{
		EvidenceVerifier: acceptEvidenceVerifier{},
	})
	if err != attestation.ErrMissingAttestation {
		t.Fatalf("got %v, want %v", err, attestation.ErrMissingAttestation)
	}
}

func TestRejectCMWAttestationOnIntermediateEntry(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	ctx, _ := NewRandomContext(16)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
			CMWAttestationOfferExtension(),
		},
	}

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	srvState := srv.ConnectionState()
	hsCtx, h, err := ExportHandshakeContext(&srvState, RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	fk, _, err := ExportFinishedKey(&srvState, RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, aikPubHash, binding, err := attestation.ComputeBinding(&srvState, attestation.ExporterLabelAttestation, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := attestation.MarshalPayload(attestation.Payload{
		Version:   1,
		Evidence:  []byte("dummy-attestation-report"),
		MediaType: "application/eat+cwt",
		Binder: attestation.AttestationBinder{
			ExporterLabel: attestation.ExporterLabelAttestation,
			AIKPubHash:    aikPubHash,
			Binding:       binding,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := CMWAttestationDataExtension(payloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := (CertificateMessage{
		Context: ctx,
		Entries: []CertificateEntry{
			{CertDER: cert.Certificate[0]},
			{CertDER: cert.Certificate[0], Extensions: []Extension{ext}},
		},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	th1 := hashConcat(h, hsCtx, reqBytes, certBytes)
	sig, err := signCertVerify(cert.PrivateKey, uint16(tls.ECDSAWithP256AndSHA256), th1)
	if err != nil {
		t.Fatal(err)
	}
	cvBytes, err := (CertificateVerifyMessage{
		Algorithm: uint16(tls.ECDSAWithP256AndSHA256),
		Signature: sig,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	th2 := hashConcat(h, hsCtx, reqBytes, certBytes, cvBytes)
	finBytes, err := (FinishedMessage{VerifyData: hmacSum(h, fk, th2)}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	auth := append(append(certBytes, cvBytes...), finBytes...)

	cliState := cli.ConnectionState()
	if _, err := ValidateAuthenticatorWithAttestation(&cliState, RoleServer, req, auth, nil, attestation.VerificationPolicy{
		EvidenceVerifier: acceptEvidenceVerifier{},
	}); err != ErrBadRequest {
		t.Fatalf("got %v, want %v", err, ErrBadRequest)
	}
}

func TestSessionRejectsContextReuse(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	ctx, _ := NewRandomContext(12)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
		},
	}

	createSession := NewSession()
	srvState := srv.ConnectionState()
	auth, err := createSession.CreateAuthenticator(&srvState, RoleServer, req, cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createSession.CreateAuthenticator(&srvState, RoleServer, req, cert, nil); err != ErrContextReuse {
		t.Fatalf("got %v, want %v", err, ErrContextReuse)
	}

	validateSession := NewSession()
	cliState := cli.ConnectionState()
	roots := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	roots.AddCert(leaf)

	if _, err := validateSession.ValidateAuthenticator(&cliState, RoleServer, req, auth, &x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatal(err)
	}
	if _, err := validateSession.ValidateAuthenticator(&cliState, RoleServer, req, auth, &x509.VerifyOptions{Roots: roots}); err != ErrContextReuse {
		t.Fatalf("got %v, want %v", err, ErrContextReuse)
	}
}

func TestEmptyAuthenticatorRoundTrip(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	ctx, _ := NewRandomContext(10)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
		},
	}

	srvState := srv.ConnectionState()
	auth, err := CreateAuthenticator(&srvState, RoleServer, req, tls.Certificate{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cliState := cli.ConnectionState()
	res, err := ValidateAuthenticator(&cliState, RoleServer, req, auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Empty {
		t.Fatalf("expected empty authenticator result")
	}
	if len(res.Chain) != 0 {
		t.Fatalf("expected no certificate chain")
	}
}

func TestRejectCertificateMessageWithEmptyEntries(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	ctx, _ := NewRandomContext(10)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
		},
	}

	certBytes, err := (CertificateMessage{Context: ctx}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cvBytes, err := (CertificateVerifyMessage{
		Algorithm: uint16(tls.ECDSAWithP256AndSHA256),
		Signature: []byte{0x01},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	finBytes, err := (FinishedMessage{VerifyData: []byte{0x01}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	auth := append(append(certBytes, cvBytes...), finBytes...)

	cliState := cli.ConnectionState()
	if _, err := ValidateAuthenticator(&cliState, RoleServer, req, auth, nil); err != ErrUnsupportedHandshakeType {
		t.Fatalf("got %v, want %v", err, ErrUnsupportedHandshakeType)
	}
}

func TestRejectSpontaneousClientAuthenticator(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	cliState := cli.ConnectionState()
	if _, err := CreateAuthenticator(&cliState, RoleClient, nil, cert, nil); err != ErrInvalidRole {
		t.Fatalf("got %v, want %v", err, ErrInvalidRole)
	}
}

func TestRequestParsers(t *testing.T) {
	oidDER, err := asn1.Marshal(asn1.ObjectIdentifier{2, 5, 4, 3})
	if err != nil {
		t.Fatal(err)
	}
	oidFilterPayload := append([]byte{byte(len(oidDER))}, oidDER...)
	oidFilterPayload = append(oidFilterPayload, 0x00, 0x02, 'o', 'k')
	req := AuthenticatorRequest{
		Type:    HandshakeTypeCertificateRequest,
		Context: []byte{1, 2, 3},
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x07}},
			{Type: SignatureAlgorithmsCertExtensionType, Data: []byte{0x00, 0x02, 0x08, 0x07}},
			{Type: CertificateAuthoritiesExtensionType, Data: []byte{0x00, 0x06, 0x00, 0x04, 't', 'e', 's', 't'}},
			{Type: OIDFiltersExtensionType, Data: append([]byte{0x00, byte(len(oidFilterPayload))}, oidFilterPayload...)},
		},
	}

	if got, ok := req.SignatureSchemes(); !ok || len(got) != 2 || got[0] != uint16(tls.ECDSAWithP256AndSHA256) || got[1] != uint16(tls.Ed25519) {
		t.Fatalf("unexpected signature schemes: %v %v", got, ok)
	}
	if got, ok := req.SignatureSchemesCert(); !ok || len(got) != 1 || got[0] != uint16(tls.Ed25519) {
		t.Fatalf("unexpected signature_algorithms_cert: %v %v", got, ok)
	}
	if got, ok := req.CertificateAuthorities(); !ok || len(got) != 1 || string(got[0]) != "test" {
		t.Fatalf("unexpected certificate authorities: %q %v", got, ok)
	}
	if got, ok := req.OIDFilters(); !ok || len(got) != 1 || !got[0].OID.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) || string(got[0].Values) != "ok" {
		t.Fatalf("unexpected oid filters: %#v %v", got, ok)
	}
}

func TestRejectLeafExtensionNotPermittedByRequest(t *testing.T) {
	cert := selfSignedCert(t)
	srv, _ := tlsPair(t, cert)
	defer srv.Close()

	ctx, _ := NewRandomContext(8)
	req := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: ctx,
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
		},
	}

	srvState := srv.ConnectionState()
	ext := Extension{Type: 0x1234, Data: []byte{0x00}}
	if _, err := CreateAuthenticator(&srvState, RoleServer, req, cert, []Extension{ext}); err == nil {
		t.Fatalf("expected policy error for unpermitted leaf extension")
	}
}

func TestSpontaneousPolicyPermitsCertificateExtension(t *testing.T) {
	cert := selfSignedCert(t)
	srv, cli := tlsPair(t, cert)
	defer srv.Close()
	defer cli.Close()

	payloadBytes, err := attestation.MarshalPayload(attestation.Payload{
		Version:   1,
		Evidence:  []byte("dummy-attestation-report"),
		MediaType: "application/eat+cwt",
		Binder: attestation.AttestationBinder{
			ExporterLabel: attestation.ExporterLabelAttestation,
			AIKPubHash:    []byte("placeholder-aik"),
			Binding:       []byte("placeholder-binding"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := CMWAttestationDataExtension(payloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	policy := &SpontaneousAuthenticatorPolicy{
		AllowedSignatureSchemes:      []uint16{uint16(tls.ECDSAWithP256AndSHA256)},
		AllowedCertificateExtensions: []uint16{CMWAttestationExtensionType},
	}

	srvState := srv.ConnectionState()
	auth, err := CreateAuthenticatorWithPolicy(&srvState, RoleServer, nil, policy, cert, []Extension{ext})
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) == 0 {
		t.Fatalf("expected authenticator bytes")
	}
}

func TestSpontaneousPolicyRejectsCertificateExtension(t *testing.T) {
	cert := selfSignedCert(t)
	srv, _ := tlsPair(t, cert)
	defer srv.Close()

	ext, err := CMWAttestationDataExtension([]byte("dummy-attestation-report"))
	if err != nil {
		t.Fatal(err)
	}
	policy := &SpontaneousAuthenticatorPolicy{
		AllowedSignatureSchemes: []uint16{uint16(tls.ECDSAWithP256AndSHA256)},
	}

	srvState := srv.ConnectionState()
	if _, err := CreateAuthenticatorWithPolicy(&srvState, RoleServer, nil, policy, cert, []Extension{ext}); err == nil {
		t.Fatalf("expected policy error for unpermitted spontaneous extension")
	}
}

func TestSpontaneousPolicyRejectsSignatureScheme(t *testing.T) {
	cert := selfSignedCert(t)
	srv, _ := tlsPair(t, cert)
	defer srv.Close()

	policy := &SpontaneousAuthenticatorPolicy{
		AllowedSignatureSchemes: []uint16{uint16(tls.Ed25519)},
	}

	srvState := srv.ConnectionState()
	if _, err := CreateAuthenticatorWithPolicy(&srvState, RoleServer, nil, policy, cert, nil); err != ErrUnsupportedSignatureScheme {
		t.Fatalf("got %v, want %v", err, ErrUnsupportedSignatureScheme)
	}
}
