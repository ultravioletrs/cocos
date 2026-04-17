// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

const alternateExporterLabel = "Attestation Binding"

type stubEvidenceVerifier struct {
	called bool
	err    error
}

func (s *stubEvidenceVerifier) VerifyEvidence(evidence []byte) error {
	s.called = true
	return s.err
}

type stubResultsVerifier struct {
	called bool
	err    error
}

func (s *stubResultsVerifier) VerifyAttestationResults(results []byte) error {
	s.called = true
	return s.err
}

func makeCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "binding"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, leaf
}

func tls13Client(t *testing.T, cert tls.Certificate) (*tls.Conn, *tls.Conn) {
	t.Helper()
	srvConf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	cliConf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	a, b := net.Pipe()
	srv := tls.Server(a, srvConf)
	cli := tls.Client(b, cliConf)
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

func TestComputeBindingDeterministic(t *testing.T) {
	cert, leaf := makeCert(t)
	srv, cli := tls13Client(t, cert)
	defer srv.Close()
	defer cli.Close()

	st := cli.ConnectionState()
	ctx := []byte{1, 2, 3, 4}

	ev1, aik1, b1, err := ComputeBinding(&st, ExporterLabelAttestation, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	ev2, aik2, b2, err := ComputeBinding(&st, ExporterLabelAttestation, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}

	if len(ev1) != ExportedAttestationValueLen {
		t.Fatalf("unexpected exported len: %d", len(ev1))
	}
	if !bytes.Equal(ev1, ev2) || !bytes.Equal(aik1, aik2) || !bytes.Equal(b1, b2) {
		t.Fatalf("expected deterministic outputs for same conn+context")
	}
	if bytes.Equal(aik1, b1) {
		t.Fatalf("unexpected aik == binding")
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	payload := Payload{
		Version:   1,
		MediaType: "application/eat+cwt",
		Evidence:  []byte("evidence"),
		Binder: AttestationBinder{
			ExporterLabel: ExporterLabelAttestation,
			AIKPubHash:    []byte("aik"),
			Binding:       []byte("binding"),
		},
	}

	raw, err := MarshalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != 1 || parsed.MediaType != "application/eat+cwt" || string(parsed.Evidence) != "evidence" {
		t.Fatalf("unexpected parsed payload: %#v", parsed)
	}
}

func TestVerifyPayloadSuccess(t *testing.T) {
	cert, leaf := makeCert(t)
	srv, cli := tls13Client(t, cert)
	defer srv.Close()
	defer cli.Close()

	st := cli.ConnectionState()
	ctx := []byte{1, 2, 3, 4}
	_, aik, binding, err := ComputeBinding(&st, ExporterLabelAttestation, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}

	ev := &stubEvidenceVerifier{}
	rv := &stubResultsVerifier{}
	payload := &Payload{
		Version:            1,
		Evidence:           []byte("evidence"),
		AttestationResults: []byte("results"),
		Binder: AttestationBinder{
			ExporterLabel: ExporterLabelAttestation,
			AIKPubHash:    aik,
			Binding:       binding,
		},
	}

	verified, err := VerifyPayload(&st, ExporterLabelAttestation, ctx, leaf, payload, VerificationPolicy{
		EvidenceVerifier: ev,
		ResultsVerifier:  rv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.BindingVerified || !verified.EvidenceVerified || !verified.ResultsVerified {
		t.Fatalf("unexpected verification result: %#v", verified)
	}
	if !ev.called || !rv.called {
		t.Fatalf("expected both verifiers to be called")
	}
}

func TestVerifyPayloadRejectsAlternateExporterLabel(t *testing.T) {
	cert, leaf := makeCert(t)
	srv, cli := tls13Client(t, cert)
	defer srv.Close()
	defer cli.Close()

	st := cli.ConnectionState()
	ctx := []byte{1, 2, 3, 4}
	_, aik, binding, err := ComputeBinding(&st, alternateExporterLabel, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}

	payload := &Payload{
		Version:  1,
		Evidence: []byte("evidence"),
		Binder: AttestationBinder{
			ExporterLabel: alternateExporterLabel,
			AIKPubHash:    aik,
			Binding:       binding,
		},
	}

	_, err = VerifyPayload(&st, ExporterLabelAttestation, ctx, leaf, payload, VerificationPolicy{
		EvidenceVerifier: &stubEvidenceVerifier{},
	})
	if err != ErrUnexpectedExporterLabel {
		t.Fatalf("got %v, want %v", err, ErrUnexpectedExporterLabel)
	}
}

func TestVerifyBinderRejectsMismatch(t *testing.T) {
	cert, leaf := makeCert(t)
	srv, cli := tls13Client(t, cert)
	defer srv.Close()
	defer cli.Close()

	st := cli.ConnectionState()
	ctx := []byte{1, 2, 3, 4}
	_, aik, binding, err := ComputeBinding(&st, ExporterLabelAttestation, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	binding[0] ^= 0xff

	err = VerifyBinder(&st, ExporterLabelAttestation, ctx, leaf, AttestationBinder{
		AIKPubHash: aik,
		Binding:    binding,
	})
	if err != ErrBindingMismatch {
		t.Fatalf("got %v, want %v", err, ErrBindingMismatch)
	}
}

func TestVerifyPayloadRejectsBadBinderBeforeEvidenceVerification(t *testing.T) {
	cert, leaf := makeCert(t)
	srv, cli := tls13Client(t, cert)
	defer srv.Close()
	defer cli.Close()

	st := cli.ConnectionState()
	ctx := []byte{1, 2, 3, 4}
	_, aik, binding, err := ComputeBinding(&st, ExporterLabelAttestation, ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	binding[0] ^= 0xff

	ev := &stubEvidenceVerifier{}
	payload := &Payload{
		Version:  1,
		Evidence: []byte("evidence"),
		Binder: AttestationBinder{
			ExporterLabel: ExporterLabelAttestation,
			AIKPubHash:    aik,
			Binding:       binding,
		},
	}

	_, err = VerifyPayload(&st, ExporterLabelAttestation, ctx, leaf, payload, VerificationPolicy{
		EvidenceVerifier: ev,
	})
	if err != ErrBindingMismatch {
		t.Fatalf("got %v, want %v", err, ErrBindingMismatch)
	}
	if ev.called {
		t.Fatalf("evidence verifier should not be called before binder verification succeeds")
	}
}
