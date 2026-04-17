// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ea

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	eaattestation "github.com/ultravioletrs/cocos/pkg/atls/eaattestation"
)

var (
	ErrTruncated                = errors.New("ea: truncated input")
	ErrInvalidLength            = errors.New("ea: invalid length")
	ErrUnsupportedHandshakeType = errors.New("ea: unsupported handshake type")
	ErrNotTLS13                 = errors.New("ea: not TLS 1.3")
	ErrUnknownCipherSuite       = errors.New("ea: unknown cipher suite")
	ErrContextReuse             = errors.New("ea: certificate_request_context already used")
	ErrInvalidRole              = errors.New("ea: invalid authenticator role")

	ErrUnsupportedSignatureScheme = errors.New("ea: unsupported signature scheme")
	ErrSignatureMismatch          = errors.New("ea: CertificateVerify signature mismatch")
	ErrFinishedMismatch           = errors.New("ea: Finished MAC mismatch")
	ErrContextMismatch            = errors.New("ea: certificate_request_context mismatch")
	ErrBadRequest                 = errors.New("ea: bad authenticator request")
)

type ValidationResult struct {
	Context        []byte
	Chain          []*x509.Certificate
	CMWAttestation []byte
	Attestation    *eaattestation.VerifiedPayload
	Empty          bool
}

func CreateAuthenticator(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, identity tls.Certificate, leafEntryExtensions []Extension) ([]byte, error) {
	return createAuthenticator(nil, st, role, req, nil, identity, leafEntryExtensions)
}

func CreateAuthenticatorWithPolicy(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, policy *SpontaneousAuthenticatorPolicy, identity tls.Certificate, leafEntryExtensions []Extension) ([]byte, error) {
	return createAuthenticator(nil, st, role, req, policy, identity, leafEntryExtensions)
}

func createAuthenticator(session *Session, st *tls.ConnectionState, role Role, req *AuthenticatorRequest, policy *SpontaneousAuthenticatorPolicy, identity tls.Certificate, leafEntryExtensions []Extension) ([]byte, error) {
	if st.Version != tls.VersionTLS13 {
		return nil, ErrNotTLS13
	}
	if req == nil && role != RoleServer {
		return nil, ErrInvalidRole
	}
	if err := validateCertificateEntryExtensions(leafEntryExtensions, req, policy); err != nil {
		return nil, err
	}
	emptyAuthenticator := len(identity.Certificate) == 0 && identity.PrivateKey == nil
	if !emptyAuthenticator && (len(identity.Certificate) == 0 || identity.PrivateKey == nil) {
		return nil, ErrBadRequest
	}

	var reqBytes []byte
	var offered []uint16
	var ctx []byte

	if req != nil {
		var err error
		reqBytes, err = req.Marshal()
		if err != nil {
			return nil, err
		}
		ctx = append([]byte(nil), req.Context...)
		if schemes, ok := req.SignatureSchemes(); ok {
			offered = schemes
		} else {
			return nil, fmt.Errorf("%w: missing signature_algorithms", ErrBadRequest)
		}
	} else {
		c, err := NewRandomContext(32)
		if err != nil {
			return nil, err
		}
		ctx = c
	}

	hsCtx, h, err := ExportHandshakeContext(st, role)
	if err != nil {
		return nil, err
	}
	fk, _, err := ExportFinishedKey(st, role)
	if err != nil {
		return nil, err
	}

	if emptyAuthenticator {
		if req == nil {
			return nil, ErrBadRequest
		}
		certBytes, err := (CertificateMessage{Context: ctx}).Marshal()
		if err != nil {
			return nil, err
		}
		th := hashConcat(h, hsCtx, reqBytes, certBytes)
		verifyData := hmacSum(h, fk, th)
		finBytes, err := (FinishedMessage{VerifyData: verifyData}).Marshal()
		if err != nil {
			return nil, err
		}
		if err := session.MarkContextUsed(ctx); err != nil {
			return nil, err
		}
		return finBytes, nil
	}

	scheme, err := chooseSignatureScheme(identity.PrivateKey, offered)
	if err != nil {
		return nil, err
	}
	if req == nil && !policyPermitsSignatureScheme(policy, scheme) {
		return nil, ErrUnsupportedSignatureScheme
	}

	entries := make([]CertificateEntry, 0, len(identity.Certificate))
	for i, der := range identity.Certificate {
		exts := []Extension(nil)
		if i == 0 && len(leafEntryExtensions) > 0 {
			exts = leafEntryExtensions
		}
		entries = append(entries, CertificateEntry{CertDER: der, Extensions: exts})
	}
	certBytes, err := (CertificateMessage{Context: ctx, Entries: entries}).Marshal()
	if err != nil {
		return nil, err
	}

	th1 := hashConcat(h, hsCtx, reqBytes, certBytes)
	sig, err := signCertVerify(identity.PrivateKey, scheme, th1)
	if err != nil {
		return nil, err
	}
	cvBytes, err := (CertificateVerifyMessage{Algorithm: scheme, Signature: sig}).Marshal()
	if err != nil {
		return nil, err
	}

	th2 := hashConcat(h, hsCtx, reqBytes, certBytes, cvBytes)
	verifyData := hmacSum(h, fk, th2)
	finBytes, err := (FinishedMessage{VerifyData: verifyData}).Marshal()
	if err != nil {
		return nil, err
	}

	if err := session.MarkContextUsed(ctx); err != nil {
		return nil, err
	}
	return append(append(certBytes, cvBytes...), finBytes...), nil
}

func ValidateAuthenticator(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, authBytes []byte, verifyOpts *x509.VerifyOptions) (*ValidationResult, error) {
	return validateAuthenticator(nil, st, role, req, nil, nil, authBytes, verifyOpts)
}

func ValidateAuthenticatorWithPolicy(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, policy *SpontaneousAuthenticatorPolicy, authBytes []byte, verifyOpts *x509.VerifyOptions) (*ValidationResult, error) {
	return validateAuthenticator(nil, st, role, req, policy, nil, authBytes, verifyOpts)
}

func ValidateAuthenticatorWithAttestation(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, authBytes []byte, verifyOpts *x509.VerifyOptions, attPolicy eaattestation.VerificationPolicy) (*ValidationResult, error) {
	return validateAuthenticator(nil, st, role, req, nil, &attPolicy, authBytes, verifyOpts)
}

func ValidateAuthenticatorWithPolicies(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, policy *SpontaneousAuthenticatorPolicy, authBytes []byte, verifyOpts *x509.VerifyOptions, attPolicy eaattestation.VerificationPolicy) (*ValidationResult, error) {
	return validateAuthenticator(nil, st, role, req, policy, &attPolicy, authBytes, verifyOpts)
}

func validateAuthenticator(session *Session, st *tls.ConnectionState, role Role, req *AuthenticatorRequest, policy *SpontaneousAuthenticatorPolicy, attPolicy *eaattestation.VerificationPolicy, authBytes []byte, verifyOpts *x509.VerifyOptions) (*ValidationResult, error) {
	if st.Version != tls.VersionTLS13 {
		return nil, ErrNotTLS13
	}

	hsCtx, h, err := ExportHandshakeContext(st, role)
	if err != nil {
		return nil, err
	}
	fk, _, err := ExportFinishedKey(st, role)
	if err != nil {
		return nil, err
	}

	var reqBytes []byte
	var offered []uint16
	var reqCtx []byte
	if req != nil {
		reqCtx = req.Context
		reqBytes, err = req.Marshal()
		if err != nil {
			return nil, err
		}
		if schemes, ok := req.SignatureSchemes(); ok {
			offered = schemes
		} else {
			return nil, fmt.Errorf("%w: missing signature_algorithms", ErrBadRequest)
		}
	}

	firstHm, rest, err := UnmarshalHandshakeMessage(authBytes)
	if err != nil {
		return nil, err
	}
	if firstHm.Type == HandshakeTypeFinished {
		if req == nil || len(rest) != 0 {
			return nil, ErrUnsupportedHandshakeType
		}
		finBytes, _ := MarshalHandshakeMessage(firstHm)
		finMsg, _, err := UnmarshalFinishedMessage(finBytes)
		if err != nil {
			return nil, err
		}
		certBytes, err := (CertificateMessage{Context: reqCtx}).Marshal()
		if err != nil {
			return nil, err
		}
		th := hashConcat(h, hsCtx, reqBytes, certBytes)
		expectedFin := hmacSum(h, fk, th)
		if !constantTimeEqual(expectedFin, finMsg.VerifyData) {
			return nil, ErrFinishedMismatch
		}
		if err := session.MarkContextUsed(reqCtx); err != nil {
			return nil, err
		}
		return &ValidationResult{
			Context: append([]byte(nil), reqCtx...),
			Empty:   true,
		}, nil
	}
	if firstHm.Type != HandshakeTypeCertificate {
		return nil, ErrUnsupportedHandshakeType
	}
	certHm := firstHm
	certBytes, _ := MarshalHandshakeMessage(certHm)

	cvHm, rest, err := UnmarshalHandshakeMessage(rest)
	if err != nil || cvHm.Type != HandshakeTypeCertificateVerify {
		return nil, ErrUnsupportedHandshakeType
	}
	cvBytes, _ := MarshalHandshakeMessage(cvHm)

	finHm, rest, err := UnmarshalHandshakeMessage(rest)
	if err != nil || finHm.Type != HandshakeTypeFinished || len(rest) != 0 {
		return nil, ErrInvalidLength
	}
	finBytes, _ := MarshalHandshakeMessage(finHm)

	certMsg, _, err := UnmarshalCertificateMessage(certBytes)
	if err != nil {
		return nil, err
	}
	cvMsg, _, err := UnmarshalCertificateVerifyMessage(cvBytes)
	if err != nil {
		return nil, err
	}
	finMsg, _, err := UnmarshalFinishedMessage(finBytes)
	if err != nil {
		return nil, err
	}

	if req != nil && !bytes.Equal(certMsg.Context, reqCtx) {
		return nil, ErrContextMismatch
	}
	if len(certMsg.Entries) == 0 {
		// Empty authenticators are encoded as Finished-only. A Certificate
		// message with zero entries followed by CertificateVerify/Finished is
		// malformed and must not be accepted as an empty authenticator.
		return nil, ErrUnsupportedHandshakeType
	}
	if err := ValidateCMWAttestationPlacement(certMsg.Entries); err != nil {
		return nil, err
	}
	for _, entry := range certMsg.Entries {
		if err := validateCertificateEntryExtensions(entry.Extensions, req, policy); err != nil {
			return nil, err
		}
	}

	extracted, present, err := ExtractCMWAttestationFromExtensions(certMsg.Entries[0].Extensions)
	if err != nil {
		return nil, err
	}
	if present && req != nil && !RequestPermitsCertificateExtension(req, CMWAttestationExtensionType) {
		return nil, ErrBadRequest
	}
	if present && req == nil && !PolicyPermitsCertificateExtension(policy, CMWAttestationExtensionType) {
		return nil, ErrBadRequest
	}

	chain := make([]*x509.Certificate, 0, len(certMsg.Entries))
	for _, e := range certMsg.Entries {
		c, err := x509.ParseCertificate(e.CertDER)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	leaf := chain[0]

	if req != nil {
		ok := false
		for _, s := range offered {
			if s == cvMsg.Algorithm {
				ok = true
				break
			}
		}
		if !ok {
			return nil, ErrUnsupportedSignatureScheme
		}
	}

	th1 := hashConcat(h, hsCtx, reqBytes, certBytes)
	if err := verifyCertVerify(leaf.PublicKey, cvMsg.Algorithm, th1, cvMsg.Signature); err != nil {
		return nil, err
	}

	th2 := hashConcat(h, hsCtx, reqBytes, certBytes, cvBytes)
	expectedFin := hmacSum(h, fk, th2)
	if !constantTimeEqual(expectedFin, finMsg.VerifyData) {
		return nil, ErrFinishedMismatch
	}

	if verifyOpts != nil {
		opts := *verifyOpts
		if opts.Intermediates == nil {
			opts.Intermediates = x509.NewCertPool()
		}
		for _, ic := range chain[1:] {
			opts.Intermediates.AddCert(ic)
		}
		if _, err := leaf.Verify(opts); err != nil {
			return nil, err
		}
	}
	if err := session.MarkContextUsed(certMsg.Context); err != nil {
		return nil, err
	}

	res := &ValidationResult{
		Context: append([]byte(nil), certMsg.Context...),
		Chain:   chain,
	}
	var verifierPolicy eaattestation.VerificationPolicy
	// A nil attestation policy is intentional: VerifyPayload then fails closed
	// for any payload that carries evidence or attestation results without
	// explicit verifiers being configured.
	if attPolicy != nil {
		verifierPolicy = *attPolicy
	}
	if !present && verifierPolicy.RequiresAttestation() {
		return nil, eaattestation.ErrMissingAttestation
	}
	if present {
		res.CMWAttestation = extracted
		parsed, err := eaattestation.ParsePayload(extracted)
		if err != nil {
			return nil, err
		}
		verified, err := eaattestation.VerifyPayload(st, eaattestation.ExporterLabelAttestation, certMsg.Context, leaf, parsed, verifierPolicy)
		if err != nil {
			return nil, err
		}
		res.Attestation = verified
	}
	return res, nil
}
