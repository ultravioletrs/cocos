package ea

import (
	"crypto/tls"
	"crypto/x509"
	"sync"

	eaattestation "github.com/ultravioletrs/cocos/pkg/atls/eaattestation"
)

type Session struct {
	mu   sync.Mutex
	used map[string]struct{}
}

func NewSession() *Session {
	return &Session{used: make(map[string]struct{})}
}

func (s *Session) MarkContextUsed(ctx []byte) error {
	if s == nil {
		return nil
	}
	key := string(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.used[key]; ok {
		return ErrContextReuse
	}
	s.used[key] = struct{}{}
	return nil
}

func (s *Session) CreateAuthenticator(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, identity tls.Certificate, leafEntryExtensions []Extension) ([]byte, error) {
	return createAuthenticator(s, st, role, req, nil, identity, leafEntryExtensions)
}

func (s *Session) ValidateAuthenticator(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, authBytes []byte, verifyOpts *x509.VerifyOptions) (*ValidationResult, error) {
	return validateAuthenticator(s, st, role, req, nil, nil, authBytes, verifyOpts)
}

func (s *Session) CreateAuthenticatorWithPolicy(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, policy *SpontaneousAuthenticatorPolicy, identity tls.Certificate, leafEntryExtensions []Extension) ([]byte, error) {
	return createAuthenticator(s, st, role, req, policy, identity, leafEntryExtensions)
}

func (s *Session) ValidateAuthenticatorWithPolicy(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, policy *SpontaneousAuthenticatorPolicy, authBytes []byte, verifyOpts *x509.VerifyOptions) (*ValidationResult, error) {
	return validateAuthenticator(s, st, role, req, policy, nil, authBytes, verifyOpts)
}

func (s *Session) ValidateAuthenticatorWithAttestation(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, authBytes []byte, verifyOpts *x509.VerifyOptions, attPolicy eaattestation.VerificationPolicy) (*ValidationResult, error) {
	return validateAuthenticator(s, st, role, req, nil, &attPolicy, authBytes, verifyOpts)
}

func (s *Session) ValidateAuthenticatorWithPolicies(st *tls.ConnectionState, role Role, req *AuthenticatorRequest, policy *SpontaneousAuthenticatorPolicy, authBytes []byte, verifyOpts *x509.VerifyOptions, attPolicy eaattestation.VerificationPolicy) (*ValidationResult, error) {
	return validateAuthenticator(s, st, role, req, policy, &attPolicy, authBytes, verifyOpts)
}
