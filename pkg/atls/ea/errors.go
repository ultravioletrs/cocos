package ea

import "errors"

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
