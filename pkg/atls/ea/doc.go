package ea

// Phase 3: Minimal RFC 9261 Exported Authenticator builder/verifier + a private-use
// "cmw_attestation" extension with a dummy attestation report test.
//
// Notes:
// - This is application-layer EA: messages are serialized TLS handshake messages.
// - "cmw_attestation" extension type is private-use (0xFF00) until IANA assigns one.
