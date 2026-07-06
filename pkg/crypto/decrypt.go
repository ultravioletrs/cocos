// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/absmach/magistrala/pkg/errors"
)

var (
	// ErrDecryptionFailed indicates a decryption operation failed.
	ErrDecryptionFailed = errors.New("decryption failed")
	// ErrInvalidKey indicates the provided key is invalid.
	ErrInvalidKey = errors.New("invalid decryption key")
	// ErrInvalidCiphertext indicates the ciphertext is invalid or corrupted.
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	// ErrInvalidFormat indicates the encrypted resource format is invalid.
	ErrInvalidFormat = errors.New("invalid encrypted resource format")
)

// EncryptedResource represents an encrypted resource from KBS.
// This matches the format used by Confidential Containers KBS.
type EncryptedResource struct {
	// Ciphertext is the encrypted data.
	Ciphertext []byte `json:"ciphertext"`
	// EncryptedKey is the wrapped encryption key.
	EncryptedKey []byte `json:"encrypted_key"`
	// IV is the initialization vector for AES-GCM.
	IV []byte `json:"iv"`
	// Tag is the authentication tag for AES-GCM.
	Tag []byte `json:"tag"`
	// AAD is the additional authenticated data.
	AAD []byte `json:"aad,omitempty"`
	// EPK is the ephemeral public key for ECDH key derivation.
	EPK *EphemeralPublicKey `json:"epk,omitempty"`
}

// EphemeralPublicKey represents an ephemeral EC P-256 public key.
type EphemeralPublicKey struct {
	// Curve is the elliptic curve (should be "P-256").
	Curve string `json:"crv"`
	// X is the X coordinate of the public key.
	X string `json:"x"`
	// Y is the Y coordinate of the public key.
	Y string `json:"y"`
}

// DecryptAESGCM decrypts data using AES-GCM with the provided key.
// This is used when the decryption key is provided directly (not wrapped).
func DecryptAESGCM(ciphertext, key, iv, tag, aad []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.Wrap(ErrInvalidKey, errors.New("key must be 16, 24, or 32 bytes"))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(ErrDecryptionFailed, err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(ErrDecryptionFailed, err)
	}

	// Combine ciphertext and tag for GCM
	combined := append(ciphertext, tag...)

	plaintext, err := aesgcm.Open(nil, iv, combined, aad)
	if err != nil {
		return nil, errors.Wrap(ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// DecryptWithWrappedKey decrypts data using a wrapped key and ECDH key derivation.
// This matches the KBS encryption format with ephemeral key exchange.
func DecryptWithWrappedKey(encryptedResource EncryptedResource, privateKey *ecdh.PrivateKey) ([]byte, error) {
	if encryptedResource.EPK == nil {
		return nil, errors.Wrap(ErrInvalidFormat, errors.New("ephemeral public key is required"))
	}

	// Decode ephemeral public key coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(encryptedResource.EPK.X)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(encryptedResource.EPK.Y)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, err)
	}

	// Reconstruct ephemeral public key (uncompressed format: 0x04 || X || Y)
	epkBytes := make([]byte, 1+len(xBytes)+len(yBytes))
	epkBytes[0] = 0x04
	copy(epkBytes[1:], xBytes)
	copy(epkBytes[1+len(xBytes):], yBytes)

	curve := ecdh.P256()
	epk, err := curve.NewPublicKey(epkBytes)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, err)
	}

	// Perform ECDH to derive shared secret
	sharedSecret, err := privateKey.ECDH(epk)
	if err != nil {
		return nil, errors.Wrap(ErrDecryptionFailed, err)
	}

	// Derive KEK (Key Encryption Key) using Concat KDF (NIST SP 800-56A)
	algStr := "ECDH-ES+A256KW"
	otherInfo := make([]byte, 0, 4+len(algStr)+4+4+4)
	algLen := uint32(len(algStr))
	otherInfo = append(otherInfo, byte(algLen>>24), byte(algLen>>16), byte(algLen>>8), byte(algLen))
	otherInfo = append(otherInfo, algStr...)
	otherInfo = append(otherInfo, 0, 0, 0, 0) // PartyUInfo
	otherInfo = append(otherInfo, 0, 0, 0, 0) // PartyVInfo
	otherInfo = append(otherInfo, 0, 0, 1, 0) // SuppPubInfo (256 bits BE)

	// Since we need a 32-byte KEK, and SHA-256 produces 32 bytes, we run exactly 1 iteration (counter = 1)
	counter := uint32(1)
	hashInput := make([]byte, 0, 4+len(sharedSecret)+len(otherInfo))
	hashInput = append(hashInput, byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter))
	hashInput = append(hashInput, sharedSecret...)
	hashInput = append(hashInput, otherInfo...)

	h := sha256.New()
	h.Write(hashInput)
	kek := h.Sum(nil)

	// Unwrap the content encryption key (CEK)
	cek, err := unwrapKey(encryptedResource.EncryptedKey, kek)
	if err != nil {
		return nil, err
	}

	// Decrypt the actual content using the CEK
	plaintext, err := DecryptAESGCM(
		encryptedResource.Ciphertext,
		cek,
		encryptedResource.IV,
		encryptedResource.Tag,
		encryptedResource.AAD,
	)
	if err != nil {
		return nil, err
	}

	// Zero out sensitive key material
	zeroBytes(kek)
	zeroBytes(cek)
	zeroBytes(sharedSecret)

	return plaintext, nil
}

// unwrapKey unwraps an encrypted key using AES Key Wrap (RFC 3394).
func unwrapKey(wrappedKey, kek []byte) ([]byte, error) {
	if len(wrappedKey)%8 != 0 || len(wrappedKey) < 24 {
		return nil, errors.Wrap(ErrInvalidKey, errors.New("wrapped key length must be a multiple of 8 and at least 24 bytes"))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errors.Wrap(ErrDecryptionFailed, err)
	}

	n := len(wrappedKey)/8 - 1
	r := make([][]byte, n+1)
	r[0] = wrappedKey[:8]
	for i := 1; i <= n; i++ {
		r[i] = wrappedKey[i*8 : (i+1)*8]
	}

	a := r[0]
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			b := make([]byte, 16)
			for k := 0; k < 8; k++ {
				b[k] = a[k] ^ byte(t>>(56-8*k))
			}
			copy(b[8:], r[i])

			block.Decrypt(b, b)
			a = b[:8]
			r[i] = b[8:]
		}
	}

	// Check integrity value
	expectedIV := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	for i := 0; i < 8; i++ {
		if a[i] != expectedIV[i] {
			return nil, errors.Wrap(ErrDecryptionFailed, errors.New("key unwrap integrity check failed"))
		}
	}

	// Concatenate unwrapped key
	unwrapped := make([]byte, 0, n*8)
	for i := 1; i <= n; i++ {
		unwrapped = append(unwrapped, r[i]...)
	}

	return unwrapped, nil
}

func decodeBase64(s string) ([]byte, error) {
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	if d, err := base64.URLEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	if d, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	if d, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	return nil, errors.New("invalid base64 encoding")
}

// ParseEncryptedResource parses a JSON-encoded encrypted resource.
func ParseEncryptedResource(data []byte) (*EncryptedResource, error) {
	var jwe struct {
		Protected    string `json:"protected"`
		EncryptedKey string `json:"encrypted_key"`
		IV           string `json:"iv"`
		Ciphertext   string `json:"ciphertext"`
		Tag          string `json:"tag"`
	}
	if err := json.Unmarshal(data, &jwe); err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, err)
	}

	// JWE structure check: if it lacks protected header, try legacy standard struct unmarshal
	if jwe.Protected == "" {
		var legacy struct {
			Ciphertext   string              `json:"ciphertext"`
			EncryptedKey string              `json:"encrypted_key"`
			IV           string              `json:"iv"`
			Tag          string              `json:"tag"`
			AAD          string              `json:"aad,omitempty"`
			EPK          *EphemeralPublicKey `json:"epk,omitempty"`
		}
		if err := json.Unmarshal(data, &legacy); err != nil {
			return nil, errors.Wrap(ErrInvalidFormat, err)
		}

		ciphertext, err := decodeBase64(legacy.Ciphertext)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidFormat, err)
		}

		encryptedKey, err := decodeBase64(legacy.EncryptedKey)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidFormat, err)
		}

		iv, err := decodeBase64(legacy.IV)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidFormat, err)
		}

		tag, err := decodeBase64(legacy.Tag)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidFormat, err)
		}

		var aad []byte
		if legacy.AAD != "" {
			aad, err = decodeBase64(legacy.AAD)
			if err != nil {
				return nil, errors.Wrap(ErrInvalidFormat, err)
			}
		}

		return &EncryptedResource{
			Ciphertext:   ciphertext,
			EncryptedKey: encryptedKey,
			IV:           iv,
			Tag:          tag,
			AAD:          aad,
			EPK:          legacy.EPK,
		}, nil
	}

	// 1. Decode Protected Header JSON
	protectedJSON, err := decodeBase64(jwe.Protected)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, fmt.Errorf("failed to decode JWE protected header: %w", err))
	}

	// 2. Parse Ephemeral Public Key (EPK) from Protected Header
	var header struct {
		Alg string              `json:"alg"`
		EPK *EphemeralPublicKey `json:"epk"`
	}
	if err := json.Unmarshal(protectedJSON, &header); err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, fmt.Errorf("failed to parse JWE header JSON: %w", err))
	}

	// 3. Decode main crypto fields
	ciphertext, err := decodeBase64(jwe.Ciphertext)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, err)
	}

	encryptedKey, err := decodeBase64(jwe.EncryptedKey)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, err)
	}

	iv, err := decodeBase64(jwe.IV)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, err)
	}

	tag, err := decodeBase64(jwe.Tag)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, err)
	}

	// In JWE, AAD is the ASCII bytes of the protected header string
	aad := []byte(jwe.Protected)

	return &EncryptedResource{
		Ciphertext:   ciphertext,
		EncryptedKey: encryptedKey,
		IV:           iv,
		Tag:          tag,
		AAD:          aad,
		EPK:          header.EPK,
	}, nil
}

// zeroBytes securely zeros out a byte slice.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
