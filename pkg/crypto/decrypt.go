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

	"github.com/absmach/supermq/pkg/errors"
	"golang.org/x/crypto/hkdf"
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

	// Derive KEK (Key Encryption Key) using HKDF
	kek := make([]byte, 32)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, nil)
	if _, err := kdf.Read(kek); err != nil {
		return nil, errors.Wrap(ErrDecryptionFailed, err)
	}

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

// ParseEncryptedResource parses a JSON-encoded encrypted resource.
func ParseEncryptedResource(data []byte) (*EncryptedResource, error) {
	var resource EncryptedResource
	if err := json.Unmarshal(data, &resource); err != nil {
		return nil, errors.Wrap(ErrInvalidFormat, err)
	}
	return &resource, nil
}

// zeroBytes securely zeros out a byte slice.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
