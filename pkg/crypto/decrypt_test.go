// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// testAESKeyWrap implements RFC 3394 AES Key Wrap for use in test setup.
func testAESKeyWrap(kek, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(key) / 8
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := make([][]byte, n+1)
	for i := 1; i <= n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], key[(i-1)*8:i*8])
	}

	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			t := uint64(n*j + i)
			b := make([]byte, 16)
			copy(b[:8], a)
			copy(b[8:], r[i])
			block.Encrypt(b, b)
			for k := 0; k < 8; k++ {
				a[k] = b[k] ^ byte(t>>(56-8*k))
			}
			r[i] = make([]byte, 8)
			copy(r[i], b[8:])
		}
	}

	result := make([]byte, (n+1)*8)
	copy(result[:8], a)
	for i := 1; i <= n; i++ {
		copy(result[i*8:(i+1)*8], r[i])
	}
	return result, nil
}

func TestDecryptAESGCM(t *testing.T) {
	// Generate a valid key
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	// Generate valid plaintext
	plaintext := []byte("test plaintext data")

	// Create cipher and encrypt
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	aesgcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	iv := make([]byte, aesgcm.NonceSize())
	_, err = rand.Read(iv)
	require.NoError(t, err)

	aad := []byte("additional data")
	ciphertext := aesgcm.Seal(nil, iv, plaintext, aad)
	// Split ciphertext and tag
	tag := ciphertext[len(ciphertext)-aesgcm.Overhead():]
	ciphertextOnly := ciphertext[:len(ciphertext)-aesgcm.Overhead()]

	tests := []struct {
		name       string
		ciphertext []byte
		key        []byte
		iv         []byte
		tag        []byte
		aad        []byte
		wantErr    bool
		errContain string
	}{
		{
			name:       "valid decryption",
			ciphertext: ciphertextOnly,
			key:        key,
			iv:         iv,
			tag:        tag,
			aad:        aad,
			wantErr:    false,
		},
		{
			name:       "invalid key length",
			ciphertext: ciphertextOnly,
			key:        []byte("short"),
			iv:         iv,
			tag:        tag,
			aad:        aad,
			wantErr:    true,
			errContain: "key must be 16, 24, or 32 bytes",
		},
		{
			name:       "wrong key",
			ciphertext: ciphertextOnly,
			key:        make([]byte, 32),
			iv:         iv,
			tag:        tag,
			aad:        aad,
			wantErr:    true,
			errContain: "decryption failed",
		},
		{
			name:       "corrupted tag",
			ciphertext: ciphertextOnly,
			key:        key,
			iv:         iv,
			tag:        make([]byte, len(tag)),
			aad:        aad,
			wantErr:    true,
			errContain: "decryption failed",
		},
		{
			name:       "wrong aad",
			ciphertext: ciphertextOnly,
			key:        key,
			iv:         iv,
			tag:        tag,
			aad:        []byte("wrong aad"),
			wantErr:    true,
			errContain: "decryption failed",
		},
		{
			name:       "16 byte key",
			ciphertext: nil,
			key:        make([]byte, 16),
			iv:         nil,
			tag:        nil,
			aad:        nil,
			wantErr:    false,
		},
		{
			name:       "24 byte key",
			ciphertext: nil,
			key:        make([]byte, 24),
			iv:         nil,
			tag:        nil,
			aad:        nil,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For tests with nil ciphertext, create new cipher with specified key
			if tt.ciphertext == nil && !tt.wantErr {
				_, err := rand.Read(tt.key)
				require.NoError(t, err)

				block, err := aes.NewCipher(tt.key)
				require.NoError(t, err)

				aesgcm, err := cipher.NewGCM(block)
				require.NoError(t, err)

				tt.iv = make([]byte, aesgcm.NonceSize())
				_, err = rand.Read(tt.iv)
				require.NoError(t, err)

				tt.aad = []byte("test aad")
				ciphertext := aesgcm.Seal(nil, tt.iv, plaintext, tt.aad)
				tt.tag = ciphertext[len(ciphertext)-aesgcm.Overhead():]
				tt.ciphertext = ciphertext[:len(ciphertext)-aesgcm.Overhead()]
			}

			got, err := DecryptAESGCM(tt.ciphertext, tt.key, tt.iv, tt.tag, tt.aad)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, plaintext, got)
			}
		})
	}
}

func TestParseEncryptedResource(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name: "valid encrypted resource",
			data: func() []byte {
				resource := EncryptedResource{
					Ciphertext:   []byte("encrypted data"),
					EncryptedKey: []byte("wrapped key"),
					IV:           []byte("initialization vector"),
					Tag:          []byte("auth tag"),
					AAD:          []byte("additional data"),
				}
				data, err := json.Marshal(resource)
				if err != nil {
					panic(err)
				}
				return data
			}(),
			wantErr: false,
		},
		{
			name: "valid encrypted resource with EPK",
			data: func() []byte {
				resource := EncryptedResource{
					Ciphertext:   []byte("encrypted data"),
					EncryptedKey: []byte("wrapped key"),
					IV:           []byte("initialization vector"),
					Tag:          []byte("auth tag"),
					EPK: &EphemeralPublicKey{
						Curve: "P-256",
						X:     "AAAA",
						Y:     "BBBB",
					},
				}
				data, err := json.Marshal(resource)
				if err != nil {
					panic(err)
				}
				return data
			}(),
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			data:    []byte("not valid json"),
			wantErr: true,
		},
		{
			name:    "empty JSON",
			data:    []byte("{}"),
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEncryptedResource(tt.data)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "zero empty slice",
			input: []byte{},
		},
		{
			name:  "zero small slice",
			input: []byte{1, 2, 3, 4, 5},
		},
		{
			name:  "zero large slice",
			input: make([]byte, 1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill with non-zero values
			for i := range tt.input {
				tt.input[i] = byte(i + 1)
			}

			zeroBytes(tt.input)

			// Verify all bytes are zero
			for i, b := range tt.input {
				assert.Equal(t, byte(0), b, "byte at index %d should be 0", i)
			}
		})
	}
}

func TestDecryptWithWrappedKey(t *testing.T) {
	tests := []struct {
		name              string
		encryptedResource EncryptedResource
		privateKey        *ecdh.PrivateKey
		wantErr           bool
		errContain        string
	}{
		{
			name: "missing ephemeral public key",
			encryptedResource: EncryptedResource{
				Ciphertext:   []byte("test"),
				EncryptedKey: []byte("key"),
				IV:           []byte("iv"),
				Tag:          []byte("tag"),
				EPK:          nil,
			},
			privateKey: nil,
			wantErr:    true,
			errContain: "ephemeral public key is required",
		},
		{
			name: "invalid X coordinate encoding",
			encryptedResource: EncryptedResource{
				Ciphertext:   []byte("test"),
				EncryptedKey: []byte("key"),
				IV:           []byte("iv"),
				Tag:          []byte("tag"),
				EPK: &EphemeralPublicKey{
					Curve: "P-256",
					X:     "!!!invalid base64!!!",
					Y:     "AAAA",
				},
			},
			privateKey: nil,
			wantErr:    true,
			errContain: "invalid encrypted resource format",
		},
		{
			name: "invalid Y coordinate encoding",
			encryptedResource: EncryptedResource{
				Ciphertext:   []byte("test"),
				EncryptedKey: []byte("key"),
				IV:           []byte("iv"),
				Tag:          []byte("tag"),
				EPK: &EphemeralPublicKey{
					Curve: "P-256",
					X:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
					Y:     "!!!invalid base64!!!",
				},
			},
			privateKey: nil,
			wantErr:    true,
			errContain: "invalid encrypted resource format",
		},
		{
			name: "invalid public key bytes",
			encryptedResource: EncryptedResource{
				Ciphertext:   []byte("test"),
				EncryptedKey: []byte("key"),
				IV:           []byte("iv"),
				Tag:          []byte("tag"),
				EPK: &EphemeralPublicKey{
					Curve: "P-256",
					X:     base64.RawURLEncoding.EncodeToString([]byte("short")),
					Y:     base64.RawURLEncoding.EncodeToString([]byte("short")),
				},
			},
			privateKey: func() *ecdh.PrivateKey {
				key, _ := ecdh.P256().GenerateKey(rand.Reader)
				return key
			}(),
			wantErr:    true,
			errContain: "invalid encrypted resource format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecryptWithWrappedKey(tt.encryptedResource, tt.privateKey)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestUnwrapKey(t *testing.T) {
	tests := []struct {
		name       string
		wrappedKey []byte
		kek        []byte
		wantErr    bool
		errContain string
	}{
		{
			name:       "wrapped key too short",
			wrappedKey: []byte("short"),
			kek:        make([]byte, 32),
			wantErr:    true,
			errContain: "wrapped key length must be a multiple of 8 and at least 24 bytes",
		},
		{
			name:       "wrapped key not multiple of 8",
			wrappedKey: make([]byte, 25),
			kek:        make([]byte, 32),
			wantErr:    true,
			errContain: "wrapped key length must be a multiple of 8 and at least 24 bytes",
		},
		{
			name:       "invalid kek length",
			wrappedKey: make([]byte, 24),
			kek:        []byte("short"),
			wantErr:    true,
			errContain: "decryption failed",
		},
		{
			name:       "integrity check failure",
			wrappedKey: make([]byte, 24),
			kek:        make([]byte, 32),
			wantErr:    true,
			errContain: "key unwrap integrity check failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unwrapKey(tt.wrappedKey, tt.kek)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestEncryptedResourceStructure(t *testing.T) {
	t.Run("EphemeralPublicKey JSON serialization", func(t *testing.T) {
		epk := EphemeralPublicKey{
			Curve: "P-256",
			X:     "test_x",
			Y:     "test_y",
		}

		data, err := json.Marshal(epk)
		require.NoError(t, err)

		var decoded EphemeralPublicKey
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, epk.Curve, decoded.Curve)
		assert.Equal(t, epk.X, decoded.X)
		assert.Equal(t, epk.Y, decoded.Y)
	})

	t.Run("EncryptedResource JSON serialization", func(t *testing.T) {
		resource := EncryptedResource{
			Ciphertext:   []byte("ciphertext"),
			EncryptedKey: []byte("encrypted_key"),
			IV:           []byte("iv"),
			Tag:          []byte("tag"),
			AAD:          []byte("aad"),
			EPK: &EphemeralPublicKey{
				Curve: "P-256",
				X:     "x_coord",
				Y:     "y_coord",
			},
		}

		data, err := json.Marshal(resource)
		require.NoError(t, err)

		var decoded EncryptedResource
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, resource.Ciphertext, decoded.Ciphertext)
		assert.Equal(t, resource.EncryptedKey, decoded.EncryptedKey)
		assert.Equal(t, resource.IV, decoded.IV)
		assert.Equal(t, resource.Tag, decoded.Tag)
		assert.Equal(t, resource.AAD, decoded.AAD)
		assert.NotNil(t, decoded.EPK)
		assert.Equal(t, resource.EPK.Curve, decoded.EPK.Curve)
	})
}

func TestDecryptWithWrappedKeyFullRoundTrip(t *testing.T) {
	t.Run("full ECDH + key wrap + AES-GCM round trip", func(t *testing.T) {
		// Generate recipient private key (who will decrypt)
		recipientKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Generate ephemeral key pair (used to encrypt)
		ephemeralKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Compute shared secret: ephemeral_private ECDH recipient_public
		sharedSecret, err := ephemeralKey.ECDH(recipientKey.PublicKey())
		require.NoError(t, err)

		// Derive KEK using HKDF (same as in DecryptWithWrappedKey)
		kek := make([]byte, 32)
		kdf := hkdf.New(sha256.New, sharedSecret, nil, nil)
		_, err = kdf.Read(kek)
		require.NoError(t, err)

		// Generate random CEK (32 bytes)
		cek := make([]byte, 32)
		_, err = rand.Read(cek)
		require.NoError(t, err)

		// Wrap CEK using AES Key Wrap (RFC 3394)
		wrappedKey, err := testAESKeyWrap(kek, cek)
		require.NoError(t, err)

		// Encrypt plaintext with AES-GCM using CEK
		plaintext := []byte("hello world secret message for testing")
		blk, err := aes.NewCipher(cek)
		require.NoError(t, err)
		aesgcm, err := cipher.NewGCM(blk)
		require.NoError(t, err)
		iv := make([]byte, aesgcm.NonceSize())
		_, err = rand.Read(iv)
		require.NoError(t, err)

		// Go's Seal returns ciphertext || tag
		combined := aesgcm.Seal(nil, iv, plaintext, nil)
		ciphertext := combined[:len(combined)-aesgcm.Overhead()]
		tag := combined[len(combined)-aesgcm.Overhead():]

		// Get ephemeral public key coordinates (uncompressed: 0x04 || X(32) || Y(32))
		epkPubBytes := ephemeralKey.PublicKey().Bytes()
		xBytes := epkPubBytes[1:33]
		yBytes := epkPubBytes[33:65]

		resource := EncryptedResource{
			Ciphertext:   ciphertext,
			EncryptedKey: wrappedKey,
			IV:           iv,
			Tag:          tag,
			EPK: &EphemeralPublicKey{
				Curve: "P-256",
				X:     base64.RawURLEncoding.EncodeToString(xBytes),
				Y:     base64.RawURLEncoding.EncodeToString(yBytes),
			},
		}

		decrypted, err := DecryptWithWrappedKey(resource, recipientKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("full round trip with AAD", func(t *testing.T) {
		recipientKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		ephemeralKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		sharedSecret, err := ephemeralKey.ECDH(recipientKey.PublicKey())
		require.NoError(t, err)

		kek := make([]byte, 32)
		kdf := hkdf.New(sha256.New, sharedSecret, nil, nil)
		_, err = kdf.Read(kek)
		require.NoError(t, err)

		cek := make([]byte, 16) // 16-byte CEK (AES-128)
		_, err = rand.Read(cek)
		require.NoError(t, err)

		wrappedKey, err := testAESKeyWrap(kek, cek)
		require.NoError(t, err)

		plaintext := []byte("confidential data with AAD")
		aad := []byte("additional authenticated data")

		blk, err := aes.NewCipher(cek)
		require.NoError(t, err)
		aesgcm, err := cipher.NewGCM(blk)
		require.NoError(t, err)
		iv := make([]byte, aesgcm.NonceSize())
		_, err = rand.Read(iv)
		require.NoError(t, err)

		combined := aesgcm.Seal(nil, iv, plaintext, aad)
		ciphertext := combined[:len(combined)-aesgcm.Overhead()]
		tag := combined[len(combined)-aesgcm.Overhead():]

		epkPubBytes := ephemeralKey.PublicKey().Bytes()
		xBytes := epkPubBytes[1:33]
		yBytes := epkPubBytes[33:65]

		resource := EncryptedResource{
			Ciphertext:   ciphertext,
			EncryptedKey: wrappedKey,
			IV:           iv,
			Tag:          tag,
			AAD:          aad,
			EPK: &EphemeralPublicKey{
				Curve: "P-256",
				X:     base64.RawURLEncoding.EncodeToString(xBytes),
				Y:     base64.RawURLEncoding.EncodeToString(yBytes),
			},
		}

		decrypted, err := DecryptWithWrappedKey(resource, recipientKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("wrong private key fails decryption", func(t *testing.T) {
		recipientKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)
		wrongKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		ephemeralKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		sharedSecret, err := ephemeralKey.ECDH(recipientKey.PublicKey())
		require.NoError(t, err)

		kek := make([]byte, 32)
		kdf := hkdf.New(sha256.New, sharedSecret, nil, nil)
		_, err = kdf.Read(kek)
		require.NoError(t, err)

		cek := make([]byte, 32)
		_, err = rand.Read(cek)
		require.NoError(t, err)

		wrappedKey, err := testAESKeyWrap(kek, cek)
		require.NoError(t, err)

		plaintext := []byte("secret")
		blk, err := aes.NewCipher(cek)
		require.NoError(t, err)
		aesgcm, err := cipher.NewGCM(blk)
		require.NoError(t, err)
		iv := make([]byte, aesgcm.NonceSize())
		_, err = rand.Read(iv)
		require.NoError(t, err)

		combined := aesgcm.Seal(nil, iv, plaintext, nil)
		ciphertext := combined[:len(combined)-aesgcm.Overhead()]
		tag := combined[len(combined)-aesgcm.Overhead():]

		epkPubBytes := ephemeralKey.PublicKey().Bytes()
		xBytes := epkPubBytes[1:33]
		yBytes := epkPubBytes[33:65]

		resource := EncryptedResource{
			Ciphertext:   ciphertext,
			EncryptedKey: wrappedKey,
			IV:           iv,
			Tag:          tag,
			EPK: &EphemeralPublicKey{
				Curve: "P-256",
				X:     base64.RawURLEncoding.EncodeToString(xBytes),
				Y:     base64.RawURLEncoding.EncodeToString(yBytes),
			},
		}

		// Using wrong key should fail
		_, err = DecryptWithWrappedKey(resource, wrongKey)
		assert.Error(t, err)
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("error constants are defined", func(t *testing.T) {
		assert.NotNil(t, ErrDecryptionFailed)
		assert.NotNil(t, ErrInvalidKey)
		assert.NotNil(t, ErrInvalidCiphertext)
		assert.NotNil(t, ErrInvalidFormat)

		assert.Equal(t, "decryption failed", ErrDecryptionFailed.Error())
		assert.Equal(t, "invalid decryption key", ErrInvalidKey.Error())
		assert.Equal(t, "invalid ciphertext", ErrInvalidCiphertext.Error())
		assert.Equal(t, "invalid encrypted resource format", ErrInvalidFormat.Error())
	})
}
