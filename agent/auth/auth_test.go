// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
	"google.golang.org/grpc/metadata"
)

func TestAuthenticateUser(t *testing.T) {
	resultConsumerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	dataProviderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	algorithmProviderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	resultConsumerPubKey, err := x509.MarshalPKIXPublicKey(&resultConsumerKey.PublicKey)
	require.NoError(t, err)

	dataProviderPubKey, err := x509.MarshalPKIXPublicKey(&dataProviderKey.PublicKey)
	require.NoError(t, err)

	algorithmProviderPubKey, err := x509.MarshalPKIXPublicKey(&algorithmProviderKey.PublicKey)
	require.NoError(t, err)

	manifest := agent.Computation{
		ResultConsumers: []agent.ResultConsumer{{UserKey: resultConsumerPubKey}},
		Datasets:        []agent.Dataset{{UserKey: dataProviderPubKey}},
		Algorithm:       agent.Algorithm{UserKey: algorithmProviderPubKey},
	}

	auth, err := New(manifest)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	testCases := []struct {
		name        string
		role        UserRole
		key         *rsa.PrivateKey
		expectedErr error
	}{
		{
			name:        "valid result consumer",
			role:        ConsumerRole,
			key:         resultConsumerKey,
			expectedErr: nil,
		},
		{
			name:        "valid data provider",
			role:        DataProviderRole,
			key:         dataProviderKey,
			expectedErr: nil,
		},
		{
			name:        "valid algorithm provider",
			role:        AlgorithmProviderRole,
			key:         algorithmProviderKey,
			expectedErr: nil,
		},
		{
			name:        "invalid role",
			role:        "invalid-role",
			key:         resultConsumerKey,
			expectedErr: ErrSignatureVerificationFailed,
		},
		{
			name:        "invalid key",
			role:        ConsumerRole,
			key:         dataProviderKey,
			expectedErr: ErrSignatureVerificationFailed,
		},
		{
			name:        "missing signature",
			role:        ConsumerRole,
			key:         resultConsumerKey,
			expectedErr: ErrInvalidMetadata,
		},
		{
			name:        "missing metadata",
			role:        ConsumerRole,
			key:         resultConsumerKey,
			expectedErr: ErrMissingMetadata,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signature, err := signRole(tc.role, tc.key)
			if err != nil {
				t.Fatalf("failed to sign role: %v", err)
			}

			ctx := context.Background()

			switch tc.name {
			case "missing signature":
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs())
			case "missing metadata":
			default:
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(SignatureMetadataKey, signature))
			}

			ctx, err = auth.AuthenticateUser(ctx, tc.role)
			assert.True(t, errors.Contains(err, tc.expectedErr), "expected error %v, got %v", tc.expectedErr, err)

			if err == nil {
				switch id, ok := agent.IndexFromContext(ctx); {
				case tc.role == ConsumerRole, tc.role == DataProviderRole:
					assert.True(t, ok, "expected index in context")
					assert.Equal(t, 0, id, "expected index 0 in context")
				default:
					assert.False(t, ok, "expected no index in context")
				}
			}
		})
	}
}

func signRole(role UserRole, key *rsa.PrivateKey) (string, error) {
	hash := sha256.Sum256([]byte(role))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}
