// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/ultravioletrs/cocos/agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type UserRole string

const (
	UserMetadataKey                = "user-id"
	SignatureMetadataKey           = "signature"
	ConsumerRole          UserRole = "consumer"
	DataProviderRole      UserRole = "data-provider"
	AlgorithmProviderRole UserRole = "algorithm-provider"
)

var (
	ErrMissingMetadata             = errors.New("missing metadata")
	ErrInvalidMetadata             = errors.New("invalid metadata")
	ErrSignatureVerificationFailed = errors.New("signature verification failed")
)

//go:generate mockery --name Authenticator --output=../mocks --filename auth.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type Authenticator interface {
	AuthenticateUser(ctx context.Context, role UserRole) (context.Context, error)
}

type service struct {
	resultConsumers   []interface{}
	datasetProviders  []interface{}
	algorithmProvider interface{}
}

func New(manifest agent.Computation) (Authenticator, error) {
	s := &service{}
	for _, rc := range manifest.ResultConsumers {
		pubKey, err := x509.ParsePKIXPublicKey(rc.UserKey)
		if err != nil {
			return nil, err
		}

		pKey, err := decodePublicKey(pubKey)
		if err != nil {
			return nil, err
		}

		s.resultConsumers = append(s.resultConsumers, pKey)
	}

	for _, dp := range manifest.Datasets {
		pubKey, err := x509.ParsePKIXPublicKey(dp.UserKey)
		if err != nil {
			return nil, err
		}

		pKey, err := decodePublicKey(pubKey)
		if err != nil {
			return nil, err
		}

		s.datasetProviders = append(s.datasetProviders, pKey)
	}

	pubKey, err := x509.ParsePKIXPublicKey(manifest.Algorithm.UserKey)
	if err != nil {
		return nil, err
	}

	pKey, err := decodePublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	s.algorithmProvider = pKey
	return s, nil
}

func extractSignature(md metadata.MD) (string, error) {
	signature := md.Get(SignatureMetadataKey)
	if len(signature) != 1 {
		return "", status.Errorf(codes.Unauthenticated, "invalid metadata")
	}

	return signature[0], nil
}

func verifySignature(role UserRole, signature string, publicKey any) error {
	hash := sha256.Sum256([]byte(role))
	sigByte, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	var ok bool

	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		if err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigByte); err != nil {
			return err
		}
		return nil
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(publicKey, hash[:], sigByte)
	case ed25519.PublicKey:
		ok = ed25519.Verify(publicKey, []byte(role), sigByte)
	}

	if !ok {
		return ErrSignatureVerificationFailed
	}

	return nil
}

func (s *service) AuthenticateUser(ctx context.Context, role UserRole) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrMissingMetadata
	}
	signature, err := extractSignature(md)
	if err != nil {
		return nil, errors.Wrap(err, ErrInvalidMetadata)
	}

	switch role {
	case ConsumerRole:
		for i, rc := range s.resultConsumers {
			if err := verifySignature(role, signature, rc); err == nil {
				return agent.IndexToContext(ctx, i), nil
			}
		}
	case DataProviderRole:
		for _, dp := range s.datasetProviders {
			if err := verifySignature(role, signature, dp); err == nil {
				return ctx, nil
			}
		}
	case AlgorithmProviderRole:
		if err := verifySignature(role, signature, s.algorithmProvider); err == nil {
			return ctx, nil
		}
	}

	return ctx, ErrSignatureVerificationFailed
}

func decodePublicKey(key any) (pubKey any, err error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		return key, nil
	case ed25519.PublicKey:
		return key, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}
