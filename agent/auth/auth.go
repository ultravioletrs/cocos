// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto"
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
	errNotRSAPublicKey             = errors.New("not an RSA public key")
	ErrMissingMetadata             = errors.New("missing metadata")
	ErrInvalidMetadata             = errors.New("invalid metadata")
	ErrSignatureVerificationFailed = errors.New("signature verification failed")
)

//go:generate mockery --name Authenticator --output=../mocks --filename auth.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type Authenticator interface {
	AuthenticateUser(ctx context.Context, role UserRole) (context.Context, error)
}

type service struct {
	resultConsumers   []*rsa.PublicKey
	datasetProviders  []*rsa.PublicKey
	algorithmProvider *rsa.PublicKey
}

func New(manifest agent.Computation) (Authenticator, error) {
	s := &service{}
	for _, rc := range manifest.ResultConsumers {
		pubKey, err := x509.ParsePKIXPublicKey(rc.UserKey)
		if err != nil {
			return nil, err
		}

		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errNotRSAPublicKey
		}

		s.resultConsumers = append(s.resultConsumers, rsaPubKey)
	}

	for _, dp := range manifest.Datasets {
		pubKey, err := x509.ParsePKIXPublicKey(dp.UserKey)
		if err != nil {
			return nil, err
		}

		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errNotRSAPublicKey
		}

		s.datasetProviders = append(s.datasetProviders, rsaPubKey)
	}

	pubKey, err := x509.ParsePKIXPublicKey(manifest.Algorithm.UserKey)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errNotRSAPublicKey
	}

	s.algorithmProvider = rsaPubKey
	return s, nil
}

func extractSignature(md metadata.MD) (string, error) {
	signature := md.Get(SignatureMetadataKey)
	if len(signature) != 1 {
		return "", status.Errorf(codes.Unauthenticated, "invalid metadata")
	}

	return signature[0], nil
}

func verifySignature(role UserRole, signature string, publicKey *rsa.PublicKey) error {
	hash := sha256.Sum256([]byte(role))
	sigByte, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigByte); err != nil {
		return err
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
		for i, dp := range s.datasetProviders {
			if err := verifySignature(role, signature, dp); err == nil {
				return agent.IndexToContext(ctx, i), nil
			}
		}
	case AlgorithmProviderRole:
		if err := verifySignature(role, signature, s.algorithmProvider); err == nil {
			return ctx, nil
		}
	}

	return ctx, ErrSignatureVerificationFailed
}
