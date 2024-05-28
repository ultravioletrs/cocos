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
	"errors"

	"github.com/ultravioletrs/cocos/agent"
	"google.golang.org/grpc"
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

var errNotRSAPublicKey = errors.New("not an RSA public key")

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *wrappedServerStream) Context() context.Context {
	return s.ctx
}

type Service struct {
	resultConsumers   []*rsa.PublicKey
	datasetProviders  []*rsa.PublicKey
	algorithmProvider *rsa.PublicKey
}

func New(manifest agent.Computation) (*Service, error) {
	s := &Service{}
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

func (s *Service) AuthStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		switch info.FullMethod {
		case agent.AgentService_Algo_FullMethodName:
			md, ok := metadata.FromIncomingContext(stream.Context())
			if !ok {
				return status.Errorf(codes.Unauthenticated, "missing metadata")
			}
			signature, err := extractSignature(md)
			if err != nil {
				return status.Errorf(codes.Unauthenticated, "invalid metadata")
			}
			isValid, err := verifySignature(AlgorithmProviderRole, signature, s.algorithmProvider)
			if err != nil || !isValid {
				return status.Errorf(codes.Unauthenticated, "signature verification failed")
			}
		case agent.AgentService_Data_FullMethodName:
			md, ok := metadata.FromIncomingContext(stream.Context())
			if !ok {
				return status.Errorf(codes.Unauthenticated, "missing metadata")
			}
			signature, err := extractSignature(md)
			if err != nil {
				return status.Errorf(codes.Unauthenticated, "invalid metadata")
			}
			for index, dp := range s.datasetProviders {
				isValid, err := verifySignature(DataProviderRole, signature, dp)
				if err == nil || isValid {
					ctx := agent.IndexToContext(stream.Context(), index)
					wrapped := &wrappedServerStream{ServerStream: stream, ctx: ctx}
					return handler(srv, wrapped)
				}
			}
			return status.Errorf(codes.Unauthenticated, "signature verification failed")
		default:
			return handler(srv, stream)
		}
		return handler(srv, stream)
	}
}

func (s *Service) AuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		switch info.FullMethod {
		case agent.AgentService_Result_FullMethodName:
			md, ok := metadata.FromIncomingContext(ctx)
			if !ok {
				return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
			}
			signature, err := extractSignature(md)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "invalid metadata")
			}
			for index, rc := range s.resultConsumers {
				isValid, err := verifySignature(ConsumerRole, signature, rc)
				if err == nil || isValid {
					ctx := agent.IndexToContext(ctx, index)
					return handler(ctx, req)
				}
			}
			return nil, status.Errorf(codes.Unauthenticated, "signature verification failed")
		default:
			return handler(ctx, req)
		}
	}
}

func extractSignature(md metadata.MD) (string, error) {
	signature := md.Get(SignatureMetadataKey)
	if len(signature) != 1 {
		return "", status.Errorf(codes.Unauthenticated, "invalid metadata")
	}

	return signature[0], nil
}

func verifySignature(role UserRole, signature string, publicKey *rsa.PublicKey) (bool, error) {
	hash := sha256.Sum256([]byte(role))
	sigByte, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigByte); err != nil {
		return false, err
	}
	return true, nil
}
