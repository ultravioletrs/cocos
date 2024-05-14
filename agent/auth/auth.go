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
	consumerRole          UserRole = "consumer"
	dataProviderRole      UserRole = "data-provider"
	algorithmProviderRole UserRole = "algorithm-provider"
)

var errNotRSAPublicKey = errors.New("not an RSA public key")

type Service struct {
	users map[string]struct {
		PublicKey *rsa.PublicKey
		Role      UserRole
	}
}

func New(manifest agent.Computation) (*Service, error) {
	s := &Service{
		users: make(map[string]struct {
			PublicKey *rsa.PublicKey
			Role      UserRole
		}),
	}
	for _, rc := range manifest.ResultConsumers {
		pubKey, err := x509.ParsePKIXPublicKey(rc.UserKey)
		if err != nil {
			return nil, err
		}
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errNotRSAPublicKey
		}
		s.users[rc.Consumer] = struct {
			PublicKey *rsa.PublicKey
			Role      UserRole
		}{
			PublicKey: rsaPubKey,
			Role:      consumerRole,
		}
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
		s.users[dp.Provider] = struct {
			PublicKey *rsa.PublicKey
			Role      UserRole
		}{
			PublicKey: rsaPubKey,
			Role:      dataProviderRole,
		}
	}
	pubKey, err := x509.ParsePKIXPublicKey(manifest.Algorithm.UserKey)
	if err != nil {
		return nil, err
	}
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errNotRSAPublicKey
	}
	s.users[manifest.Algorithm.Provider] = struct {
		PublicKey *rsa.PublicKey
		Role      UserRole
	}{
		PublicKey: rsaPubKey,
		Role:      algorithmProviderRole,
	}
	return s, nil
}

func (s *Service) AuthStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		switch info.FullMethod {
		case agent.AgentService_Algo_FullMethodName, agent.AgentService_Data_FullMethodName:
		default:
			return handler(srv, stream)
		}
		md, ok := metadata.FromIncomingContext(stream.Context())
		if !ok {
			return status.Errorf(codes.Unauthenticated, "missing metadata")
		}
		userID, signature, err := extractSignatureAndUserID(md)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "invalid metadata")
		}

		userInfo, ok := s.users[userID]
		if !ok {
			return status.Errorf(codes.Unauthenticated, "user not found")
		}

		isValid, err := verifySignature(userID, signature, userInfo.PublicKey)
		if err != nil || !isValid {
			return status.Errorf(codes.Unauthenticated, "signature verification failed")
		}

		return handler(srv, stream)
	}
}

func (s *Service) AuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		switch info.FullMethod {
		case agent.AgentService_Result_FullMethodName:
		default:
			return handler(ctx, req)
		}
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
		}
		userID, signature, err := extractSignatureAndUserID(md)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid metadata")
		}

		userInfo, ok := s.users[userID]
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "user not found")
		}

		isValid, err := verifySignature(userID, signature, userInfo.PublicKey)
		if err != nil || !isValid {
			return nil, status.Errorf(codes.Unauthenticated, "signature verification failed")
		}

		return handler(ctx, req)
	}
}

func extractSignatureAndUserID(md metadata.MD) (string, string, error) {
	userID := md.Get(UserMetadataKey)
	signature := md.Get(SignatureMetadataKey)
	if len(userID) != 1 || len(signature) != 1 {
		return "", "", status.Errorf(codes.Unauthenticated, "invalid metadata")
	}

	return userID[0], signature[0], nil
}

func verifySignature(userID, signature string, publicKey *rsa.PublicKey) (bool, error) {
	hash := sha256.Sum256([]byte(userID))
	sigByte, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigByte); err != nil {
		return false, err
	}
	return true, nil
}
