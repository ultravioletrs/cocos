// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/ultravioletrs/cocos/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	UserMetadataKey      = "user-id"
	SignatureMetadataKey = "signature"
)

type Service struct {
	users map[string]struct {
		PublicKey *rsa.PublicKey
		Role      string
	}
}

func New(manifest agent.Computation) *Service {
	s := &Service{
		users: make(map[string]struct {
			PublicKey *rsa.PublicKey
			Role      string
		}),
	}

}

func (s *Service) AuthInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
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

		var m proto.Message

		if err := stream.RecvMsg(&m); err != nil {
			return err
		}

		isValid, err := verifySignature(m, signature, userInfo.PublicKey)
		if err != nil || !isValid {
			return status.Errorf(codes.Unauthenticated, "signature verification failed")
		}

		return handler(srv, stream)
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

func verifySignature(m proto.Message, signature string, publicKey *rsa.PublicKey) (bool, error) {
	marshalledmes, err := proto.Marshal(m)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(marshalledmes)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], []byte(signature)); err != nil {
		return false, err
	}
	return true, nil
}
