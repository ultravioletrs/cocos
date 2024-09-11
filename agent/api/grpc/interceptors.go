// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"

	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authInterceptor struct {
	auth auth.Authenticator
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *wrappedServerStream) Context() context.Context {
	return s.ctx
}

func NewAuthInterceptor(authSvc auth.Authenticator) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	ai := &authInterceptor{auth: authSvc}
	return ai.AuthUnaryInterceptor(), ai.AuthStreamInterceptor()
}

func (s *authInterceptor) AuthStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		switch info.FullMethod {
		case agent.AgentService_Algo_FullMethodName:
			if _, err := s.auth.AuthenticateUser(stream.Context(), auth.AlgorithmProviderRole); err != nil {
				return status.Errorf(codes.Unauthenticated, "%v", err.Error())
			}
			return handler(srv, stream)
		case agent.AgentService_Data_FullMethodName:
			ctx, err := s.auth.AuthenticateUser(stream.Context(), auth.DataProviderRole)
			if err != nil {
				return status.Errorf(codes.Unauthenticated, "%s", err.Error())
			}
			wrapped := &wrappedServerStream{ServerStream: stream, ctx: ctx}
			return handler(srv, wrapped)
		case agent.AgentService_Result_FullMethodName:
			ctx, err := s.auth.AuthenticateUser(stream.Context(), auth.ConsumerRole)
			if err != nil {
				return status.Errorf(codes.Unauthenticated, "%v", err.Error())
			}
			wrapped := &wrappedServerStream{ServerStream: stream, ctx: ctx}
			return handler(srv, wrapped)
		default:
			return handler(srv, stream)
		}
	}
}

func (s *authInterceptor) AuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		switch info.FullMethod {
		case agent.AgentService_Result_FullMethodName:
			ctx, err := s.auth.AuthenticateUser(ctx, auth.ConsumerRole)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "%v", err.Error())
			}
			return handler(ctx, req)
		default:
			return handler(ctx, req)
		}
	}
}
