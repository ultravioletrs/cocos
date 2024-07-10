// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/auth"
	"github.com/ultravioletrs/cocos/agent/mocks"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestAuthUnaryInterceptor(t *testing.T) {
	authmock := new(mocks.Authenticator)
	tests := []struct {
		name       string
		authorized bool
		method     string
		role       auth.UserRole
		wantErr    bool
	}{
		{
			name:       "authorized result method",
			authorized: true,
			method:     agent.AgentService_Result_FullMethodName,
			role:       auth.ConsumerRole,
			wantErr:    false,
		},
		{
			name:       "unauthorized result method",
			authorized: false,
			method:     agent.AgentService_Result_FullMethodName,
			role:       auth.ConsumerRole,
			wantErr:    true,
		},
		{
			name:       "other method",
			authorized: false,
			method:     "OtherMethod",
			role:       auth.ConsumerRole,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.authorized {
			case true:
				mockCall := authmock.On("AuthenticateUser", context.Background(), tt.role).Return(context.Background(), nil)
				mockCall.Once()
			case false:
				mockCall := authmock.On("AuthenticateUser", context.Background(), tt.role).Return(context.Background(), auth.ErrMissingMetadata)
				mockCall.Once()
			}
			unaryInt, _ := NewAuthInterceptor(authmock)

			_, err := unaryInt(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: tt.method}, func(ctx context.Context, req interface{}) (interface{}, error) {
				return nil, nil
			})

			if tt.wantErr && err == nil {
				t.Errorf("expected error, got none")
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAuthStreamInterceptor(t *testing.T) {
	authmock := new(mocks.Authenticator)
	tests := []struct {
		name       string
		authorized bool
		method     string
		role       auth.UserRole
		wantErr    bool
	}{
		{
			name:       "authorized algo method",
			authorized: true,
			method:     agent.AgentService_Algo_FullMethodName,
			role:       auth.AlgorithmProviderRole,
			wantErr:    false,
		},
		{
			name:       "unauthorized algo method",
			authorized: false,
			method:     agent.AgentService_Algo_FullMethodName,
			role:       auth.AlgorithmProviderRole,
			wantErr:    true,
		},
		{
			name:       "authorized data method",
			authorized: true,
			method:     agent.AgentService_Data_FullMethodName,
			role:       auth.DataProviderRole,
			wantErr:    false,
		},
		{
			name:       "unauthorized data method",
			authorized: false,
			method:     agent.AgentService_Data_FullMethodName,
			role:       auth.DataProviderRole,
			wantErr:    true,
		},
		{
			name:       "other method",
			authorized: false,
			method:     "OtherMethod",
			role:       auth.DataProviderRole,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.authorized {
			case true:
				mockCall := authmock.On("AuthenticateUser", mock.Anything, tt.role).Return(context.Background(), nil)
				mockCall.Once()
			case false:
				mockCall := authmock.On("AuthenticateUser", mock.Anything, tt.role).Return(context.Background(), auth.ErrMissingMetadata)
				mockCall.Once()
			}
			_, streamInt := NewAuthInterceptor(authmock)

			err := streamInt(nil, &mockServerStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs())}, &grpc.StreamServerInfo{FullMethod: tt.method}, func(srv interface{}, stream grpc.ServerStream) error {
				return nil
			})

			if tt.wantErr && err == nil {
				t.Errorf("expected error, got none")
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}
