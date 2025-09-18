// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/mocks"
	"github.com/ultravioletrs/cocos/pkg/clients"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

type TestServer struct {
	agent.UnimplementedAgentServiceServer
	server     *grpc.Server
	health     *health.Server
	port       int
	listenAddr string
}

func NewTestServer() (*TestServer, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	addr := listener.Addr().(*net.TCPAddr)

	server := grpc.NewServer()
	healthServer := health.NewServer()

	ts := &TestServer{
		server:     server,
		health:     healthServer,
		port:       addr.Port,
		listenAddr: fmt.Sprintf("localhost:%d", addr.Port),
	}

	svc := new(mocks.Service)
	agent.RegisterAgentServiceServer(server, agentgrpc.NewServer(svc))
	grpchealth.RegisterHealthServer(server, healthServer)

	go func() {
		if err := server.Serve(listener); err != nil {
			fmt.Printf("Server exited with error: %v\n", err)
		}
	}()

	healthServer.SetServingStatus("agent", grpchealth.HealthCheckResponse_SERVING)

	return ts, nil
}

func (s *TestServer) Stop() {
	if s.server != nil {
		s.server.GracefulStop()
	}
}

func TestAgentClientIntegration(t *testing.T) {
	testServer, err := NewTestServer()
	require.NoError(t, err)
	defer testServer.Stop()

	time.Sleep(100 * time.Millisecond)

	tests := []struct {
		name          string
		serverRunning bool
		config        clients.AttestedClientConfig
		err           error
	}{
		{
			name:          "successful connection",
			serverRunning: true,
			config: clients.AttestedClientConfig{
				BaseConfig: clients.BaseConfig{
					URL:     testServer.listenAddr,
					Timeout: 1,
				},
			},
			err: nil,
		},
		{
			name:          "server not healthy",
			serverRunning: false,
			config: clients.AttestedClientConfig{
				BaseConfig: clients.BaseConfig{
					URL:     "",
					Timeout: 1,
				},
			},
			err: errors.New("failed to connect to grpc server"),
		},
		{
			name: "invalid config, missing AttestationPolicy with aTLS",
			config: clients.AttestedClientConfig{
				BaseConfig: clients.BaseConfig{
					URL:     testServer.listenAddr,
					Timeout: 1,
				},
				AttestedTLS: true,
			},
			err: errors.New("failed to stat attestation policy file"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			if !tt.serverRunning {
				testServer.health.SetServingStatus("agent", grpchealth.HealthCheckResponse_NOT_SERVING)
			} else {
				testServer.health.SetServingStatus("agent", grpchealth.HealthCheckResponse_SERVING)
			}

			client, agentClient, err := NewAgentClient(ctx, tt.config)
			assert.True(t, errors.Contains(err, tt.err))
			if err != nil {
				assert.Nil(t, client)
				assert.Nil(t, agentClient)
				return
			}

			require.NotNil(t, client)
			require.NotNil(t, agentClient)
			defer client.Close()
		})
	}
}
