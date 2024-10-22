package agent

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/mocks"
	pkggrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

// TestServer represents our test gRPC server
type TestServer struct {
	agent.UnimplementedAgentServiceServer
	server     *grpc.Server
	health     *health.Server
	port       int
	listenAddr string
}

// NewTestServer creates a new test server instance
func NewTestServer() (*TestServer, error) {
	// Find an available port
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	// Get the chosen port
	addr := listener.Addr().(*net.TCPAddr)

	// Create a new gRPC server
	server := grpc.NewServer()
	healthServer := health.NewServer()

	ts := &TestServer{
		server:     server,
		health:     healthServer,
		port:       addr.Port,
		listenAddr: fmt.Sprintf("localhost:%d", addr.Port),
	}

	svc := new(mocks.Service)
	// Register services
	agent.RegisterAgentServiceServer(server, agentgrpc.NewServer(svc))
	grpchealth.RegisterHealthServer(server, healthServer)

	// Start server
	go func() {
		if err := server.Serve(listener); err != nil {
			fmt.Printf("Server exited with error: %v\n", err)
		}
	}()

	// Set status to serving
	healthServer.SetServingStatus("agent", grpchealth.HealthCheckResponse_SERVING)

	return ts, nil
}

// Stop stops the test server
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
		err           error
	}{
		{
			name:          "successful connection",
			serverRunning: true,
			err:           nil,
		},
		{
			name:          "server not healthy",
			serverRunning: false,
			err:           ErrAgentServiceUnavailable,
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

			cfg := pkggrpc.Config{
				URL:     testServer.listenAddr,
				Timeout: 1,
			}

			if !tt.serverRunning {
				cfg.URL = ""
			}

			client, agentClient, err := NewAgentClient(ctx, cfg)
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
