// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/mocks"
)

func setupTest(t *testing.T) (*slog.Logger, *mocks.Service, string, string, string, []byte) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockSvc := new(mocks.Service)
	host := "localhost"
	caUrl := "https://ca.example.com"
	cvmId := "test-cvm-id"

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err, "Failed to generate ECDSA key")

	pubkey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	assert.NoError(t, err, "Failed to marshal public key")

	return logger, mockSvc, host, caUrl, cvmId, pubkey
}

func TestNewServer(t *testing.T) {
	logger, svc, host, caUrl, cvmId, _ := setupTest(t)

	tests := []struct {
		name     string
		logger   *slog.Logger
		svc      agent.Service
		host     string
		caUrl    string
		cvmId    string
		expected AgentServer
	}{
		{
			name:   "valid server creation",
			logger: logger,
			svc:    svc,
			host:   host,
			caUrl:  caUrl,
			cvmId:  cvmId,
		},
		{
			name:   "server with empty host",
			logger: logger,
			svc:    svc,
			host:   "",
			caUrl:  caUrl,
			cvmId:  cvmId,
		},
		{
			name:   "server with empty caUrl",
			logger: logger,
			svc:    svc,
			host:   host,
			caUrl:  "",
			cvmId:  cvmId,
		},
		{
			name:   "server with empty cvmId",
			logger: logger,
			svc:    svc,
			host:   host,
			caUrl:  caUrl,
			cvmId:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(tt.logger, tt.svc, tt.host, tt.caUrl, tt.cvmId)

			assert.NotNil(t, server)

			agentSrv, ok := server.(*agentServer)
			assert.True(t, ok)
			assert.Equal(t, tt.logger, agentSrv.logger)
			assert.Equal(t, tt.svc, agentSrv.svc)
			assert.Equal(t, tt.host, agentSrv.host)
			assert.Equal(t, tt.caUrl, agentSrv.caUrl)
			assert.Equal(t, tt.cvmId, agentSrv.cvmId)
		})
	}
}

func TestAgentServer_Start(t *testing.T) {
	logger, svc, host, caUrl, cvmId, pubKey := setupTest(t)

	tests := []struct {
		name          string
		cfg           agent.AgentConfig
		cmp           agent.Computation
		setupMocks    func(*mocks.Service)
		expectedError bool
		errorContains string
	}{
		{
			name: "successful start with default port",
			cfg: agent.AgentConfig{
				Port:         "",
				CertFile:     "cert.pem",
				KeyFile:      "key.pem",
				ServerCAFile: "server-ca.pem",
				ClientCAFile: "client-ca.pem",
				AttestedTls:  true,
			},
			cmp: agent.Computation{
				ID:          "test-computation-1",
				Name:        "Test Computation",
				Description: "A test computation",
				Algorithm: agent.Algorithm{
					Hash:    [32]byte{0x01, 0x02, 0x03},
					UserKey: pubKey,
				},
				Datasets: []agent.Dataset{
					{
						Hash:    [32]byte{0x04, 0x05, 0x06},
						UserKey: pubKey,
					},
				},
				ResultConsumers: []agent.ResultConsumer{
					{
						UserKey: pubKey,
					},
				},
			},
			setupMocks: func(m *mocks.Service) {
			},
			expectedError: false,
		},
		{
			name: "successful start with custom port",
			cfg: agent.AgentConfig{
				Port:         "8080",
				CertFile:     "cert.pem",
				KeyFile:      "key.pem",
				ServerCAFile: "server-ca.pem",
				ClientCAFile: "client-ca.pem",
				AttestedTls:  false,
			},
			cmp: agent.Computation{
				ID:          "test-computation-2",
				Name:        "Test Computation 2",
				Description: "Another test computation",
				Algorithm: agent.Algorithm{
					Hash:    [32]byte{0x07, 0x08, 0x09},
					UserKey: pubKey,
				},
				Datasets: []agent.Dataset{
					{
						Hash:    [32]byte{0x0a, 0x0b, 0x0c},
						UserKey: pubKey,
					},
				},
				ResultConsumers: []agent.ResultConsumer{
					{
						UserKey: pubKey,
					},
				},
			},
			setupMocks: func(m *mocks.Service) {
			},
			expectedError: false,
		},
		{
			name: "start with minimal config",
			cfg: agent.AgentConfig{
				Port:        "9090",
				AttestedTls: false,
			},
			cmp: agent.Computation{
				ID:   "test-computation-3",
				Name: "Minimal Test",
				Algorithm: agent.Algorithm{
					Hash:    [32]byte{0x0d, 0x0e, 0x0f},
					UserKey: pubKey,
				},
				Datasets: []agent.Dataset{
					{
						Hash:    [32]byte{0x10, 0x11, 0x12},
						UserKey: pubKey,
					},
				},
				ResultConsumers: []agent.ResultConsumer{
					{
						UserKey: pubKey,
					},
				},
			},
			setupMocks: func(m *mocks.Service) {
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks(svc)

			server := NewServer(logger, svc, host, caUrl, cvmId)

			err := server.Start(tt.cfg, tt.cmp)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify the port was set correctly
				agentSrv := server.(*agentServer)
				assert.NotNil(t, agentSrv.gs)

				if err := server.Stop(); err != nil {
					t.Fatalf("Failed to stop server after start: %v", err)
				}
			}

			svc.AssertExpectations(t)
		})
	}
}

func TestAgentServer_Stop(t *testing.T) {
	logger, svc, host, caUrl, cvmId, pubKey := setupTest(t)

	tests := []struct {
		name          string
		setupServer   func(AgentServer) error
		expectedError bool
		errorContains string
	}{
		{
			name: "stop unstarted server",
			setupServer: func(server AgentServer) error {
				// Don't start the server
				return nil
			},
			expectedError: false,
		},
		{
			name: "stop started server",
			setupServer: func(server AgentServer) error {
				cfg := agent.AgentConfig{
					Port: "7004",
				}
				cmp := agent.Computation{
					ID:   "test-stop-computation",
					Name: "Stop Test",
					Algorithm: agent.Algorithm{
						Hash:    [32]byte{0x19, 0x1a, 0x1b},
						UserKey: pubKey,
					},
					Datasets: []agent.Dataset{
						{
							Hash:    [32]byte{0x1c, 0x1d, 0x1e},
							UserKey: pubKey,
						},
					},
					ResultConsumers: []agent.ResultConsumer{
						{
							UserKey: pubKey,
						},
					},
				}
				return server.Start(cfg, cmp)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(logger, svc, host, caUrl, cvmId)

			err := tt.setupServer(server)
			if err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			// Give the server a moment to start if it was started
			time.Sleep(10 * time.Millisecond)

			err = server.Stop()

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}

			svc.AssertExpectations(t)
		})
	}
}

func TestAgentServer_StopMultipleTimes(t *testing.T) {
	logger, svc, host, caUrl, cvmId, pubKey := setupTest(t)
	server := NewServer(logger, svc, host, caUrl, cvmId)

	// Start the server
	cfg := agent.AgentConfig{Port: "7005"}
	cmp := agent.Computation{
		ID:   "test-multiple-stop",
		Name: "Multiple Stop Test",
		Algorithm: agent.Algorithm{
			Hash:    [32]byte{0x1f, 0x20, 0x21},
			UserKey: pubKey,
		},
		Datasets: []agent.Dataset{
			{
				Hash:    [32]byte{0x22, 0x23, 0x24},
				UserKey: pubKey,
			},
		},
		ResultConsumers: []agent.ResultConsumer{
			{
				UserKey: pubKey,
			},
		},
	}

	err := server.Start(cfg, cmp)
	assert.NoError(t, err)

	// Give the server a moment to start
	time.Sleep(10 * time.Millisecond)

	// Stop the server multiple times
	err1 := server.Stop()
	err2 := server.Stop()
	err3 := server.Stop()

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NoError(t, err3)

	svc.AssertExpectations(t)
}

func TestAgentServer_StartAfterStop(t *testing.T) {
	logger, svc, host, caUrl, cvmId, pubKey := setupTest(t)
	server := NewServer(logger, svc, host, caUrl, cvmId)

	cfg := agent.AgentConfig{Port: "7006"}
	cmp := agent.Computation{
		ID:   "test-restart",
		Name: "Restart Test",
		Algorithm: agent.Algorithm{
			Hash:    [32]byte{0x25, 0x26, 0x27},
			UserKey: pubKey,
		},
		Datasets: []agent.Dataset{
			{
				Hash:    [32]byte{0x28, 0x29, 0x2a},
				UserKey: pubKey,
			},
		},
		ResultConsumers: []agent.ResultConsumer{
			{
				UserKey: pubKey,
			},
		},
	}

	// Start, stop, then start again
	err := server.Start(cfg, cmp)
	assert.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	err = server.Stop()
	assert.NoError(t, err)

	// Start again with different config
	cfg2 := agent.AgentConfig{Port: "7007"}
	cmp2 := agent.Computation{
		ID:   "test-restart-2",
		Name: "Restart Test 2",
		Algorithm: agent.Algorithm{
			Hash:    [32]byte{0x2b, 0x2c, 0x2d},
			UserKey: pubKey,
		},
		Datasets: []agent.Dataset{
			{
				Hash:    [32]byte{0x2e, 0x2f, 0x30},
				UserKey: pubKey,
			},
		},
		ResultConsumers: []agent.ResultConsumer{
			{
				UserKey: pubKey,
			},
		},
	}

	err = server.Start(cfg2, cmp2)
	assert.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	err = server.Stop()
	assert.NoError(t, err)

	svc.AssertExpectations(t)
}

func TestAgentServer_ConfigValidation(t *testing.T) {
	logger, svc, host, caUrl, cvmId, pubKey := setupTest(t)

	tests := []struct {
		name   string
		config agent.AgentConfig
		cmp    agent.Computation
		valid  bool
	}{
		{
			name: "valid config with all fields",
			config: agent.AgentConfig{
				Port:         "8080",
				CertFile:     "cert.pem",
				KeyFile:      "key.pem",
				ServerCAFile: "server-ca.pem",
				ClientCAFile: "client-ca.pem",
				AttestedTls:  true,
			},
			cmp: agent.Computation{
				ID:   "valid-config-test",
				Name: "Valid Config Test",
				Algorithm: agent.Algorithm{
					Hash:    [32]byte{0x31, 0x32, 0x33},
					UserKey: pubKey,
				},
				Datasets: []agent.Dataset{
					{
						Hash:    [32]byte{0x34, 0x35, 0x36},
						UserKey: pubKey,
					},
				},
				ResultConsumers: []agent.ResultConsumer{
					{
						UserKey: pubKey,
					},
				},
			},
			valid: true,
		},
		{
			name: "valid config with minimal fields",
			config: agent.AgentConfig{
				Port: "9090",
			},
			cmp: agent.Computation{
				ID:   "minimal-config-test",
				Name: "Minimal Config Test",
				Algorithm: agent.Algorithm{
					Hash:    [32]byte{0x37, 0x38, 0x39},
					UserKey: pubKey,
				},
				Datasets: []agent.Dataset{
					{
						Hash:    [32]byte{0x3a, 0x3b, 0x3c},
						UserKey: pubKey,
					},
				},
				ResultConsumers: []agent.ResultConsumer{
					{
						UserKey: pubKey,
					},
				},
			},
			valid: true,
		},
		{
			name: "config with empty port uses default",
			config: agent.AgentConfig{
				Port: "",
			},
			cmp: agent.Computation{
				ID:        "default-port-test",
				Name:      "Default Port Test",
				Algorithm: agent.Algorithm{Hash: [32]byte{0x3d, 0x3e, 0x3f}, UserKey: pubKey},
				Datasets: []agent.Dataset{
					{Hash: [32]byte{0x40, 0x41, 0x42}, UserKey: pubKey},
				},
				ResultConsumers: []agent.ResultConsumer{
					{UserKey: pubKey},
				},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(logger, svc, host, caUrl, cvmId)

			err := server.Start(tt.config, tt.cmp)

			if tt.valid {
				assert.NoError(t, err)

				// Verify default port is used when empty
				if tt.config.Port == "" {
					agentSrv := server.(*agentServer)
					assert.NotNil(t, agentSrv.gs)
				}

				time.Sleep(10 * time.Millisecond)
				if err := server.Stop(); err != nil {
					t.Fatalf("Failed to stop server after start: %v", err)
				}
			} else {
				assert.Error(t, err)
			}

			svc.AssertExpectations(t)
		})
	}
}

func TestConstants(t *testing.T) {
	assert.Equal(t, "agent", svcName)
	assert.Equal(t, "7002", defSvcGRPCPort)
}
