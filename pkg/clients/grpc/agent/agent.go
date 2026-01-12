// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/clients"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	"github.com/ultravioletrs/cocos/pkg/tls"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

var ErrAgentServiceUnavailable = errors.New("agent service is unavailable")

// NewAgentClient creates new agent gRPC client instance.
func NewAgentClient(ctx context.Context, cfg clients.AttestedClientConfig) (grpc.Client, agent.AgentServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	if client.Secure() != tls.WithMATLS.String() && client.Secure() != tls.WithATLS.String() && client.Secure() != tls.WithTLS.String() {
		health := grpchealth.NewHealthClient(client.Connection())
		resp, err := health.Check(ctx, &grpchealth.HealthCheckRequest{
			Service: "agent",
		})

		if err != nil || resp.GetStatus() != grpchealth.HealthCheckResponse_SERVING {
			return nil, nil, errors.Wrap(err, ErrAgentServiceUnavailable)
		}
	}

	return client, agent.NewAgentServiceClient(client.Connection()), nil
}
