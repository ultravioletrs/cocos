// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

var ErrAgentServiceUnavailable = errors.New("agent service is unavailable")

// NewAgentClient creates new agent gRPC client instance.
func NewAgentClient(ctx context.Context, cfg grpc.AgentClientConfig) (grpc.Client, agent.AgentServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	if client.Secure() != grpc.WithMATLS && client.Secure() != grpc.WithTLS {
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
