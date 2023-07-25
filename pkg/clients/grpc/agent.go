package grpc

import (
	"github.com/opentracing/opentracing-go"
	"github.com/ultravioletrs/agent/agent"
	agentapi "github.com/ultravioletrs/agent/agent/api/grpc"
)

// NewClient creates new agent gRPC client instance.
func NewClient(cfg Config) (Client, agent.AgentServiceClient, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, agentapi.NewClient(opentracing.NoopTracer{}, client.Connection(), cfg.Timeout), nil
}
