package grpc

import (
	"github.com/ultravioletrs/manager/manager"
	managerapi "github.com/ultravioletrs/manager/manager/api/grpc"
)

// NewClient creates new manager gRPC client instance.
func NewClient(cfg Config) (Client, manager.ManagerServiceClient, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, managerapi.NewClient(client.Connection(), cfg.Timeout), nil
}
