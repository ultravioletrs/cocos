package manager

import (
	"github.com/ultravioletrs/cocos-ai/pkg/clients/grpc"
	"github.com/ultravioletrs/manager/manager"
	managerapi "github.com/ultravioletrs/manager/manager/api/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewManagerClient(cfg grpc.Config) (grpc.Client, manager.ManagerServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, managerapi.NewClient(client.Connection(), cfg.Timeout), nil
}
