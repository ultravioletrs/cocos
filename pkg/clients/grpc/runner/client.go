// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package runner

import (
	"context"
	"time"

	pb "github.com/ultravioletrs/cocos/agent/runner"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Client interface {
	Run(ctx context.Context, req *pb.RunRequest) (*pb.RunResponse, error)
	Stop(ctx context.Context, req *pb.StopRequest) (*emptypb.Empty, error)
	Close() error
}

type client struct {
	conn   *grpc.ClientConn
	client pb.ComputationRunnerClient
}

func NewClient(socketPath string) (Client, error) {
	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &client{
		conn:   conn,
		client: pb.NewComputationRunnerClient(conn),
	}, nil
}

func (c *client) Close() error {
	return c.conn.Close()
}

func (c *client) Run(ctx context.Context, req *pb.RunRequest) (*pb.RunResponse, error) {
	// Run might take long time, so we need unlimited timeout or rely on context cancellation
	return c.client.Run(ctx, req)
}

func (c *client) Stop(ctx context.Context, req *pb.StopRequest) (*emptypb.Empty, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.Stop(ctx, req)
}
