// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/ultravioletrs/cocos/internal/env"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	"github.com/ultravioletrs/cocos/manager"
	managergrpc "github.com/ultravioletrs/cocos/manager/api/grpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var _ managergrpc.Service = (*svc)(nil)

const (
	svcName     = "manager_test_server"
	defaultPort = "7001"
)

type svc struct {
	logger *slog.Logger
}

func (s *svc) Run(ipAdress string, reqChan chan *manager.ComputationRunReq) {
	s.logger.Debug(fmt.Sprintf("received who am on ip address %s", ipAdress))
	reqChan <- &manager.ComputationRunReq{
		Id:              "1",
		Name:            "sample computation",
		Description:     "sample descrption",
		Datasets:        []*manager.Dataset{{Id: "1", Provider: "provider1"}},
		Algorithms:      []*manager.Algorithm{{Id: "1", Provider: "provider1"}},
		ResultConsumers: []string{"consumer1"},
		AgentConfig: &manager.AgentConfig{
			Port:     "7002",
			LogLevel: "debug",
		},
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)
	incomingChan := make(chan *manager.ClientStreamMessage)

	logger, err := mglog.New(os.Stdout, "debug")
	if err != nil {
		log.Fatalf(err.Error())
	}

	go func() {
		for incoming := range incomingChan {
			switch incoming.Message.(type) {
			case *manager.ClientStreamMessage_Whoami:
				fmt.Println("received whoamI")
			case *manager.ClientStreamMessage_RunRes:
				fmt.Println("received runRes")
			case *manager.ClientStreamMessage_AgentEvent:
				fmt.Println("received agent event")
			case *manager.ClientStreamMessage_AgentLog:
				fmt.Println("received agent log")
			}
			fmt.Println(incoming.Message)
		}
	}()

	registerAgentServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		manager.RegisterManagerServiceServer(srv, managergrpc.NewServer(ctx, incomingChan, &svc{logger: logger}))
	}
	grpcServerConfig := server.Config{Port: defaultPort}
	if err := env.Parse(&grpcServerConfig, env.Options{}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		return
	}

	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerAgentServiceServer, logger)

	g.Go(func() error {
		return gs.Start()
	})

	g.Go(func() error {
		return server.StopHandler(ctx, cancel, logger, svcName, gs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
	}
}
