// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/ultravioletrs/cocos/internal/env"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	managergrpc "github.com/ultravioletrs/cocos/manager/api/grpc"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var _ managergrpc.Service = (*svc)(nil)

const (
	svcName     = "manager_test_server"
	defaultPort = "7001"
)

var (
	algoPath    = "./test/manual/algo/lin_reg.py"
	dataPath    = "./test/manual/data/iris.csv"
	attestedTLS = false
)

type svc struct {
	logger *slog.Logger
}

func (s *svc) Run(ipAdress string, reqChan chan *manager.ServerStreamMessage, auth credentials.AuthInfo) {
	s.logger.Debug(fmt.Sprintf("received who am on ip address %s", ipAdress))
	algo, err := os.ReadFile(algoPath)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to read algorithm file: %s", err))
		return
	}
	data, err := os.ReadFile(dataPath)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to read data file: %s", err))
		return
	}
	algoHash := sha3.Sum256(algo)
	dataHash := sha3.Sum256(data)
	reqChan <- &manager.ServerStreamMessage{
		Message: &manager.ServerStreamMessage_RunReq{
			RunReq: &manager.ComputationRunReq{
				Id:              "1",
				Name:            "sample computation",
				Description:     "sample descrption",
				Datasets:        []*manager.Dataset{{Id: "1", Provider: "provider1", Hash: dataHash[:]}},
				Algorithm:       &manager.Algorithm{Id: "1", Provider: "provider1", Hash: algoHash[:]},
				ResultConsumers: []string{"consumer1"},
				AgentConfig: &manager.AgentConfig{
					Port:     "7002",
					LogLevel: "debug",
				},
			},
		},
	}
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("usage: %s <data-path> <algo-path> <attested-tls-bool>", os.Args[0])
	}
	dataPath = os.Args[1]
	algoPath = os.Args[2]
	attestedTLSParam, err := strconv.ParseBool(os.Args[3])
	if err != nil {
		log.Fatalf("usage: %s <data-path> <algo-path> <attested-tls-bool>, <attested-tls-bool> must be a bool value", os.Args[0])
	}
	attestedTLS = attestedTLSParam

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
		manager.RegisterManagerServiceServer(srv, managergrpc.NewServer(incomingChan, &svc{logger: logger}))
	}
	grpcServerConfig := server.Config{Port: defaultPort}
	if err := env.Parse(&grpcServerConfig, env.Options{}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		return
	}

	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerAgentServiceServer, logger, nil)

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
