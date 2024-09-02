// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/caarlos0/env/v11"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	managergrpc "github.com/ultravioletrs/cocos/manager/api/grpc"
	"github.com/ultravioletrs/cocos/pkg/manager"
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
	dataPaths   []string
	attestedTLS = false
	pubKeyFile  string
)

type svc struct {
	logger *slog.Logger
}

func (s *svc) Run(ipAdress string, reqChan chan *manager.ServerStreamMessage, auth credentials.AuthInfo) {
	s.logger.Debug(fmt.Sprintf("received who am on ip address %s", ipAdress))

	pubKey, err := os.ReadFile(pubKeyFile)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to read public key file: %s", err))
		return
	}
	pubPem, _ := pem.Decode(pubKey)

	var datasets []*manager.Dataset
	for _, dataPath := range dataPaths {
		if _, err := os.Stat(dataPath); os.IsNotExist(err) {
			s.logger.Error(fmt.Sprintf("data file does not exist: %s", dataPath))
			return
		}
		dataHash, err := internal.Checksum(dataPath)
		if err != nil {
			s.logger.Error(fmt.Sprintf("failed to calculate checksum: %s", err))
			return
		}

		datasets = append(datasets, &manager.Dataset{Hash: dataHash[:], UserKey: pubPem.Bytes})
	}

	algoHash, err := internal.Checksum(algoPath)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to calculate checksum: %s", err))
		return
	}

	reqChan <- &manager.ServerStreamMessage{
		Message: &manager.ServerStreamMessage_RunReq{
			RunReq: &manager.ComputationRunReq{
				Id:              "1",
				Name:            "sample computation",
				Description:     "sample descrption",
				Datasets:        datasets,
				Algorithm:       &manager.Algorithm{Hash: algoHash[:], UserKey: pubPem.Bytes},
				ResultConsumers: []*manager.ResultConsumer{{UserKey: pubPem.Bytes}},
				AgentConfig: &manager.AgentConfig{
					Port:        "7002",
					LogLevel:    "debug",
					AttestedTls: attestedTLS,
				},
			},
		},
	}
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("usage: %s <algo-path> <public-key-path> <attested-tls-bool> <data-paths>", os.Args[0])
	}
	algoPath = os.Args[1]
	pubKeyFile = os.Args[2]
	attestedTLSParam, err := strconv.ParseBool(os.Args[3])
	if err != nil {
		log.Fatalf("usage: %s <algo-path> <public-key-path> <attested-tls-bool> <data-paths>, <attested-tls-bool> must be a bool value", os.Args[0])
	}
	attestedTLS = attestedTLSParam

	for i := 4; i < len(os.Args); i++ {
		dataPaths = append(dataPaths, os.Args[i])
	}

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
			case *manager.ClientStreamMessage_BackendInfo:
				fmt.Println("received backend info measurement request")
			}
			fmt.Println(incoming.Message)
		}
	}()

	registerAgentServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		manager.RegisterManagerServiceServer(srv, managergrpc.NewServer(incomingChan, &svc{logger: logger}))
	}
	grpcServerConfig := server.Config{Port: defaultPort}
	if err := env.ParseWithOptions(&grpcServerConfig, env.Options{}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		return
	}

	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerAgentServiceServer, logger, nil, nil)

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
