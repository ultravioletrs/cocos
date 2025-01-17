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
	"github.com/ultravioletrs/cocos/agent/cvms"
	cvmgrpc "github.com/ultravioletrs/cocos/agent/cvms/api/grpc"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var _ cvmgrpc.Service = (*svc)(nil)

const (
	svcName     = "computations_test_server"
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

func (s *svc) Run(ctx context.Context, ipAddress string, sendMessage cvmgrpc.SendFunc, authInfo credentials.AuthInfo) {
	s.logger.Debug(fmt.Sprintf("received who am on ip address %s", ipAddress))

	pubKey, err := os.ReadFile(pubKeyFile)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to read public key file: %s", err))
		return
	}
	pubPem, _ := pem.Decode(pubKey)

	var datasets []*cvms.Dataset
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

		datasets = append(datasets, &cvms.Dataset{Hash: dataHash[:], UserKey: pubPem.Bytes})
	}

	algoHash, err := internal.Checksum(algoPath)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to calculate checksum: %s", err))
		return
	}

	if err := sendMessage(&cvms.ServerStreamMessage{
		Message: &cvms.ServerStreamMessage_RunReq{
			RunReq: &cvms.ComputationRunReq{
				Id:              "1",
				Name:            "sample computation",
				Description:     "sample descrption",
				Datasets:        datasets,
				Algorithm:       &cvms.Algorithm{Hash: algoHash[:], UserKey: pubPem.Bytes},
				ResultConsumers: []*cvms.ResultConsumer{{UserKey: pubPem.Bytes}},
				AgentConfig: &cvms.AgentConfig{
					Port:        "7002",
					LogLevel:    "debug",
					AttestedTls: attestedTLS,
				},
			},
		},
	}); err != nil {
		s.logger.Error(fmt.Sprintf("failed to send run request: %s", err))
		return
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
	incomingChan := make(chan *cvms.ClientStreamMessage)

	logger, err := mglog.New(os.Stdout, "debug")
	if err != nil {
		log.Fatal(err.Error())
	}

	go func() {
		for incoming := range incomingChan {
			fmt.Println(incoming.Message)
		}
	}()

	registerAgentServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		cvms.RegisterServiceServer(srv, cvmgrpc.NewServer(incomingChan, &svc{logger: logger}))
	}
	grpcServerConfig := server.ServerConfig{
		BaseConfig: server.BaseConfig{
			Port: defaultPort,
		},
	}
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
