// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/caarlos0/env/v11"
	"github.com/ultravioletrs/cocos/agent/cvms"
	cvmsgrpc "github.com/ultravioletrs/cocos/agent/cvms/api/grpc"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var _ cvmsgrpc.Service = (*svc)(nil)

const (
	svcName     = "cvms_test_server"
	defaultPort = "7001"
)

var (
	algoPath          string
	dataPathString    string
	dataPaths         []string
	attestedTLSString string
	attestedTLS       bool
	pubKeyFile        string
	caUrl             string
	cvmId             string
	clientCAFile      string
)

type svc struct {
	logger *slog.Logger
}

func (s *svc) Run(ctx context.Context, ipAddress string, sendMessage cvmsgrpc.SendFunc, authInfo credentials.AuthInfo) {
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
					Port:         "7002",
					AttestedTls:  attestedTLS,
					ClientCaFile: clientCAFile,
				},
			},
		},
	}); err != nil {
		s.logger.Error(fmt.Sprintf("failed to send run request: %s", err))
		return
	}
}

func main() {
	flagSet := flag.NewFlagSet("tests/cvms/main.go", flag.ContinueOnError)
	flagSet.StringVar(&algoPath, "algo-path", "", "Path to the algorithm")
	flagSet.StringVar(&pubKeyFile, "public-key-path", "", "Path to the public key file")
	flagSet.StringVar(&attestedTLSString, "attested-tls-bool", "", "Should aTLS be used, must be 'true' or 'false'")
	flagSet.StringVar(&dataPathString, "data-paths", "", "Paths to data sources, list of string separated with commas")
	flagSet.StringVar(&caUrl, "ca-url", "", "URL for certificate authority, must be specified if aTLS is used")
	flagSet.StringVar(&cvmId, "cvm-id", "", "UUID for a CVM, must be specified if aTLS is used")
	flagSet.StringVar(&clientCAFile, "client-ca-file", "", "Client CA root certificate file path")

	flagSetParseError := flagSet.Parse(os.Args[1:])
	if flagSetParseError != nil {
		log.Fatalf("Error parsing flagas: %v", flagSetParseError)
	}

	parsingError := !flagSet.Parsed()
	var parsingErrorString strings.Builder

	parsingErrorString.WriteString("\n")

	if algoPath == "" {
		parsingErrorString.WriteString("Algorithm path is required\n")
		parsingError = true
	}

	if pubKeyFile == "" {
		parsingErrorString.WriteString("Public key path is required\n")
		parsingError = true
	}

	attestedTLSBoolValue, err := strconv.ParseBool(attestedTLSString)
	if err != nil {
		parsingErrorString.WriteString("Attested TLS flag is required and it must be a boolean value\n")
		parsingError = true
		attestedTLS = false
	} else {
		attestedTLS = attestedTLSBoolValue
	}

	if dataPathString == "" {
		parsingErrorString.WriteString("Date source paths are required\n")
		parsingError = true
	} else {
		dataPaths = strings.Split(dataPathString, ",")
	}

	if err == nil && caUrl != "" && !attestedTLS {
		parsingErrorString.WriteString("CA URL is only available with attested TLS\n")
		parsingError = true
	}

	if err == nil && cvmId != "" && !attestedTLS {
		parsingErrorString.WriteString("CVM UUID is only available with attested TLS\n")
		parsingError = true
	}

	if parsingError {
		parsingErrorString.WriteString("Usage :\n")
		flagSet.SetOutput(&parsingErrorString)
		flagSet.PrintDefaults()
		log.Fatal(parsingErrorString.String())
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
		cvms.RegisterServiceServer(srv, cvmsgrpc.NewServer(incomingChan, &svc{logger: logger}))
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

	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerAgentServiceServer, logger, nil, caUrl, cvmId)

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
