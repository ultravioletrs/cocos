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

	mglog "github.com/absmach/supermq/logger"
	"github.com/caarlos0/env/v11"
	"github.com/ultravioletrs/cocos/agent/cvms"
	cvmsgrpc "github.com/ultravioletrs/cocos/agent/cvms/api/grpc"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/pkg/server"
	grpcserver "github.com/ultravioletrs/cocos/pkg/server/grpc"
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
	clientCAFile      string
	// Remote resource configuration
	kbsURL              string
	algoSourceURL       string
	algoKBSResourcePath string
	datasetSourceURLs   string
	datasetKBSPaths     string
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

	// Build datasets
	var datasets []*cvms.Dataset

	// Check if using remote datasets
	var datasetURLs []string
	var datasetKBSPathsList []string
	if datasetSourceURLs != "" {
		datasetURLs = strings.Split(datasetSourceURLs, ",")
	}
	if datasetKBSPaths != "" {
		datasetKBSPathsList = strings.Split(datasetKBSPaths, ",")
	}

	if len(datasetURLs) > 0 && len(datasetKBSPathsList) > 0 {
		// Remote datasets mode
		if len(datasetURLs) != len(datasetKBSPathsList) {
			s.logger.Error("dataset source URLs and KBS paths must have the same count")
			return
		}

		for i := 0; i < len(datasetURLs); i++ {
			// For remote datasets, hash should be of the decrypted data
			// Using placeholder for now - in production, provide actual hash
			var dataHash [32]byte

			datasets = append(datasets, &cvms.Dataset{
				Hash:     dataHash[:],
				UserKey:  pubPem.Bytes,
				Filename: fmt.Sprintf("dataset_%d.csv", i),
				Source: &cvms.Source{
					Url:             datasetURLs[i],
					KbsResourcePath: datasetKBSPathsList[i],
				},
			})
		}
	} else {
		// Direct upload mode - use local files
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
	}

	// Build algorithm
	var algorithm *cvms.Algorithm
	if algoSourceURL != "" && algoKBSResourcePath != "" {
		// Remote algorithm mode
		var algoHash [32]byte
		// For remote algorithm, hash should be of the decrypted data
		// Using placeholder for now - in production, provide actual hash
		algorithm = &cvms.Algorithm{
			Hash:    algoHash[:],
			UserKey: pubPem.Bytes,
			Source: &cvms.Source{
				Url:             algoSourceURL,
				KbsResourcePath: algoKBSResourcePath,
			},
		}
	} else {
		// Direct upload mode - use local file
		if algoPath == "" {
			s.logger.Error("algorithm path is required when not using remote source")
			return
		}
		algoHash, err := internal.Checksum(algoPath)
		if err != nil {
			s.logger.Error(fmt.Sprintf("failed to calculate checksum: %s", err))
			return
		}
		algorithm = &cvms.Algorithm{Hash: algoHash[:], UserKey: pubPem.Bytes}
	}

	// Build KBS config
	var kbsConfig *cvms.KBSConfig
	if kbsURL != "" {
		kbsConfig = &cvms.KBSConfig{
			Url:     kbsURL,
			Enabled: true,
		}
	}

	s.logger.Debug("sending computation run request")
	if err := sendMessage(&cvms.ServerStreamMessage{
		Message: &cvms.ServerStreamMessage_RunReq{
			RunReq: &cvms.ComputationRunReq{
				Id:              "1",
				Name:            "sample computation",
				Description:     "sample descrption",
				Datasets:        datasets,
				Algorithm:       algorithm,
				ResultConsumers: []*cvms.ResultConsumer{{UserKey: pubPem.Bytes}},
				AgentConfig: &cvms.AgentConfig{
					Port:         "7002",
					AttestedTls:  attestedTLS,
					ClientCaFile: clientCAFile,
				},
				Kbs: kbsConfig,
			},
		},
	}); err != nil {
		s.logger.Error(fmt.Sprintf("failed to send run request: %s", err))
		return
	}
	s.logger.Info("computation run request sent successfully")

	// Keep the connection alive
	<-ctx.Done()
	s.logger.Info("connection closed")
}

func main() {
	flagSet := flag.NewFlagSet("tests/cvms/main.go", flag.ContinueOnError)
	flagSet.StringVar(&algoPath, "algo-path", "", "Path to the algorithm (for direct upload mode)")
	flagSet.StringVar(&pubKeyFile, "public-key-path", "", "Path to the public key file")
	flagSet.StringVar(&attestedTLSString, "attested-tls-bool", "", "Should aTLS be used, must be 'true' or 'false'")
	flagSet.StringVar(&dataPathString, "data-paths", "", "Paths to data sources, list of string separated with commas (for direct upload mode)")
	flagSet.StringVar(&clientCAFile, "client-ca-file", "", "Client CA root certificate file path")
	// Remote resource flags
	flagSet.StringVar(&kbsURL, "kbs-url", "", "KBS endpoint URL (e.g., 'http://localhost:8080')")
	flagSet.StringVar(&algoSourceURL, "algo-source-url", "", "Algorithm source URL (s3://bucket/key or https://...)")
	flagSet.StringVar(&algoKBSResourcePath, "algo-kbs-path", "", "Algorithm KBS resource path (e.g., 'default/key/algo-key')")
	flagSet.StringVar(&datasetSourceURLs, "dataset-source-urls", "", "Dataset source URLs, comma-separated")
	flagSet.StringVar(&datasetKBSPaths, "dataset-kbs-paths", "", "Dataset KBS resource paths, comma-separated")

	flagSetParseError := flagSet.Parse(os.Args[1:])
	if flagSetParseError != nil {
		log.Fatalf("Error parsing flags: %v", flagSetParseError)
	}

	parsingError := !flagSet.Parsed()
	var parsingErrorString strings.Builder

	parsingErrorString.WriteString("\n")

	// Validate that either algo-path OR (algo-source-url AND algo-kbs-path) is provided
	if algoPath == "" && (algoSourceURL == "" || algoKBSResourcePath == "") {
		parsingErrorString.WriteString("Either algo-path OR (algo-source-url AND algo-kbs-path) is required\n")
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

	if dataPathString != "" {
		dataPaths = strings.Split(dataPathString, ",")
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
		Config: server.Config{
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
