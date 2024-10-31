// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/prometheus"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/api"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/auth"
	"github.com/ultravioletrs/cocos/agent/events"
	"github.com/ultravioletrs/cocos/agent/quoteprovider"
	agentlogger "github.com/ultravioletrs/cocos/internal/logger"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	ackvsock "github.com/ultravioletrs/cocos/internal/vsock"
	managerevents "github.com/ultravioletrs/cocos/manager/events"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName        = "agent"
	defSvcGRPCPort = "7002"
	retryInterval  = 5 * time.Second
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	cfg, err := readConfig()
	if err != nil {
		log.Fatalf("failed to read agent configuration from vsock %s", err.Error())
	}

	conn, err := dialVsock()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	ackConn := ackvsock.NewAckWriter(conn)

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.AgentConfig.LogLevel)); err != nil {
		log.Println(err)
		exitCode = 1
		return
	}

	handler := agentlogger.NewProtoHandler(ackConn, &slog.HandlerOptions{Level: level}, cfg.ID)
	logger := slog.New(handler)

	eventSvc, err := events.New(svcName, cfg.ID, ackConn)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create events service %s", err.Error()))
		exitCode = 1
		return
	}

	qp, err := quoteprovider.GetQuoteProvider()
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create quote provider %s", err.Error()))
		exitCode = 1
		return
	}

	if err := verifyManifest(cfg, qp); err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}

	setDefaultValues(&cfg)

	svc := newService(ctx, logger, eventSvc, cfg, qp)

	grpcServerConfig := server.Config{
		Port:         cfg.AgentConfig.Port,
		Host:         cfg.AgentConfig.Host,
		CertFile:     cfg.AgentConfig.CertFile,
		KeyFile:      cfg.AgentConfig.KeyFile,
		ServerCAFile: cfg.AgentConfig.ServerCAFile,
		ClientCAFile: cfg.AgentConfig.ClientCAFile,
		AttestedTLS:  cfg.AgentConfig.AttestedTls,
	}

	registerAgentServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		agent.RegisterAgentServiceServer(srv, agentgrpc.NewServer(svc))
	}

	authSvc, err := auth.New(cfg)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create auth service %s", err.Error()))
		exitCode = 1
		return
	}

	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerAgentServiceServer, logger, qp, authSvc)

	g.Go(func() error {
		for {
			if _, err := io.Copy(io.Discard, conn); err != nil {
				log.Printf("vsock connection lost: %v, reconnecting...", err)
				conn.Close()
				conn, err = dialVsock()
				if err != nil {
					log.Fatal("failed to reconnect: ", err)
				}
			}
			time.Sleep(retryInterval)
		}
	})

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

func newService(ctx context.Context, logger *slog.Logger, eventSvc events.Service, cmp agent.Computation, qp client.QuoteProvider) agent.Service {
	svc := agent.New(ctx, logger, eventSvc, cmp, qp)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := prometheus.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}

func readConfig() (agent.Computation, error) {
	l, err := vsock.Listen(qemu.VsockConfigPort, nil)
	if err != nil {
		return agent.Computation{}, err
	}
	defer l.Close()

	conn, err := l.Accept()
	if err != nil {
		return agent.Computation{}, err
	}
	defer conn.Close()

	var buffer []byte
	for {
		chunk := make([]byte, 1024)
		n, err := conn.Read(chunk)
		if err != nil {
			if err == io.EOF {
				break
			}
			return agent.Computation{}, err
		}
		buffer = append(buffer, chunk[:n]...)
	}

	ac := agent.Computation{
		AgentConfig: agent.AgentConfig{},
	}
	if err := json.Unmarshal(buffer, &ac); err != nil {
		return agent.Computation{}, err
	}
	return ac, nil
}

func setDefaultValues(cfg *agent.Computation) {
	if cfg.AgentConfig.LogLevel == "" {
		cfg.AgentConfig.LogLevel = "info"
	}
	if cfg.AgentConfig.Port == "" {
		cfg.AgentConfig.Port = defSvcGRPCPort
	}
}

func isTEE() bool {
	_, err := os.Stat("/dev/sev-guest")
	return !os.IsNotExist(err)
}

func dialVsock() (*vsock.Conn, error) {
	var conn *vsock.Conn
	var err error

	err = backoff.Retry(func() error {
		conn, err = vsock.Dial(vsock.Host, managerevents.ManagerVsockPort, nil)
		if err == nil {
			log.Println("vsock connection established")
			return nil
		}
		log.Printf("vsock connection failed, retrying in %s... Error: %v", retryInterval, err)
		return err
	}, backoff.NewExponentialBackOff())
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func verifyManifest(cfg agent.Computation, qp client.QuoteProvider) error {
	if !isTEE() {
		return nil
	}

	ar, err := qp.GetRawQuote(sha3.Sum512([]byte(cfg.ID)))
	if err != nil {
		return err
	}

	arProto, err := abi.ReportCertsToProto(ar[:abi.ReportSize])
	if err != nil {
		return err
	}

	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	mcHash := sha3.Sum256(cfgBytes)

	if arProto.Report.HostData == nil {
		return fmt.Errorf("manifest verification failed: HostData is nil")
	}
	if !bytes.Equal(arProto.Report.HostData, mcHash[:]) {
		return fmt.Errorf("manifest verification failed")
	}

	return nil
}
