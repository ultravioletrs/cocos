// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/prometheus"
	"github.com/caarlos0/env/v11"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/api"
	"github.com/ultravioletrs/cocos/agent/cvms"
	cvmsapi "github.com/ultravioletrs/cocos/agent/cvms/api/grpc"
	"github.com/ultravioletrs/cocos/agent/cvms/server"
	"github.com/ultravioletrs/cocos/agent/events"
	agentlogger "github.com/ultravioletrs/cocos/internal/logger"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	pkggrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc"
	cvmsgrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc/cvm"
	"golang.org/x/sync/errgroup"
)

const (
	svcName          = "agent"
	defSvcGRPCPort   = "7002"
	retryInterval    = 5 * time.Second
	envPrefixCVMGRPC = "AGENT_CVM_GRPC_"
	storageDir       = "/var/lib/cocos/agent"
)

type config struct {
	LogLevel      string `env:"AGENT_LOG_LEVEL"  envDefault:"debug"`
	Vmpl          int    `env:"AGENT_VMPL"       envDefault:"2"`
	AgentGrpcHost string `env:"AGENT_GRPC_HOST"  envDefault:"0.0.0.0"`
	CAUrl         string `env:"AGENT_CVM_CA_URL" envDefault:""`
	CVMId         string `env:"AGENT_CVM_ID"     envDefault:""`
	AgentMaaURL   string `env:"AGENT_MAA_URL"    envDefault:"https://sharedeus2.eus2.attest.azure.net"`
	AgentOSBuild  string `env:"AGENT_OS_BUILD"   envDefault:"UVC"`
	AgentOSDistro string `env:"AGENT_OS_DISTRO"  envDefault:"UVC"`
	AgentOSType   string `env:"AGENT_OS_TYPE"    envDefault:"UVC"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		log.Println(err)
		exitCode = 1
		return
	}

	eventsLogsQueue := make(chan *cvms.ClientStreamMessage, 1000)

	handler := agentlogger.NewProtoHandler(os.Stdout, &slog.HandlerOptions{Level: level}, eventsLogsQueue)
	logger := slog.New(handler)

	eventSvc, err := events.New(svcName, eventsLogsQueue)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create events service %s", err.Error()))
		exitCode = 1
		return
	}

	var provider attestation.Provider
	ccPlatform := attestation.CCPlatform()

	azureConfig := azure.NewEnvConfigFromAgent(
		cfg.AgentOSBuild,
		cfg.AgentOSType,
		cfg.AgentOSDistro,
		cfg.AgentMaaURL,
	)
	azure.InitializeDefaultMAAVars(azureConfig)

	switch ccPlatform {
	case attestation.SNP:
		provider = vtpm.NewProvider(nil, false, uint(cfg.Vmpl))
	case attestation.SNPvTPM:
		provider = vtpm.NewProvider(nil, true, uint(cfg.Vmpl))
	case attestation.Azure:
		provider = azure.NewProvider()
	case attestation.TDX:
		provider = tdx.NewProvider()
	case attestation.NoCC:
		logger.Info("TEE device not found")
		provider = &attestation.EmptyProvider{}
	}

	cvmGrpcConfig := pkggrpc.CVMClientConfig{}
	if err := env.ParseWithOptions(&cvmGrpcConfig, env.Options{Prefix: envPrefixCVMGRPC}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	cvmGRPCClient, cvmsClient, err := cvmsgrpc.NewCVMClient(cvmGrpcConfig)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	defer cvmGRPCClient.Close()

	reconnectFn := func(ctx context.Context) (pkggrpc.Client, cvms.Service_ProcessClient, error) {
		grpcClient, newClient, err := cvmsgrpc.NewCVMClient(cvmGrpcConfig)
		if err != nil {
			return nil, nil, err
		}
		// Don't defer close here as we want to keep the connection open

		pc, err := newClient.Process(ctx)
		if err != nil {
			grpcClient.Close()
			return nil, nil, err
		}
		return grpcClient, pc, nil
	}

	pc, err := cvmsClient.Process(ctx)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}

	if cfg.Vmpl < 0 || cfg.Vmpl > 3 {
		logger.Error("vmpl level must be in a range [0, 3]")
		exitCode = 1
		return
	}

	svc := newService(ctx, logger, eventSvc, provider, cfg.Vmpl)

	if err := os.MkdirAll(storageDir, 0o755); err != nil {
		logger.Error(fmt.Sprintf("failed to create storage directory: %s", err))
		exitCode = 1
		return
	}

	mc, err := cvmsapi.NewClient(pc, svc, eventsLogsQueue, logger, server.NewServer(logger, svc, cfg.AgentGrpcHost, cfg.CAUrl, cfg.CVMId), storageDir, reconnectFn, cvmGRPCClient)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}

	g.Go(func() error {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(ch)

		select {
		case <-ch:
			logger.Info("Received signal, shutting down...")
			cancel()
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	g.Go(func() error {
		return mc.Process(ctx, cancel)
	})

	attest, certSerialNumber, err := attestationFromCert(ctx, cvmGrpcConfig.ClientCert, svc)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to get attestation: %s", err))
		exitCode = 1
		return
	}

	if ccPlatform == attestation.Azure {
		azureAttestationResult, azureCertSerialNumber, err := azureAttestationFromCert(ctx, cvmGrpcConfig.ClientCert, svc)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to get attestation: %s", err))
			exitCode = 1
			return
		}
		eventsLogsQueue <- &cvms.ClientStreamMessage{
			Message: &cvms.ClientStreamMessage_AzureAttestationResult{
				AzureAttestationResult: &cvms.AzureAttestationResponse{
					File:             azureAttestationResult,
					CertSerialNumber: azureCertSerialNumber,
				},
			},
		}
	}

	eventsLogsQueue <- &cvms.ClientStreamMessage{
		Message: &cvms.ClientStreamMessage_VTPMattestationReport{
			VTPMattestationReport: &cvms.AttestationResponse{
				File:             attest,
				CertSerialNumber: certSerialNumber,
			},
		},
	}

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
	}
}

func newService(ctx context.Context, logger *slog.Logger, eventSvc events.Service, provider attestation.Provider, vmpl int) agent.Service {
	svc := agent.New(ctx, logger, eventSvc, provider, vmpl)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := prometheus.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}

func attestationFromCert(ctx context.Context, certFilePath string, svc agent.Service) ([]byte, string, error) {
	if certFilePath == "" {
		return nil, "", nil
	}

	certFile, err := os.ReadFile(certFilePath)
	if err != nil {
		return nil, "", err
	}

	certPem, _ := pem.Decode(certFile)
	certx509, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, "", err
	}

	nonceSNP := sha512.Sum512(certFile)
	nonceVTPM := sha256.Sum256(certFile)
	attest, err := svc.Attestation(ctx, nonceSNP, nonceVTPM, attestation.SNPvTPM)
	if err != nil {
		return nil, "", err
	}

	return attest, certx509.SerialNumber.String(), nil
}

func azureAttestationFromCert(ctx context.Context, certFilePath string, svc agent.Service) ([]byte, string, error) {
	if certFilePath == "" {
		return nil, "", nil
	}

	certFile, err := os.ReadFile(certFilePath)
	if err != nil {
		return nil, "", err
	}

	certPem, _ := pem.Decode(certFile)
	certx509, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, "", err
	}

	nonceAzure := sha256.Sum256(certFile)
	attestation, err := svc.AttestationResult(ctx, nonceAzure, attestation.AzureToken)
	if err != nil {
		return nil, "", err
	}

	return attestation, certx509.SerialNumber.String(), nil
}
