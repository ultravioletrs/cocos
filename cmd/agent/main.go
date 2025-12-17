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
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/absmach/certs/sdk"
	mglog "github.com/absmach/supermq/logger"
	"github.com/absmach/supermq/pkg/prometheus"
	"github.com/caarlos0/env/v11"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/api"
	"github.com/ultravioletrs/cocos/agent/cvms"
	cvmsapi "github.com/ultravioletrs/cocos/agent/cvms/api/grpc"
	"github.com/ultravioletrs/cocos/agent/cvms/server"
	"github.com/ultravioletrs/cocos/agent/events"
	logpb "github.com/ultravioletrs/cocos/agent/log"
	agentlogger "github.com/ultravioletrs/cocos/internal/logger"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/clients"
	pkggrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc"
	attestation_client "github.com/ultravioletrs/cocos/pkg/clients/grpc/attestation"
	cvmsgrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc/cvm"
	logclient "github.com/ultravioletrs/cocos/pkg/clients/grpc/log"
	runnerclient "github.com/ultravioletrs/cocos/pkg/clients/grpc/runner"
	"github.com/ultravioletrs/cocos/pkg/ingress"
	"golang.org/x/sync/errgroup"
)

const (
	svcName          = "agent"
	envPrefixCVMGRPC = "AGENT_CVM_GRPC_"
	storageDir       = "/var/lib/cocos/agent"
)

type config struct {
	LogLevel                 string `env:"AGENT_LOG_LEVEL"              envDefault:"debug"`
	Vmpl                     int    `env:"AGENT_VMPL"                   envDefault:"2"`
	AgentGrpcHost            string `env:"AGENT_GRPC_HOST"              envDefault:"0.0.0.0"`
	CAUrl                    string `env:"AGENT_CVM_CA_URL"             envDefault:""`
	CVMId                    string `env:"AGENT_CVM_ID"                 envDefault:""`
	CertsToken               string `env:"AGENT_CERTS_TOKEN"            envDefault:""`
	AgentMaaURL              string `env:"AGENT_MAA_URL"                envDefault:"https://sharedeus2.eus2.attest.azure.net"`
	AgentOSBuild             string `env:"AGENT_OS_BUILD"               envDefault:"UVC"`
	AgentOSDistro            string `env:"AGENT_OS_DISTRO"              envDefault:"UVC"`
	AgentOSType              string `env:"AGENT_OS_TYPE"                envDefault:"UVC"`
	AttestationServiceSocket string `env:"ATTESTATION_SERVICE_SOCKET" envDefault:"/run/cocos/attestation.sock"`
	EnableATLS               bool   `env:"AGENT_ENABLE_ATLS"          envDefault:"true"`
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

	logQueue := make(chan *cvms.ClientStreamMessage, 1000)
	cvmsQueue := make(chan *cvms.ClientStreamMessage, 1000)

	handler := agentlogger.NewProtoHandler(os.Stdout, &slog.HandlerOptions{Level: level}, logQueue)
	logger := slog.New(handler)

	eventSvc, err := events.New(svcName, logQueue)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create events service %s", err.Error()))
		exitCode = 1
		return
	}

	// Log Client
	logClient, err := logclient.NewClient("/run/cocos/log.sock")
	if err != nil {
		logger.Warn(fmt.Sprintf("failed to create log client: %s. Logging will be local only until service is available.", err))
	} else {
		defer logClient.Close()
	}

	// Consume logQueue
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case msg := <-logQueue:
				if logClient == nil {
					continue
				}
				// Convert cvms.ClientStreamMessage to log.LogEntry or log.EventEntry
				switch m := msg.Message.(type) {
				case *cvms.ClientStreamMessage_AgentLog:
					err := logClient.SendLog(ctx, &logpb.LogEntry{
						Message:       m.AgentLog.Message,
						ComputationId: m.AgentLog.ComputationId,
						Level:         m.AgentLog.Level,
						Timestamp:     m.AgentLog.Timestamp,
					})
					if err != nil {
						// Fallback to stdout? Already handled by slog handler writing to stdout too?
						// agentlogger writes to stdout AND queue.
					}
				case *cvms.ClientStreamMessage_AgentEvent:
					err := logClient.SendEvent(ctx, &logpb.EventEntry{
						EventType:     m.AgentEvent.EventType,
						Timestamp:     m.AgentEvent.Timestamp,
						ComputationId: m.AgentEvent.ComputationId,
						Details:       m.AgentEvent.Details,
						Originator:    m.AgentEvent.Originator,
						Status:        m.AgentEvent.Status,
					})
					if err != nil {
					}
				}
			}
		}
	})

	var provider attestation.Provider
	ccPlatform := attestation.CCPlatform()

	azureConfig := azure.NewEnvConfigFromAgent(
		cfg.AgentOSBuild,
		cfg.AgentOSType,
		cfg.AgentOSDistro,
		cfg.AgentMaaURL,
	)
	azure.InitializeDefaultMAAVars(azureConfig)

	cvmGrpcConfig := clients.StandardClientConfig{}
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

	attClient, err := attestation_client.NewClient(cfg.AttestationServiceSocket)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create attestation client: %s", err))
		exitCode = 1
		return
	}
	defer attClient.Close()

	runnerClient, err := runnerclient.NewClient("/run/cocos/runner.sock")
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create runner client: %s", err))
		exitCode = 1
		return
	}
	defer runnerClient.Close()

	svc := newService(ctx, logger, eventSvc, attClient, runnerClient, cfg.Vmpl)

	if err := os.MkdirAll(storageDir, 0o755); err != nil {
		logger.Error(fmt.Sprintf("failed to create storage directory: %s", err))
		exitCode = 1
		return
	}

	var certProvider atls.CertificateProvider
	if cfg.EnableATLS && ccPlatform != attestation.NoCC {
		var certsSDK sdk.SDK
		if cfg.CAUrl != "" {
			certsSDK = sdk.NewSDK(sdk.Config{
				CertsURL: cfg.CAUrl,
			})
		}
		certProvider, err = atls.NewProvider(provider, ccPlatform, cfg.CertsToken, cfg.CVMId, certsSDK)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to create certificate provider: %s", err))
			exitCode = 1
			return
		}
	}

	// Create ingress proxy server
	backendURL, err := url.Parse("http://localhost:7001")
	if err != nil {
		logger.Error(fmt.Sprintf("failed to parse backend URL: %s", err))
		exitCode = 1
		return
	}
	ingressProxy := ingress.NewProxyServer(logger, backendURL, certProvider)

	mc, err := cvmsapi.NewClient(pc, svc, cvmsQueue, logger, server.NewServer(logger, svc, cfg.AgentGrpcHost, certProvider), ingressProxy, storageDir, reconnectFn, cvmGRPCClient)
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
		azureAttestationToken, azureCertSerialNumber, err := azureAttestationFromCert(ctx, cvmGrpcConfig.ClientCert, svc)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to get attestation: %s", err))
			exitCode = 1
			return
		}
		cvmsQueue <- &cvms.ClientStreamMessage{
			Message: &cvms.ClientStreamMessage_AzureAttestationToken{
				AzureAttestationToken: &cvms.AzureAttestationToken{
					File:             azureAttestationToken,
					CertSerialNumber: azureCertSerialNumber,
				},
			},
		}
	}

	cvmsQueue <- &cvms.ClientStreamMessage{
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

func newService(ctx context.Context, logger *slog.Logger, eventSvc events.Service, attClient attestation_client.Client, runnerClient runnerclient.Client, vmpl int) agent.Service {
	svc := agent.New(ctx, logger, eventSvc, attClient, runnerClient, vmpl)

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
	attestation, err := svc.AzureAttestationToken(ctx, nonceAzure)
	if err != nil {
		return nil, "", err
	}

	return attestation, certx509.SerialNumber.String(), nil
}
