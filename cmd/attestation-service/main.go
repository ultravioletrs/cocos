// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	mglog "github.com/absmach/supermq/logger"
	"github.com/caarlos0/env/v11"
	attestationpb "github.com/ultravioletrs/cocos/internal/proto/attestation/v1"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

const (
	svcName    = "attestation-service"
	socketPath = "/run/cocos/attestation.sock"
)

type config struct {
	LogLevel      string `env:"ATTESTATION_LOG_LEVEL"   envDefault:"debug"`
	Vmpl          int    `env:"ATTESTATION_VMPL"        envDefault:"2"`
	AgentMaaURL   string `env:"AGENT_MAA_URL"           envDefault:"https://sharedeus2.eus2.attest.azure.net"`
	AgentOSBuild  string `env:"AGENT_OS_BUILD"          envDefault:"UVC"`
	AgentOSDistro string `env:"AGENT_OS_DISTRO"         envDefault:"UVC"`
	AgentOSType   string `env:"AGENT_OS_TYPE"           envDefault:"UVC"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		fmt.Printf("failed to load %s configuration : %s\n", svcName, err)
		os.Exit(1)
	}

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		fmt.Println(err)
		exitCode = 1
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

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
		provider = vtpm.NewProvider(false, uint(cfg.Vmpl))
	case attestation.SNPvTPM:
		provider = vtpm.NewProvider(true, uint(cfg.Vmpl))
	case attestation.Azure:
		provider = azure.NewProvider()
	case attestation.TDX:
		provider = tdx.NewProvider()
	case attestation.NoCC:
		logger.Info("TEE device not found")
		provider = &attestation.EmptyProvider{}
	}

	if ccPlatform == attestation.SNP || ccPlatform == attestation.SNPvTPM {
		if err := quoteprovider.FetchCertificates(uint(cfg.Vmpl)); err != nil {
			logger.Error(fmt.Sprintf("failed to fetch certificates: %s", err))
			exitCode = 1
			return
		}
	}

	// Remove existing socket if it exists
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			logger.Error(fmt.Sprintf("failed to remove existing socket: %s", err))
			exitCode = 1
			return
		}
	}

	dir := socketPath[:len(socketPath)-len("/attestation.sock")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Error(fmt.Sprintf("failed to create socket directory: %s", err))
		exitCode = 1
		return
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to listen on socket: %s", err))
		exitCode = 1
		return
	}

	if err := os.Chmod(socketPath, 0777); err != nil {
		logger.Error(fmt.Sprintf("failed to chmod socket: %s", err))
		exitCode = 1
		return
	}

	grpcServer := grpc.NewServer()
	svc := &service{
		provider: provider,
		logger:   logger,
	}
	attestationpb.RegisterAttestationServiceServer(grpcServer, svc)

	g.Go(func() error {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(ch)

		select {
		case <-ch:
			logger.Info("Received signal, shutting down...")
			cancel()
			grpcServer.GracefulStop()
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	g.Go(func() error {
		logger.Info(fmt.Sprintf("%s started on %s", svcName, socketPath))
		return grpcServer.Serve(lis)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s terminated: %s", svcName, err))
	}
}

type service struct {
	attestationpb.UnimplementedAttestationServiceServer
	provider attestation.Provider
	logger   *slog.Logger
}

func (s *service) GetAttestation(ctx context.Context, req *attestationpb.AttestationRequest) (*attestationpb.AttestationResponse, error) {
	var quote []byte
	var err error

	switch req.PlatformType {
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP, attestationpb.PlatformType_PLATFORM_TYPE_TDX:
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		quote, err = s.provider.TeeAttestation(reportData[:])
	case attestationpb.PlatformType_PLATFORM_TYPE_VTPM:
		var nonce [32]byte
		copy(nonce[:], req.Nonce)
		quote, err = s.provider.VTpmAttestation(nonce[:])
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP_VTPM:
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		var nonce [32]byte
		copy(nonce[:], req.Nonce)
		quote, err = s.provider.Attestation(reportData[:], nonce[:])
	default:
		return nil, fmt.Errorf("unsupported platform type")
	}

	if err != nil {
		return nil, err
	}

	return &attestationpb.AttestationResponse{Quote: quote}, nil
}

func (s *service) GetAzureToken(ctx context.Context, req *attestationpb.AzureTokenRequest) (*attestationpb.AzureTokenResponse, error) {
	var nonce [32]byte
	copy(nonce[:], req.Nonce)
	token, err := s.provider.AzureAttestationToken(nonce[:])
	if err != nil {
		return nil, err
	}
	return &attestationpb.AzureTokenResponse{Token: token}, nil
}
