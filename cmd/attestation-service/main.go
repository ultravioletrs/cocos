// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/ecdsa"
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
	"github.com/ultravioletrs/cocos/pkg/attestation/ccaa"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
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
	LogLevel              string `env:"ATTESTATION_LOG_LEVEL"    envDefault:"debug"`
	Vmpl                  int    `env:"ATTESTATION_VMPL"         envDefault:"2"`
	AgentMaaURL           string `env:"AGENT_MAA_URL"            envDefault:"https://sharedeus2.eus2.attest.azure.net"`
	AgentOSBuild          string `env:"AGENT_OS_BUILD"           envDefault:"UVC"`
	AgentOSDistro         string `env:"AGENT_OS_DISTRO"          envDefault:"UVC"`
	AgentOSType           string `env:"AGENT_OS_TYPE"            envDefault:"UVC"`
	EATFormat             string `env:"ATTESTATION_EAT_FORMAT"   envDefault:"CBOR"` // JWT or CBOR
	EATIssuer             string `env:"ATTESTATION_EAT_ISSUER"   envDefault:"cocos-attestation-service"`
	UseCCAttestationAgent bool   `env:"USE_CC_ATTESTATION_AGENT" envDefault:"false"`
	CCAgentAddress        string `env:"CC_AGENT_ADDRESS"         envDefault:"127.0.0.1:50002"`

	// Future KBS Integration Configuration
	// When KBS support is added, these fields will enable:
	// - Remote attestation verification via KBS
	// - Encrypted algorithm/dataset retrieval
	// - Per-computation secret provisioning
	//
	// Example future fields:
	// KBSEndpoint   string `env:"KBS_ENDPOINT"            envDefault:""` // Optional KBS URL
	// KBSEnabled    bool   `env:"KBS_ENABLED"             envDefault:"false"`
	// KBSTimeout    int    `env:"KBS_TIMEOUT_SECONDS"     envDefault:"30"`
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

	// Try to use CC attestation-agent if configured
	if cfg.UseCCAttestationAgent {
		logger.Info(fmt.Sprintf("attempting to use CC attestation-agent at %s", cfg.CCAgentAddress))
		ccProvider, err := ccaa.NewProvider(cfg.CCAgentAddress)
		if err != nil {
			logger.Warn(fmt.Sprintf("failed to connect to CC attestation-agent: %s, falling back to direct providers", err))
		} else {
			logger.Info("successfully connected to CC attestation-agent")
			provider = ccProvider
			defer ccProvider.Close()
		}
	}

	// Fallback to direct providers if CC AA not configured or unavailable
	if provider == nil {
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
	}

	if ccPlatform == attestation.SNP || ccPlatform == attestation.SNPvTPM {
		if err := vtpm.FetchSEVCertificates(uint(cfg.Vmpl)); err != nil {
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Error(fmt.Sprintf("failed to create socket directory: %s", err))
		exitCode = 1
		return
	}

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to listen on socket: %s", err))
		exitCode = 1
		return
	}

	if err := os.Chmod(socketPath, 0o777); err != nil {
		logger.Error(fmt.Sprintf("failed to chmod socket: %s", err))
		exitCode = 1
		return
	}

	// Generate EAT signing key
	signingKey, err := eat.GenerateSigningKey()
	if err != nil {
		logger.Error(fmt.Sprintf("failed to generate EAT signing key: %s", err))
		exitCode = 1
		return
	}

	grpcServer := grpc.NewServer()
	svc := &service{
		provider:   provider,
		logger:     logger,
		signingKey: signingKey,
		eatFormat:  cfg.EATFormat,
		eatIssuer:  cfg.EATIssuer,
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
		return grpcServer.Serve(l)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s terminated: %s", svcName, err))
	}
}

type service struct {
	attestationpb.UnimplementedAttestationServiceServer
	provider   attestation.Provider
	logger     *slog.Logger
	signingKey *ecdsa.PrivateKey
	eatFormat  string
	eatIssuer  string
}

func (s *service) FetchAttestation(ctx context.Context, req *attestationpb.AttestationRequest) (*attestationpb.AttestationResponse, error) {
	// Debug: log incoming request
	s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Received attestation request with platform type: %v (%d)",
		req.PlatformType, req.PlatformType))

	var binaryReport []byte
	var err error
	var platformType attestation.PlatformType

	// Get binary attestation report based on platform type
	switch req.PlatformType {
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP, attestationpb.PlatformType_PLATFORM_TYPE_TDX:
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		binaryReport, err = s.provider.TeeAttestation(reportData[:])
		platformType = convertPlatformType(req.PlatformType)
	case attestationpb.PlatformType_PLATFORM_TYPE_VTPM:
		var nonce [32]byte
		copy(nonce[:], req.Nonce)
		binaryReport, err = s.provider.VTpmAttestation(nonce[:])
		platformType = attestation.VTPM
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP_VTPM:
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		var nonce [32]byte
		copy(nonce[:], req.Nonce)
		binaryReport, err = s.provider.Attestation(reportData[:], nonce[:])
		platformType = attestation.SNPvTPM
	case attestationpb.PlatformType_PLATFORM_TYPE_UNSPECIFIED:
		// Generate sample attestation for testing in non-TEE environments
		s.logger.Warn("generating sample attestation for PLATFORM_TYPE_UNSPECIFIED - this should only be used for testing")
		s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Generating sample attestation: reportData_len=%d, nonce_len=%d",
			len(req.ReportData), len(req.Nonce)))

		// Create a simple sample report that includes the nonce/report data
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		var nonce [32]byte
		copy(nonce[:], req.Nonce)

		// Combine report data and nonce into a simple binary report
		binaryReport = make([]byte, 0, 96)
		binaryReport = append(binaryReport, reportData[:]...)
		binaryReport = append(binaryReport, nonce[:]...)
		platformType = attestation.NoCC
		s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Sample attestation generated: binaryReport_len=%d, platformType=%v (%d)",
			len(binaryReport), platformType, platformType))
	default:
		return nil, fmt.Errorf("unsupported platform type")
	}

	if err != nil {
		return nil, err
	}

	// Create EAT claims from binary report
	nonce := req.ReportData
	if len(req.Nonce) > 0 {
		nonce = req.Nonce
	}

	claims, err := eat.NewEATClaims(binaryReport, nonce, platformType)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to create EAT claims: %s", err))
		return nil, fmt.Errorf("failed to create EAT claims: %w", err)
	}

	// Encode to EAT token based on configured format
	var eatToken []byte
	switch s.eatFormat {
	case "JWT":
		tokenString, err := eat.EncodeToJWT(claims, s.signingKey, s.eatIssuer)
		if err != nil {
			return nil, fmt.Errorf("failed to encode JWT: %w", err)
		}
		eatToken = []byte(tokenString)
	case "CBOR":
		eatToken, err = eat.EncodeToCBOR(claims, s.signingKey, s.eatIssuer)
		if err != nil {
			return nil, fmt.Errorf("failed to encode CBOR: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported EAT format: %s", s.eatFormat)
	}

	s.logger.Debug(fmt.Sprintf("generated EAT token (%s format) for platform %v", s.eatFormat, platformType))

	return &attestationpb.AttestationResponse{EatToken: eatToken}, nil
}

// convertPlatformType converts protobuf platform type to internal platform type.
func convertPlatformType(pt attestationpb.PlatformType) attestation.PlatformType {
	switch pt {
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP:
		return attestation.SNP
	case attestationpb.PlatformType_PLATFORM_TYPE_TDX:
		return attestation.TDX
	case attestationpb.PlatformType_PLATFORM_TYPE_VTPM:
		return attestation.VTPM
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP_VTPM:
		return attestation.SNPvTPM
	case attestationpb.PlatformType_PLATFORM_TYPE_AZURE:
		return attestation.Azure
	default:
		return attestation.NoCC
	}
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
