// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package ccaa

import (
	"context"
	"fmt"
	"time"

	attestation_agent "github.com/ultravioletrs/cocos/internal/proto/attestation-agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Provider implements attestation.Provider interface by delegating to CC attestation-agent.
type Provider struct {
	client attestation_agent.AttestationAgentServiceClient
	conn   *grpc.ClientConn
	addr   string
}

// NewProvider creates a new CC attestation-agent provider.
// addr should be in the format "host:port" (e.g., "127.0.0.1:50002").
func NewProvider(addr string) (*Provider, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CC attestation-agent at %s: %w", addr, err)
	}

	client := attestation_agent.NewAttestationAgentServiceClient(conn)

	// Test connection by getting TEE type
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.GetTeeType(ctx, &attestation_agent.GetTeeTypeRequest{})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to verify CC attestation-agent connection: %w", err)
	}

	return &Provider{
		client: client,
		conn:   conn,
		addr:   addr,
	}, nil
}

// Close closes the gRPC connection to CC attestation-agent.
func (p *Provider) Close() error {
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

// TeeAttestation retrieves TEE attestation evidence using report data.
// For TDX/SNP, reportData should be 64 bytes.
func (p *Provider) TeeAttestation(reportData []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := p.client.GetEvidence(ctx, &attestation_agent.GetEvidenceRequest{
		RuntimeData: reportData,
	})
	if err != nil {
		return nil, fmt.Errorf("CC attestation-agent GetEvidence failed: %w", err)
	}

	return resp.Evidence, nil
}

// VTpmAttestation retrieves vTPM attestation evidence using nonce.
// For vTPM, nonce should be 32 bytes.
func (p *Provider) VTpmAttestation(nonce []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := p.client.GetEvidence(ctx, &attestation_agent.GetEvidenceRequest{
		RuntimeData: nonce,
	})
	if err != nil {
		return nil, fmt.Errorf("CC attestation-agent GetEvidence failed: %w", err)
	}

	return resp.Evidence, nil
}

// Attestation retrieves combined attestation evidence using both report data and nonce.
// This is used for SNP+vTPM scenarios.
func (p *Provider) Attestation(reportData []byte, nonce []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Combine reportData and nonce into RuntimeData
	runtimeData := append(reportData, nonce...)

	resp, err := p.client.GetEvidence(ctx, &attestation_agent.GetEvidenceRequest{
		RuntimeData: runtimeData,
	})
	if err != nil {
		return nil, fmt.Errorf("CC attestation-agent GetEvidence failed: %w", err)
	}

	return resp.Evidence, nil
}

// AzureAttestationToken retrieves Azure-specific attestation token.
// Note: CC attestation-agent may not support Azure tokens in the same way.
// This implementation attempts to use GetToken with "Azure" token type.
func (p *Provider) AzureAttestationToken(nonce []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try to get Azure token via GetToken method
	resp, err := p.client.GetToken(ctx, &attestation_agent.GetTokenRequest{
		TokenType: "Azure",
	})
	if err != nil {
		// Fallback: try GetEvidence with nonce
		evidenceResp, evidenceErr := p.client.GetEvidence(ctx, &attestation_agent.GetEvidenceRequest{
			RuntimeData: nonce,
		})
		if evidenceErr != nil {
			return nil, fmt.Errorf("CC attestation-agent Azure token not supported: GetToken failed: %w, GetEvidence fallback failed: %v", err, evidenceErr)
		}
		return evidenceResp.Evidence, nil
	}

	return resp.Token, nil
}
