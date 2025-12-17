// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package attestation

import (
	"context"
	"time"

	attestation_v1 "github.com/ultravioletrs/cocos/internal/proto/attestation/v1"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client interface {
	GetAttestation(ctx context.Context, reportData [64]byte, nonce [32]byte, attType attestation.PlatformType) ([]byte, error)
	GetAzureToken(ctx context.Context, nonce [32]byte) ([]byte, error)
	Close() error
}

type client struct {
	conn   *grpc.ClientConn
	client attestation_v1.AttestationServiceClient
}

func NewClient(socketPath string) (Client, error) {
	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &client{
		conn:   conn,
		client: attestation_v1.NewAttestationServiceClient(conn),
	}, nil
}

func (c *client) Close() error {
	return c.conn.Close()
}

func (c *client) GetAttestation(ctx context.Context, reportData [64]byte, nonce [32]byte, attType attestation.PlatformType) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var platformType attestation_v1.PlatformType
	switch attType {
	case attestation.SNP:
		platformType = attestation_v1.PlatformType_PLATFORM_TYPE_SNP
	case attestation.TDX:
		platformType = attestation_v1.PlatformType_PLATFORM_TYPE_TDX
	case attestation.VTPM:
		platformType = attestation_v1.PlatformType_PLATFORM_TYPE_VTPM
	case attestation.SNPvTPM:
		platformType = attestation_v1.PlatformType_PLATFORM_TYPE_SNP_VTPM
	default:
		platformType = attestation_v1.PlatformType_PLATFORM_TYPE_UNSPECIFIED
	}

	req := &attestation_v1.AttestationRequest{
		ReportData:   reportData[:],
		Nonce:        nonce[:],
		PlatformType: platformType,
	}

	resp, err := c.client.FetchAttestation(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Quote, nil
}

func (c *client) GetAzureToken(ctx context.Context, nonce [32]byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req := &attestation_v1.AzureTokenRequest{
		Nonce: nonce[:],
	}

	resp, err := c.client.FetchAzureToken(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Token, nil
}
