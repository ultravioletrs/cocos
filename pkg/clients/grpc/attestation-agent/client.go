// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package attestation_agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	aa "github.com/ultravioletrs/cocos/internal/proto/attestation-agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client provides access to attestation-agent services.
type Client interface {
	// GetToken gets a token from the attestation-agent (e.g., KBS token).
	GetToken(ctx context.Context, tokenType string) ([]byte, error)
	Close() error
}

type client struct {
	conn   *grpc.ClientConn
	client aa.AttestationAgentServiceClient
}

// NewClient creates a new attestation-agent client.
// address can be either a TCP address (e.g., "127.0.0.1:50002") or Unix socket path (e.g., "/run/aa.sock")
func NewClient(address string) (Client, error) {
	var target string
	// If address contains ":", it's a TCP address, otherwise it's a Unix socket
	if strings.Contains(address, ":") {
		target = address
	} else {
		target = "unix://" + address
	}

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to attestation-agent: %w", err)
	}

	return &client{
		conn:   conn,
		client: aa.NewAttestationAgentServiceClient(conn),
	}, nil
}

func (c *client) Close() error {
	return c.conn.Close()
}

// GetToken gets a token from the attestation-agent.
// tokenType should be "kbs" for KBS tokens.
func (c *client) GetToken(ctx context.Context, tokenType string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req := &aa.GetTokenRequest{
		TokenType: tokenType,
	}

	resp, err := c.client.GetToken(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get token from attestation-agent: %w", err)
	}

	return resp.Token, nil
}
