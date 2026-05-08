// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	attestationpb "github.com/ultravioletrs/cocos/internal/proto/attestation/v1"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	attestationgpu "github.com/ultravioletrs/cocos/pkg/attestation/gpu"
)

func TestRequestNonce(t *testing.T) {
	req := &attestationpb.AttestationRequest{
		ReportData: []byte("report"),
		Nonce:      []byte("nonce"),
	}

	assert.Equal(t, []byte("nonce"), requestNonce(req))

	req.Nonce = nil
	assert.Equal(t, []byte("report"), requestNonce(req))
}

func TestDeriveComponentNonce(t *testing.T) {
	sessionNonce := []byte("session-nonce")

	gpuNonce := deriveComponentNonce(sessionNonce, "gpu")
	gpuNonceAgain := deriveComponentNonce(sessionNonce, "gpu")
	teeNonce := deriveComponentNonce(sessionNonce, "tee")

	assert.Len(t, gpuNonce, 32)
	assert.Equal(t, gpuNonce, gpuNonceAgain)
	assert.NotEqual(t, gpuNonce, teeNonce)
}

func TestShouldCollectGPU(t *testing.T) {
	assert.True(t, shouldCollectGPU(attestation.SNP))
	assert.True(t, shouldCollectGPU(attestation.SNPvTPM))
	assert.True(t, shouldCollectGPU(attestation.TDX))
	assert.False(t, shouldCollectGPU(attestation.VTPM))
	assert.False(t, shouldCollectGPU(attestation.NoCC))
}

func TestNewGPUCollector(t *testing.T) {
	collector, err := newGPUCollector(config{})
	assert.NoError(t, err)
	assert.Nil(t, collector)

	collector, err = newGPUCollector(config{
		GPUHelperPath:    "/tmp/helper",
		GPUHelperTimeout: 0,
	})
	assert.NoError(t, err)
	assert.NotNil(t, collector)
}

func TestClaimOptions_SkipsOptionalGPUFailure(t *testing.T) {
	svc := &service{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		gpuCollector: failingCollector{},
	}

	req := &attestationpb.AttestationRequest{
		ReportData: []byte("report-data"),
		Nonce:      []byte("nonce-data"),
	}

	opts, err := svc.claimOptions(context.Background(), req, attestation.TDX)
	assert.NoError(t, err)
	assert.Empty(t, opts)
}

type failingCollector struct{}

func (failingCollector) Collect(context.Context, []byte) (*attestationgpu.Evidence, error) {
	return nil, assert.AnError
}
