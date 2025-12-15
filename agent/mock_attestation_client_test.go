// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"

	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/pkg/attestation"
)

type MockAttestationClient struct {
	mock.Mock
}

func (m *MockAttestationClient) GetAttestation(ctx context.Context, reportData [64]byte, nonce [32]byte, attType attestation.PlatformType) ([]byte, error) {
	args := m.Called(ctx, reportData, nonce, attType)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockAttestationClient) GetAzureToken(ctx context.Context, nonce [32]byte) ([]byte, error) {
	args := m.Called(ctx, nonce)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockAttestationClient) Close() error {
	args := m.Called()
	return args.Error(0)
}
