// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/mocks"
	config "github.com/ultravioletrs/cocos/pkg/attestation"
	"golang.org/x/crypto/sha3"
)

const svcErr = "Service Error"

func TestAlgoEndpoint(t *testing.T) {
	svc := new(mocks.Service)
	tests := []struct {
		name        string
		req         algoReq
		expectedErr bool
	}{
		{
			name: "Success",
			req:  algoReq{Algorithm: []byte("algorithm")},
		},
		{
			name:        "Validation Error",
			req:         algoReq{},
			expectedErr: true,
		},
		{
			name:        "Service Error",
			req:         algoReq{Algorithm: []byte("algorithm")},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == svcErr {
				svc.On("Algo", context.Background(), agent.Algorithm{Algorithm: tt.req.Algorithm}).Return(errors.New("")).Once()
			} else {
				svc.On("Algo", context.Background(), agent.Algorithm{Algorithm: tt.req.Algorithm}).Return(nil).Once()
			}
			endpoint := algoEndpoint(svc)
			_, err := endpoint(context.Background(), tt.req)
			if (err != nil) != tt.expectedErr {
				t.Errorf("algoEndpoint() error = %v, expectedErr %v", err, tt.expectedErr)
			}
		})
	}
}

func TestDataEndpoint(t *testing.T) {
	svc := new(mocks.Service)
	tests := []struct {
		name        string
		req         dataReq
		expectedErr bool
	}{
		{
			name: "Success",
			req:  dataReq{Dataset: []byte("dataset")},
		},
		{
			name:        "Validation Error",
			req:         dataReq{},
			expectedErr: true,
		},
		{
			name:        "Service Error",
			req:         dataReq{Dataset: []byte("dataset")},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == svcErr {
				svc.On("Data", context.Background(), agent.Dataset{Dataset: tt.req.Dataset}).Return(errors.New("")).Once()
			} else {
				svc.On("Data", context.Background(), agent.Dataset{Dataset: tt.req.Dataset}).Return(nil).Once()
			}
			endpoint := dataEndpoint(svc)
			_, err := endpoint(context.Background(), tt.req)
			if (err != nil) != tt.expectedErr {
				t.Errorf("dataEndpoint() error = %v, expectedErr %v", err, tt.expectedErr)
			}
		})
	}
}

func TestResultEndpoint(t *testing.T) {
	svc := new(mocks.Service)
	tests := []struct {
		name        string
		req         resultReq
		expectedErr bool
	}{
		{
			name: "Success",
			req:  resultReq{},
		},
		{
			name:        "Service Error",
			req:         resultReq{},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == svcErr {
				svc.On("Result", context.Background()).Return([]byte{}, errors.New("")).Once()
			} else {
				svc.On("Result", context.Background()).Return([]byte{}, nil).Once()
			}
			endpoint := resultEndpoint(svc)
			res, err := endpoint(context.Background(), tt.req)
			if (err != nil) != tt.expectedErr {
				t.Errorf("resultEndpoint() error = %v, expectedErr %v", err, tt.expectedErr)
			}
			if err == nil {
				_, ok := res.(resultRes)
				if !ok {
					t.Errorf("resultEndpoint() returned unexpected type %T", res)
				}
			}
		})
	}
}

func TestAttestationEndpoint(t *testing.T) {
	svc := new(mocks.Service)
	tests := []struct {
		name        string
		req         attestationReq
		expectedErr bool
	}{
		{
			name: "Success",
			req:  attestationReq{TeeNonce: sha3.Sum512([]byte("report data")), VtpmNonce: sha3.Sum256([]byte("vtpm nonce")), AttType: config.SNP},
		},
		{
			name:        "Service Error",
			req:         attestationReq{TeeNonce: sha3.Sum512([]byte("report data")), VtpmNonce: sha3.Sum256([]byte("vtpm nonce")), AttType: config.SNP},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == svcErr {
				svc.On("Attestation", context.Background(), tt.req.TeeNonce, tt.req.VtpmNonce, tt.req.AttType).Return([]byte{}, errors.New("")).Once()
			} else {
				svc.On("Attestation", context.Background(), tt.req.TeeNonce, tt.req.VtpmNonce, tt.req.AttType).Return([]byte{}, nil).Once()
			}
			endpoint := attestationEndpoint(svc)
			res, err := endpoint(context.Background(), tt.req)
			if (err != nil) != tt.expectedErr {
				t.Errorf("attestationEndpoint() error = %v, expectedErr %v", err, tt.expectedErr)
			}
			if err == nil {
				_, ok := res.(attestationRes)
				if !ok {
					t.Errorf("attestationEndpoint() returned unexpected type %T", res)
				}
			}
		})
	}
}
