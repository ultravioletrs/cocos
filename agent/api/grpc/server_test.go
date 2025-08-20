// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/mocks"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type MockAgentService_AlgoServer struct {
	grpc.ServerStream
	mock.Mock
	ctx context.Context
}

func (m *MockAgentService_AlgoServer) Context() context.Context {
	return m.ctx
}

func (m *MockAgentService_AlgoServer) Recv() (*agent.AlgoRequest, error) {
	args := m.Called()
	return args.Get(0).(*agent.AlgoRequest), args.Error(1)
}

func (m *MockAgentService_AlgoServer) SendAndClose(resp *agent.AlgoResponse) error {
	args := m.Called(resp)
	return args.Error(0)
}

type MockAgentService_DataServer struct {
	grpc.ServerStream
	mock.Mock
	ctx context.Context
}

func (m *MockAgentService_DataServer) Context() context.Context {
	return m.ctx
}

func (m *MockAgentService_DataServer) Recv() (*agent.DataRequest, error) {
	args := m.Called()
	return args.Get(0).(*agent.DataRequest), args.Error(1)
}

func (m *MockAgentService_DataServer) SendAndClose(resp *agent.DataResponse) error {
	args := m.Called(resp)
	return args.Error(0)
}

type MockAgentService_ResultServer struct {
	grpc.ServerStream
	mock.Mock
	ctx context.Context
}

func (m *MockAgentService_ResultServer) Context() context.Context {
	return m.ctx
}

func (m *MockAgentService_ResultServer) SetHeader(md metadata.MD) error {
	args := m.Called(md)
	return args.Error(0)
}

func (m *MockAgentService_ResultServer) Send(resp *agent.ResultResponse) error {
	args := m.Called(resp)
	return args.Error(0)
}

type MockAgentService_AttestationServer struct {
	grpc.ServerStream
	mock.Mock
	ctx context.Context
}

func (m *MockAgentService_AttestationServer) Context() context.Context {
	return m.ctx
}

func (m *MockAgentService_AttestationServer) Send(resp *agent.AttestationResponse) error {
	args := m.Called(resp)
	return args.Error(0)
}

func (m *MockAgentService_AttestationServer) SetHeader(md metadata.MD) error {
	args := m.Called(md)
	return args.Error(0)
}

type MockAgentService_IMAMeasurementsServer struct {
	grpc.ServerStream
	mock.Mock
	ctx context.Context
}

func (m *MockAgentService_IMAMeasurementsServer) Context() context.Context {
	return m.ctx
}

func (m *MockAgentService_IMAMeasurementsServer) Send(resp *agent.IMAMeasurementsResponse) error {
	args := m.Called(resp)
	return args.Error(0)
}

func (m *MockAgentService_IMAMeasurementsServer) SetHeader(md metadata.MD) error {
	args := m.Called(md)
	return args.Error(0)
}

func TestNewServer(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	grpcServer, ok := server.(*grpcServer)
	assert.True(t, ok)
	assert.NotNil(t, grpcServer.handlers)
	assert.Len(t, grpcServer.handlers, 6) // Should have 6 handlers

	// Check that all expected handlers are present
	expectedHandlers := []string{"algo", "data", "result", "attestation", "imaMeasurements", "attestationToken"}
	for _, handler := range expectedHandlers {
		assert.Contains(t, grpcServer.handlers, handler)
		assert.NotNil(t, grpcServer.handlers[handler])
	}
}

func TestAlgo(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	mockStream := &MockAgentService_AlgoServer{ctx: context.Background()}
	mockStream.On("Recv").Return(&agent.AlgoRequest{Algorithm: []byte("algo"), Requirements: []byte("req")}, nil).Once()
	mockStream.On("Recv").Return(&agent.AlgoRequest{}, io.EOF).Once()
	mockStream.On("SendAndClose", &agent.AlgoResponse{}).Return(nil).Once()

	mockService.On("Algo", context.Background(), agent.Algorithm{Algorithm: []byte("algo"), Requirements: []byte("req")}).Return(nil)

	err := server.Algo(mockStream)
	assert.NoError(t, err)

	mockStream.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

func TestAlgoWithMultipleChunks(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	mockStream := &MockAgentService_AlgoServer{ctx: context.Background()}
	mockStream.On("Recv").Return(&agent.AlgoRequest{Algorithm: []byte("algo"), Requirements: []byte("req")}, nil).Once()
	mockStream.On("Recv").Return(&agent.AlgoRequest{Algorithm: []byte("2"), Requirements: []byte("2")}, nil).Once()
	mockStream.On("Recv").Return(&agent.AlgoRequest{}, io.EOF).Once()
	mockStream.On("SendAndClose", &agent.AlgoResponse{}).Return(nil).Once()

	mockService.On("Algo", context.Background(), agent.Algorithm{Algorithm: []byte("algo2"), Requirements: []byte("req2")}).Return(nil)

	err := server.Algo(mockStream)
	assert.NoError(t, err)

	mockStream.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

func TestData(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	mockStream := &MockAgentService_DataServer{ctx: context.Background()}
	mockStream.On("Recv").Return(&agent.DataRequest{Dataset: []byte("data"), Filename: "test.txt"}, nil).Once()
	mockStream.On("Recv").Return(&agent.DataRequest{}, io.EOF).Once()
	mockStream.On("SendAndClose", &agent.DataResponse{}).Return(nil).Once()

	mockService.On("Data", context.Background(), agent.Dataset{Dataset: []byte("data"), Filename: "test.txt"}).Return(nil)

	err := server.Data(mockStream)
	assert.NoError(t, err)

	mockStream.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

func TestResult(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	resultData := []byte("result data")
	mockStream := &MockAgentService_ResultServer{ctx: context.Background()}

	// Mock the SetHeader call
	mockStream.On("SetHeader", mock.AnythingOfType("metadata.MD")).Return(nil).Once()

	// Mock the Send call - it should be called with the result data
	mockStream.On("Send", mock.MatchedBy(func(resp *agent.ResultResponse) bool {
		return len(resp.File) > 0
	})).Return(nil).Once()

	mockService.On("Result", mock.Anything).Return(resultData, nil)

	err := server.Result(&agent.ResultRequest{}, mockStream)
	assert.NoError(t, err)

	mockStream.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

func TestAttestation(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	attestationData := []byte("attestation data")
	mockStream := &MockAgentService_AttestationServer{ctx: context.Background()}

	// Mock the SetHeader call
	mockStream.On("SetHeader", mock.AnythingOfType("metadata.MD")).Return(nil).Once()

	// Mock the Send call
	mockStream.On("Send", mock.MatchedBy(func(resp *agent.AttestationResponse) bool {
		return len(resp.File) > 0
	})).Return(nil).Once()

	reportData := [quoteprovider.Nonce]byte{}
	vtpmNonce := [vtpm.Nonce]byte{}
	attestationType := attestation.SNP
	mockService.On("Attestation", mock.Anything, reportData, vtpmNonce, attestationType).Return(attestationData, nil)

	err := server.Attestation(&agent.AttestationRequest{TeeNonce: reportData[:], Type: int32(attestationType)}, mockStream)
	assert.NoError(t, err)

	mockService.AssertExpectations(t)
	mockStream.AssertExpectations(t)
}

func TestIMAMeasurements(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	imaData := []byte("ima data")
	pcr10Data := []byte("pcr10 data")

	mockStream := &MockAgentService_IMAMeasurementsServer{ctx: context.Background()}

	// Mock the SetHeader call
	mockStream.On("SetHeader", mock.AnythingOfType("metadata.MD")).Return(nil).Once()

	// Mock the Send call
	mockStream.On("Send", mock.MatchedBy(func(resp *agent.IMAMeasurementsResponse) bool {
		return len(resp.File) > 0 || len(resp.Pcr10) > 0
	})).Return(nil).Once()

	mockService.On("IMAMeasurements", mock.Anything).Return(imaData, pcr10Data, nil)

	err := server.IMAMeasurements(&agent.IMAMeasurementsRequest{}, mockStream)
	assert.NoError(t, err)

	mockService.AssertExpectations(t)
	mockStream.AssertExpectations(t)
}

func TestAttestationToken(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	attestationData := []byte("attestation token data")
	vtpmNonce := [vtpm.Nonce]byte{}
	attestationType := attestation.SNP

	mockService.On("AzureAttestationToken", mock.Anything, vtpmNonce, attestationType).Return(attestationData, nil)

	resp, err := server.AzureAttestationToken(context.Background(), &agent.AttestationTokenRequest{
		TokenNonce: vtpmNonce[:],
		Type:       int32(attestationType),
	})

	assert.NoError(t, err)
	assert.Equal(t, attestationData, resp.File)

	mockService.AssertExpectations(t)
}

func TestValidateNonce(t *testing.T) {
	tests := []struct {
		name        string
		nonce       []byte
		maxLen      int
		shouldError bool
		expectedErr error
	}{
		{
			name:        "valid TEE nonce",
			nonce:       make([]byte, quoteprovider.Nonce),
			maxLen:      quoteprovider.Nonce,
			shouldError: false,
		},
		{
			name:        "valid vTPM nonce",
			nonce:       make([]byte, vtpm.Nonce),
			maxLen:      vtpm.Nonce,
			shouldError: false,
		},
		{
			name:        "TEE nonce too long",
			nonce:       make([]byte, quoteprovider.Nonce+1),
			maxLen:      quoteprovider.Nonce,
			shouldError: true,
			expectedErr: ErrTEENonceLength,
		},
		{
			name:        "vTPM nonce too long",
			nonce:       make([]byte, vtpm.Nonce+1),
			maxLen:      vtpm.Nonce,
			shouldError: true,
			expectedErr: ErrVTPMNonceLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.maxLen == quoteprovider.Nonce {
				var target [quoteprovider.Nonce]byte
				err := validateNonce(tt.nonce, tt.maxLen, &target)
				if tt.shouldError {
					assert.Error(t, err)
					assert.Equal(t, tt.expectedErr, err)
				} else {
					assert.NoError(t, err)
				}
			} else {
				var target [vtpm.Nonce]byte
				err := validateNonce(tt.nonce, tt.maxLen, &target)
				if tt.shouldError {
					assert.Error(t, err)
					assert.Equal(t, tt.expectedErr, err)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestDecodeAlgoRequest(t *testing.T) {
	req := &agent.AlgoRequest{Algorithm: []byte("algo"), Requirements: []byte("req")}
	decoded, err := decodeAlgoRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, algoReq{Algorithm: []byte("algo"), Requirements: []byte("req")}, decoded)
}

func TestEncodeAlgoResponse(t *testing.T) {
	encoded, err := encodeAlgoResponse(context.Background(), algoRes{})
	assert.NoError(t, err)
	assert.Equal(t, &agent.AlgoResponse{}, encoded)
}

func TestDecodeDataRequest(t *testing.T) {
	req := &agent.DataRequest{Dataset: []byte("data"), Filename: "test.txt"}
	decoded, err := decodeDataRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, dataReq{Dataset: []byte("data"), Filename: "test.txt"}, decoded)
}

func TestEncodeDataResponse(t *testing.T) {
	encoded, err := encodeDataResponse(context.Background(), dataRes{})
	assert.NoError(t, err)
	assert.Equal(t, &agent.DataResponse{}, encoded)
}

func TestDecodeResultRequest(t *testing.T) {
	decoded, err := decodeResultRequest(context.Background(), &agent.ResultRequest{})
	assert.NoError(t, err)
	assert.Equal(t, resultReq{}, decoded)
}

func TestEncodeResultResponse(t *testing.T) {
	encoded, err := encodeResultResponse(context.Background(), resultRes{File: []byte("result")})
	assert.NoError(t, err)
	assert.Equal(t, &agent.ResultResponse{File: []byte("result")}, encoded)
}

func TestDecodeAttestationRequest(t *testing.T) {
	teeNonce := make([]byte, quoteprovider.Nonce)
	vtpmNonce := make([]byte, vtpm.Nonce)

	req := &agent.AttestationRequest{
		TeeNonce:  teeNonce,
		VtpmNonce: vtpmNonce,
		Type:      int32(attestation.SNP),
	}

	decoded, err := decodeAttestationRequest(context.Background(), req)
	assert.NoError(t, err)

	decodedReq := decoded.(attestationReq)
	assert.Equal(t, attestation.SNP, decodedReq.AttType)
}

func TestDecodeAttestationRequestWithInvalidNonce(t *testing.T) {
	// Test with TEE nonce too long
	teeNonce := make([]byte, quoteprovider.Nonce+1)
	req := &agent.AttestationRequest{TeeNonce: teeNonce}

	_, err := decodeAttestationRequest(context.Background(), req)
	assert.Error(t, err)
	assert.Equal(t, ErrTEENonceLength, err)

	// Test with vTPM nonce too long
	vtpmNonce := make([]byte, vtpm.Nonce+1)
	req = &agent.AttestationRequest{VtpmNonce: vtpmNonce}

	_, err = decodeAttestationRequest(context.Background(), req)
	assert.Error(t, err)
	assert.Equal(t, ErrVTPMNonceLength, err)
}

func TestEncodeAttestationResponse(t *testing.T) {
	encoded, err := encodeAttestationResponse(context.Background(), attestationRes{File: []byte("attestation")})
	assert.NoError(t, err)
	assert.Equal(t, &agent.AttestationResponse{File: []byte("attestation")}, encoded)
}

func TestDecodeAttestationTokenRequest(t *testing.T) {
	tokenNonce := make([]byte, vtpm.Nonce)
	req := &agent.AttestationTokenRequest{
		TokenNonce: tokenNonce,
		Type:       int32(attestation.SNP),
	}

	_, err := decodeAttestationTokenRequest(context.Background(), req)
	assert.NoError(t, err)
}

func TestDecodeAttestationTokenRequestWithInvalidNonce(t *testing.T) {
	// Test with token nonce too long
	tokenNonce := make([]byte, vtpm.Nonce+1)
	req := &agent.AttestationTokenRequest{TokenNonce: tokenNonce}

	_, err := decodeAttestationTokenRequest(context.Background(), req)
	assert.Error(t, err)
	assert.Equal(t, ErrVTPMNonceLength, err)
}

func TestEncodeAttestationTokenResponse(t *testing.T) {
	encoded, err := encodeAttestationTokenResponse(context.Background(), fetchAttestationTokenRes{File: []byte("attestation")})
	assert.NoError(t, err)
	assert.Equal(t, &agent.AttestationTokenResponse{File: []byte("attestation")}, encoded)
}

func TestDecodeIMAMeasurementsRequest(t *testing.T) {
	decoded, err := decodeIMAMeasurementsRequest(context.Background(), &agent.IMAMeasurementsRequest{})
	assert.NoError(t, err)
	assert.Equal(t, imaMeasurementsReq{}, decoded)
}

func TestEncodeIMAMeasurementsResponse(t *testing.T) {
	encoded, err := encodeIMAMeasurementsResponse(context.Background(), imaMeasurementsRes{
		File:  []byte("ima"),
		PCR10: []byte("pcr10"),
	})
	assert.NoError(t, err)
	assert.Equal(t, &agent.IMAMeasurementsResponse{
		File:  []byte("ima"),
		Pcr10: []byte("pcr10"),
	}, encoded)
}

func TestAlgoWithStreamError(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	mockStream := &MockAgentService_AlgoServer{ctx: context.Background()}
	mockStream.On("Recv").Return(&agent.AlgoRequest{}, assert.AnError).Once()

	err := server.Algo(mockStream)
	assert.Error(t, err)

	mockStream.AssertExpectations(t)
}

func TestDataWithStreamError(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	mockStream := &MockAgentService_DataServer{ctx: context.Background()}
	mockStream.On("Recv").Return(&agent.DataRequest{}, assert.AnError).Once()

	err := server.Data(mockStream)
	assert.Error(t, err)

	mockStream.AssertExpectations(t)
}
