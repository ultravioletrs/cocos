package grpc

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/mocks"
	"google.golang.org/grpc"
)

// MockAgentService_AlgoServer is a mock for the agent.AgentService_AlgoServer interface
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

// MockAgentService_DataServer is a mock for the agent.AgentService_DataServer interface
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

// MockAgentService_ResultServer is a mock for the agent.AgentService_ResultServer interface
type MockAgentService_ResultServer struct {
	grpc.ServerStream
	mock.Mock
	ctx context.Context
}

func (m *MockAgentService_ResultServer) Context() context.Context {
	return m.ctx
}

func (m *MockAgentService_ResultServer) Send(resp *agent.ResultResponse) error {
	args := m.Called(resp)
	return args.Error(0)
}

// TestAlgo tests the Algo method of grpcServer
func TestAlgo(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	mockStream := &MockAgentService_AlgoServer{ctx: context.Background()}
	mockStream.On("Recv").Return(&agent.AlgoRequest{Algorithm: []byte("algo"), Requirements: []byte("req")}, nil).Once()
	mockStream.On("Recv").Return(&agent.AlgoRequest{}, io.EOF)
	mockStream.On("SendAndClose", &agent.AlgoResponse{}).Return(nil)

	mockService.On("Algo", context.Background(), agent.Algorithm{Algorithm: []byte("algo"), Requirements: []byte("req")}).Return(nil)

	err := server.Algo(mockStream)
	assert.NoError(t, err)

	mockStream.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestData tests the Data method of grpcServer
func TestData(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	mockStream := &MockAgentService_DataServer{ctx: context.Background()}
	mockStream.On("Recv").Return(&agent.DataRequest{Dataset: []byte("data"), Filename: "test.txt"}, nil).Once()
	mockStream.On("Recv").Return(&agent.DataRequest{}, io.EOF)
	mockStream.On("SendAndClose", &agent.DataResponse{}).Return(nil)

	mockService.On("Data", context.Background(), agent.Dataset{Dataset: []byte("data"), Filename: "test.txt"}).Return(nil)

	err := server.Data(mockStream)
	assert.NoError(t, err)

	mockStream.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestResult tests the Result method of grpcServer
func TestResult(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	mockStream := &MockAgentService_ResultServer{ctx: context.Background()}
	mockService.On("Result", mock.Anything).Return([]byte("result data"), nil)
	mockStream.On("Send", mock.AnythingOfType("*agent.ResultResponse")).Return(nil)

	err := server.Result(&agent.ResultRequest{}, mockStream)
	assert.NoError(t, err)

	mockStream.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestAttestation tests the Attestation method of grpcServer
func TestAttestation(t *testing.T) {
	mockService := new(mocks.Service)
	server := NewServer(mockService)

	reportData := [agent.ReportDataSize]byte{}
	mockService.On("Attestation", mock.Anything, reportData).Return([]byte("attestation data"), nil)

	resp, err := server.Attestation(context.Background(), &agent.AttestationRequest{ReportData: reportData[:]})
	assert.NoError(t, err)
	assert.Equal(t, []byte("attestation data"), resp.File)

	mockService.AssertExpectations(t)
}

// Test decode and encode functions
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
	reportData := [agent.ReportDataSize]byte{}
	req := &agent.AttestationRequest{ReportData: reportData[:]}
	decoded, err := decodeAttestationRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, attestationReq{ReportData: reportData}, decoded)
}

func TestEncodeAttestationResponse(t *testing.T) {
	encoded, err := encodeAttestationResponse(context.Background(), attestationRes{File: []byte("attestation")})
	assert.NoError(t, err)
	assert.Equal(t, &agent.AttestationResponse{File: []byte("attestation")}, encoded)
}
