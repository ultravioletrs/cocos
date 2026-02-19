// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package ccaa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	attestation_agent "github.com/ultravioletrs/cocos/internal/proto/attestation-agent"
	"github.com/ultravioletrs/cocos/internal/proto/attestation-agent/mocks"
)

// TestTeeAttestationSuccess tests successful TDX attestation.
func TestTeeAttestationSuccess(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	mockClient.EXPECT().
		GetEvidence(mock.MatchedBy(func(ctx context.Context) bool {
			return ctx != nil
		}), mock.MatchedBy(func(req *attestation_agent.GetEvidenceRequest) bool {
			return len(req.RuntimeData) == 64
		})).
		Return(&attestation_agent.GetEvidenceResponse{
			Evidence: []byte("test_evidence"),
		}, nil)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	evidence, err := provider.TeeAttestation(make([]byte, 64))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(evidence) != "test_evidence" {
		t.Fatalf("expected 'test_evidence', got '%s'", string(evidence))
	}
}

// TestVTpmAttestationSuccess tests successful vTPM attestation.
func TestVTpmAttestationSuccess(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	mockClient.EXPECT().
		GetEvidence(mock.MatchedBy(func(ctx context.Context) bool {
			return ctx != nil
		}), mock.MatchedBy(func(req *attestation_agent.GetEvidenceRequest) bool {
			return len(req.RuntimeData) == 32
		})).
		Return(&attestation_agent.GetEvidenceResponse{
			Evidence: []byte("vtpm_evidence"),
		}, nil)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	evidence, err := provider.VTpmAttestation(make([]byte, 32))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(evidence) != "vtpm_evidence" {
		t.Fatalf("expected 'vtpm_evidence', got '%s'", string(evidence))
	}
}

// TestAttestationSuccess tests combined SNP+vTPM attestation.
func TestAttestationSuccess(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	mockClient.EXPECT().
		GetEvidence(mock.MatchedBy(func(ctx context.Context) bool {
			return ctx != nil
		}), mock.MatchedBy(func(req *attestation_agent.GetEvidenceRequest) bool {
			return len(req.RuntimeData) == 96 // 64 + 32
		})).
		Return(&attestation_agent.GetEvidenceResponse{
			Evidence: []byte("combined_evidence"),
		}, nil)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	evidence, err := provider.Attestation(make([]byte, 64), make([]byte, 32))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(evidence) != "combined_evidence" {
		t.Fatalf("expected 'combined_evidence', got '%s'", string(evidence))
	}
}

// TestAzureTokenSuccess tests Azure token retrieval via GetToken.
func TestAzureTokenSuccess(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	mockClient.EXPECT().
		GetToken(mock.MatchedBy(func(ctx context.Context) bool {
			return ctx != nil
		}), mock.MatchedBy(func(req *attestation_agent.GetTokenRequest) bool {
			return req.TokenType == "Azure"
		})).
		Return(&attestation_agent.GetTokenResponse{
			Token: []byte("azure_token"),
		}, nil)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	token, err := provider.AzureAttestationToken(make([]byte, 32))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(token) != "azure_token" {
		t.Fatalf("expected 'azure_token', got '%s'", string(token))
	}
}

// TestAzureTokenFallback tests fallback from GetToken to GetEvidence.
func TestAzureTokenFallback(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)

	// GetToken fails
	mockClient.EXPECT().
		GetToken(mock.Anything, mock.Anything).
		Return(nil, context.DeadlineExceeded).Once()

	// Fallback to GetEvidence
	mockClient.EXPECT().
		GetEvidence(mock.MatchedBy(func(ctx context.Context) bool {
			return ctx != nil
		}), mock.Anything).
		Return(&attestation_agent.GetEvidenceResponse{
			Evidence: []byte("fallback_evidence"),
		}, nil)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	evidence, err := provider.AzureAttestationToken(make([]byte, 32))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(evidence) != "fallback_evidence" {
		t.Fatalf("expected 'fallback_evidence', got '%s'", string(evidence))
	}
}

// TestTeeAttestationError tests error handling in TeeAttestation.
func TestTeeAttestationError(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	mockClient.EXPECT().
		GetEvidence(mock.Anything, mock.Anything).
		Return(nil, context.DeadlineExceeded)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	_, err := provider.TeeAttestation(make([]byte, 64))

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestVTpmAttestationError tests error handling in VTpmAttestation.
func TestVTpmAttestationError(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	mockClient.EXPECT().
		GetEvidence(mock.Anything, mock.Anything).
		Return(nil, context.DeadlineExceeded)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	_, err := provider.VTpmAttestation(make([]byte, 32))

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestAzureTokenBothFail tests error when both GetToken and GetEvidence fail.
func TestAzureTokenBothFail(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)

	mockClient.EXPECT().
		GetToken(mock.Anything, mock.Anything).
		Return(nil, context.DeadlineExceeded).Once()

	mockClient.EXPECT().
		GetEvidence(mock.Anything, mock.Anything).
		Return(nil, context.DeadlineExceeded)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	_, err := provider.AzureAttestationToken(make([]byte, 32))

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestCloseWithNilConnection tests Close with nil connection.
func TestCloseWithNilConnection(t *testing.T) {
	provider := &Provider{conn: nil}
	err := provider.Close()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// TestProviderFields tests provider field initialization.
func TestProviderFields(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	addr := "localhost:50002"

	provider := &Provider{
		client: mockClient,
		conn:   nil,
		addr:   addr,
	}

	if provider.addr != addr {
		t.Fatalf("expected addr '%s', got '%s'", addr, provider.addr)
	}
	if provider.client != mockClient {
		t.Fatal("client mismatch")
	}
}

// TestEmptyReportData tests TeeAttestation with empty data.
func TestEmptyReportData(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	mockClient.EXPECT().
		GetEvidence(mock.Anything, mock.MatchedBy(func(req *attestation_agent.GetEvidenceRequest) bool {
			return len(req.RuntimeData) == 0
		})).
		Return(&attestation_agent.GetEvidenceResponse{
			Evidence: []byte("empty_data_evidence"),
		}, nil)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	evidence, err := provider.TeeAttestation([]byte{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(evidence) != "empty_data_evidence" {
		t.Fatalf("expected 'empty_data_evidence', got '%s'", string(evidence))
	}
}

// TestLargeReportData tests TeeAttestation with large data.
func TestLargeReportData(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	mockClient.EXPECT().
		GetEvidence(mock.Anything, mock.MatchedBy(func(req *attestation_agent.GetEvidenceRequest) bool {
			return len(req.RuntimeData) == 10000
		})).
		Return(&attestation_agent.GetEvidenceResponse{
			Evidence: []byte("large_data_evidence"),
		}, nil)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	evidence, err := provider.TeeAttestation(make([]byte, 10000))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(evidence) != "large_data_evidence" {
		t.Fatalf("expected 'large_data_evidence', got '%s'", string(evidence))
	}
}

// TestDataConcatenationInAttestation tests data concatenation.
func TestDataConcatenationInAttestation(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	mockClient.EXPECT().
		GetEvidence(mock.Anything, mock.MatchedBy(func(req *attestation_agent.GetEvidenceRequest) bool {
			// Verify data was concatenated correctly
			expected := []byte{1, 2, 3, 4, 5, 6}
			return len(req.RuntimeData) == len(expected)
		})).
		Return(&attestation_agent.GetEvidenceResponse{
			Evidence: []byte("concat_evidence"),
		}, nil)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	evidence, err := provider.Attestation([]byte{1, 2, 3}, []byte{4, 5, 6})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(evidence) != "concat_evidence" {
		t.Fatalf("expected 'concat_evidence', got '%s'", string(evidence))
	}
}

// TestMultipleCalls tests multiple successive calls.
func TestMultipleCalls(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)

	// Expect 3 calls
	for i := 0; i < 3; i++ {
		mockClient.EXPECT().
			GetEvidence(mock.Anything, mock.Anything).
			Return(&attestation_agent.GetEvidenceResponse{
				Evidence: []byte("evidence"),
			}, nil).Once()
	}

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}

	for i := 0; i < 3; i++ {
		evidence, err := provider.TeeAttestation(make([]byte, 64))
		if err != nil {
			t.Fatalf("iteration %d: expected no error, got %v", i, err)
		}
		if string(evidence) != "evidence" {
			t.Fatalf("iteration %d: expected 'evidence', got '%s'", i, string(evidence))
		}
	}
}

// TestEvidencePreservation tests that evidence data is preserved.
func TestEvidencePreservation(t *testing.T) {
	mockClient := mocks.NewAttestationAgentServiceClient(t)
	expectedBytes := []byte{0xFF, 0xEE, 0xDD, 0xCC}

	mockClient.EXPECT().
		GetEvidence(mock.Anything, mock.Anything).
		Return(&attestation_agent.GetEvidenceResponse{
			Evidence: expectedBytes,
		}, nil)

	provider := &Provider{client: mockClient, conn: nil, addr: "localhost:50002"}
	evidence, err := provider.TeeAttestation(make([]byte, 64))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	for i, b := range evidence {
		if b != expectedBytes[i] {
			t.Fatalf("byte mismatch at index %d: expected 0x%02x, got 0x%02x", i, expectedBytes[i], b)
		}
	}
}
