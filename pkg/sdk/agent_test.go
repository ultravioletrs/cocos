// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"testing"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/sdk"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var (
	algoPath = "../../test/manual/algo/lin_reg.py"
	dataPath = "../../test/manual/data/iris.csv"

	errInappropriateIoctl = errors.New("failed to get terminal width: inappropriate ioctl for device")
)

func TestAlgo(t *testing.T) {
	logger, err := mglog.New(os.Stdout, "info")
	require.NoError(t, err)

	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(logger, client)
	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	algorithmProviderKey, algorithmProviderPubKey := generateKeys(t, "ed25519")

	algoProvider1Key, algoProvider1PubKey := generateKeys(t, "ed25519")

	algorithm := agent.Algorithm{
		Algorithm: algo,
		Hash:      algoHash,
		UserKey:   algorithmProviderPubKey,
	}

	cases := []struct {
		name    string
		err     error
		algo    agent.Algorithm
		userKey any
	}{
		{
			name:    "Test Algo successfully",
			algo:    algorithm,
			userKey: algorithmProviderKey,
			err:     nil,
		},
		{
			name: "hash mismatch",
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      sha3.Sum256([]byte("algo")),
				UserKey:   algoProvider1PubKey,
			},
			userKey: algoProvider1Key,
			err:     errInappropriateIoctl,
		},
		{
			name: "no manifest expected",
			algo: agent.Algorithm{
				Algorithm: algo,
				UserKey:   algorithmProviderPubKey,
				Hash:      algoHash,
			},
			userKey: algorithmProviderKey,
			err:     errInappropriateIoctl,
		},
		{
			name: "state not ready",
			algo: agent.Algorithm{
				Algorithm: algo,
				UserKey:   algorithmProviderPubKey,
				Hash:      algoHash,
			},
			userKey: algorithmProviderKey,
			err:     errInappropriateIoctl,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svcCall := svc.On("Algo", mock.Anything, mock.Anything).Return(tc.err)
			err = sdk.Algo(context.Background(), tc.algo, tc.userKey)

			st, _ := status.FromError(err)

			if tc.err != nil {
				if st.Message() != tc.err.Error() {
					t.Errorf("%s : Expected error message %q, but got %q", tc.name, tc.err.Error(), st.Message())
				}
			}

			svcCall.Unset()
		})
	}
}

func TestData(t *testing.T) {
	logger, err := mglog.New(os.Stdout, "info")
	require.NoError(t, err)

	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(logger, client)

	data, err := os.ReadFile(dataPath)
	require.NoError(t, err)

	dataHash := sha3.Sum256(data)

	dataProviderKey, dataProviderPubKey := generateKeys(t, "ecdsa")

	dataProvider1Key, dataProvider1PubKey := generateKeys(t, "ed25519")

	dataset := agent.Dataset{
		Hash:    dataHash,
		Dataset: data,
		UserKey: dataProviderPubKey,
	}

	cases := []struct {
		name    string
		data    agent.Dataset
		userKey any
		svcErr  error
	}{
		{
			name:    "Test data successfully",
			data:    dataset,
			userKey: dataProviderKey,
		},
		{
			name: "undeclared dataset",
			data: agent.Dataset{
				Dataset: data,
				UserKey: dataProvider1PubKey,
				Hash:    dataHash,
			},
			userKey: dataProvider1Key,
			svcErr:  errInappropriateIoctl,
		},
		{
			name: "hash mismatch",
			data: agent.Dataset{
				Dataset: data,
				UserKey: dataProvider1PubKey,
				Hash:    dataHash,
			},
			userKey: dataProvider1Key,
			svcErr:  errInappropriateIoctl,
		},
		{
			name: "all manifest items received",
			data: agent.Dataset{
				Dataset: data,
				UserKey: dataProvider1PubKey,
				Hash:    dataHash,
			},
			userKey: dataProvider1Key,
			svcErr:  errInappropriateIoctl,
		},
		{
			name: "missing dataset file",
			data: agent.Dataset{
				UserKey: dataProvider1PubKey,
				Hash:    dataHash,
			},
			userKey: dataProvider1Key,
			svcErr:  errors.New("dataset CSV file is required"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataCall := svc.On("Data", mock.Anything, mock.Anything).Return(tc.svcErr)

			err = sdk.Data(context.Background(), tc.data, tc.userKey)

			st, _ := status.FromError(err)

			if tc.svcErr != nil {
				if st.Message() != tc.svcErr.Error() {
					t.Errorf("%s: Expected error message %q, but got %q", tc.name, tc.svcErr.Error(), st.Message())
				}
			}

			dataCall.Unset()
		})
	}
}

func TestResult(t *testing.T) {
	logger, err := mglog.New(os.Stdout, "info")
	require.NoError(t, err)

	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(logger, client)

	resultConsumerKey, _ := generateKeys(t, "ecdsa")
	resultConsumer1Key, _ := generateKeys(t, "ed25519")

	response := &agent.ResultResponse{
		File: []byte{
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
		},
	}

	cases := []struct {
		name     string
		userKey  any
		response *agent.ResultResponse
		svcRes   []byte
		err      error
	}{
		{
			name:     "Test result successfully",
			userKey:  resultConsumerKey,
			response: response,
			svcRes:   response.File,
			err:      nil,
		},
		{
			name:     "Test result successfully with ed25519 key type",
			userKey:  resultConsumer1Key,
			response: response,
			svcRes:   response.File,
			err:      nil,
		},
		{
			name:    "Results not ready",
			userKey: resultConsumer1Key,
			response: &agent.ResultResponse{
				File: []byte(nil),
			},
			svcRes: nil,
			err:    agent.ErrResultsNotReady,
		},
		{
			name:    "All manifest items received",
			userKey: resultConsumer1Key,
			response: &agent.ResultResponse{
				File: []byte(nil),
			},
			svcRes: nil,
			err:    agent.ErrAllManifestItemsReceived,
		},
		{
			name:    "Undeclared consumer",
			userKey: resultConsumer1Key,
			response: &agent.ResultResponse{
				File: []byte(nil),
			},
			svcRes: nil,
			err:    agent.ErrUndeclaredConsumer,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svcCall := svc.On("Result", mock.Anything, mock.Anything).Return(tc.svcRes, tc.err)
			res, err := sdk.Result(context.Background(), tc.userKey)

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, but got: %v", err)
			}

			if tc.err != nil {
				if st.Message() != tc.err.Error() {
					t.Errorf("%s: Expected error message %q, but got %q", tc.name, tc.err.Error(), st.Message())
				}
			}
			assert.Equal(t, tc.response.File, res, tc.name)

			svcCall.Unset()
		})
	}
}

func TestAttestation(t *testing.T) {
	logger, err := mglog.New(os.Stdout, "info")
	require.NoError(t, err)

	resultConsumerKey, _ := generateKeys(t, "rsa")
	resultConsumer1Key, _ := generateKeys(t, "ed25519")

	reportData := make([]byte, 64)
	report := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
	}

	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(logger, client)

	_, err = rand.Read(reportData)
	require.NoError(t, err)

	cases := []struct {
		name       string
		userKey    any
		reportData [agent.ReportDataSize]byte
		response   *agent.AttestationResponse
		svcRes     []byte
		err        error
	}{
		{
			name:       "fetch attestation report successfully",
			userKey:    resultConsumerKey,
			reportData: [agent.ReportDataSize]byte(reportData),
			response: &agent.AttestationResponse{
				File: report,
			},
			svcRes: report,
			err:    nil,
		},
		{
			name:       "fetch attestation report with different key type",
			userKey:    resultConsumer1Key,
			reportData: [agent.ReportDataSize]byte(reportData),
			response: &agent.AttestationResponse{
				File: report,
			},
			svcRes: report,
			err:    nil,
		},
		{
			name:       "failed to fetch attestation report",
			userKey:    resultConsumerKey,
			reportData: [agent.ReportDataSize]byte(reportData),
			response: &agent.AttestationResponse{
				File: nil,
			},
			err: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svcCall := svc.On("Attestation", mock.Anything, mock.Anything).Return(tc.svcRes, tc.err)

			res, err := sdk.Attestation(context.Background(), tc.reportData)

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, but got: %v", err)
			}

			if tc.err != nil {
				if st.Message() != tc.err.Error() {
					t.Errorf("%s: Expected error message %q, but got %q", tc.name, tc.err.Error(), st.Message())
				}
			}

			assert.Equal(t, tc.response.File, res, tc.name)

			svcCall.Unset()
		})
	}
}

func generateKeys(t *testing.T, keyType string) (priv any, pub []byte) {
	switch keyType {
	case "ecdsa":
		privEcdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privEcdsaKey.PublicKey)
		require.NoError(t, err)
		return privEcdsaKey, pubKeyBytes

	case "ed25519":
		pubEd25519Key, privEd25519Key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		pubKey, err := x509.MarshalPKIXPublicKey(pubEd25519Key)
		require.NoError(t, err)
		return privEd25519Key, pubKey

	default:
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		require.NoError(t, err)
		return privKey, pubKeyBytes
	}
}
