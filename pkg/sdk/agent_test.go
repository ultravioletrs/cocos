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
	"os"
	"testing"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/ultravioletrs/cocos/pkg/sdk"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

var (
	algoPath = "../../test/manual/algo/lin_reg.py"
	dataPath = "../../test/manual/data/iris.csv"

	errInappropriateIoctl = errors.New("failed to get terminal width: inappropriate ioctl for device")
)

func TestAlgo(t *testing.T) {
	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(client)
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
		{
			name: "gRPC client error",
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
				UserKey:   algoProvider1PubKey,
			},
			userKey: algoProvider1Key,
			err:     errors.New("gRPC client error"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svcCall := svc.On("Algo", mock.Anything, mock.Anything).Return(tc.err)

			algo, err := os.CreateTemp("", "algo")
			require.NoError(t, err)
			defer os.Remove(algo.Name())

			_, err = algo.Write(algorithm.Algorithm)
			require.NoError(t, err)

			err = algo.Close()
			require.NoError(t, err)

			algo, err = os.Open(algo.Name())
			require.NoError(t, err)

			err = sdk.Algo(context.Background(), algo, nil, tc.userKey)

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
	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(client)

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

			data, err := os.CreateTemp("", "data")
			require.NoError(t, err)

			_, err = data.Write(dataset.Dataset)
			require.NoError(t, err)

			err = data.Close()
			require.NoError(t, err)

			data, err = os.Open(data.Name())
			require.NoError(t, err)

			err = sdk.Data(context.Background(), data, tc.data.Filename, tc.userKey)

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
	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(client)

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
				File: []byte{},
			},
			svcRes: nil,
			err:    agent.ErrResultsNotReady,
		},
		{
			name:    "All manifest items received",
			userKey: resultConsumer1Key,
			response: &agent.ResultResponse{
				File: []byte{},
			},
			svcRes: nil,
			err:    agent.ErrAllManifestItemsReceived,
		},
		{
			name:    "Undeclared consumer",
			userKey: resultConsumer1Key,
			response: &agent.ResultResponse{
				File: []byte{},
			},
			svcRes: nil,
			err:    agent.ErrUndeclaredConsumer,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svcCall := svc.On("Result", mock.Anything, mock.Anything).Return(tc.svcRes, tc.err)

			resultFile, err := os.CreateTemp("", "result")
			require.NoError(t, err)

			t.Cleanup(func() {
				os.Remove(resultFile.Name())
			})

			err = sdk.Result(context.Background(), tc.userKey, resultFile)

			require.NoError(t, resultFile.Close())

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, but got: %v", err)
			}

			if tc.err != nil {
				if st.Message() != tc.err.Error() {
					t.Errorf("%s: Expected error message %q, but got %q", tc.name, tc.err.Error(), st.Message())
				}
			}

			res, err := os.ReadFile(resultFile.Name())
			require.NoError(t, err)

			assert.Equal(t, tc.response.File, res, tc.name)

			svcCall.Unset()
		})
	}
}

func TestAttestation(t *testing.T) {
	resultConsumerKey, _ := generateKeys(t, "rsa")
	resultConsumer1Key, _ := generateKeys(t, "ed25519")

	reportData := make([]byte, 64)
	nonce := make([]byte, 64)
	report := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
	}

	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(client)

	_, err = rand.Read(reportData)
	require.NoError(t, err)

	cases := []struct {
		name       string
		userKey    any
		reportData [quoteprovider.Nonce]byte
		nonce      [vtpm.Nonce]byte
		response   *agent.AttestationResponse
		svcRes     []byte
		err        error
	}{
		{
			name:       "fetch attestation report successfully",
			userKey:    resultConsumerKey,
			reportData: [quoteprovider.Nonce]byte(reportData),
			nonce:      [vtpm.Nonce]byte(nonce),
			response: &agent.AttestationResponse{
				File: report,
			},
			svcRes: report,
			err:    nil,
		},
		{
			name:       "fetch attestation report with different key type",
			userKey:    resultConsumer1Key,
			reportData: [quoteprovider.Nonce]byte(reportData),
			nonce:      [vtpm.Nonce]byte(nonce),
			response: &agent.AttestationResponse{
				File: report,
			},
			svcRes: report,
			err:    nil,
		},
		{
			name:       "failed to fetch attestation report",
			userKey:    resultConsumerKey,
			reportData: [quoteprovider.Nonce]byte(reportData),
			nonce:      [vtpm.Nonce]byte(nonce),
			response: &agent.AttestationResponse{
				File: []byte{},
			},
			err: nil,
		},
		{
			name:       "invalid report data",
			userKey:    resultConsumerKey,
			reportData: [quoteprovider.Nonce]byte{},
			nonce:      [vtpm.Nonce]byte(nonce),
			response: &agent.AttestationResponse{
				File: []byte{},
			},
			svcRes: nil,
			err:    errors.New("invalid report data"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svcCall := svc.On("Attestation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.svcRes, tc.err)

			file, err := os.CreateTemp("", "attestation")
			require.NoError(t, err)

			t.Cleanup(func() {
				os.Remove(file.Name())
			})

			err = sdk.Attestation(context.Background(), tc.reportData, tc.nonce, 0, file)

			require.NoError(t, file.Close())

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, but got: %v", err)
			}

			if tc.err != nil {
				if st.Message() != tc.err.Error() {
					t.Errorf("%s: Expected error message %q, but got %q", tc.name, tc.err.Error(), st.Message())
				}
			}

			res, err := os.ReadFile(file.Name())
			require.NoError(t, err)

			assert.Equal(t, tc.response.File, res, tc.name)

			svcCall.Unset()
		})
	}
}

func TestAttestationResult(t *testing.T) {
	reportData := make([]byte, 64)
	nonce := make([]byte, 64)
	report := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
	}

	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(client)

	_, err = rand.Read(reportData)
	require.NoError(t, err)

	cases := []struct {
		name     string
		nonce    [vtpm.Nonce]byte
		response *agent.AttestationResultResponse
		svcRes   []byte
		err      error
	}{
		{
			name:  "fetch attestation report successfully",
			nonce: [vtpm.Nonce]byte(nonce),
			response: &agent.AttestationResultResponse{
				File: report,
			},
			svcRes: report,
			err:    nil,
		},
		{
			name:  "failed to fetch attestation report",
			nonce: [vtpm.Nonce]byte(nonce),
			response: &agent.AttestationResultResponse{
				File: []byte{},
			},
			err: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svcCall := svc.On("AttestationResult", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.svcRes, tc.err)

			file, err := os.CreateTemp("", "attestation")
			require.NoError(t, err)

			t.Cleanup(func() {
				os.Remove(file.Name())
			})

			err = sdk.AttestationResult(context.Background(), tc.nonce, 0, file)

			require.NoError(t, file.Close())

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, but got: %v", err)
			}

			if tc.err != nil {
				if st.Message() != tc.err.Error() {
					t.Errorf("%s: Expected error message %q, but got %q", tc.name, tc.err.Error(), st.Message())
				}
			}

			res, err := os.ReadFile(file.Name())
			require.NoError(t, err)

			assert.Equal(t, tc.response.File, res, tc.name)

			svcCall.Unset()
		})
	}
}

func TestIMAMeasurements(t *testing.T) {
	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := agent.NewAgentServiceClient(conn)

	sdk := sdk.NewAgentSDK(client)

	response := &agent.IMAMeasurementsResponse{
		File: []byte{
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
		},
	}

	cases := []struct {
		name     string
		response *agent.IMAMeasurementsResponse
		svcRes   []byte
		err      error
	}{
		{
			name:     "fetch IMA measurements successfully",
			response: response,
			svcRes:   response.File,
			err:      nil,
		},
		{
			name:     "failed to fetch IMA measurements",
			response: &agent.IMAMeasurementsResponse{File: []byte{}},
			svcRes:   nil,
			err:      errors.New("failed to fetch IMA measurements"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svcCall := svc.On("IMAMeasurements", mock.Anything).Return(tc.svcRes, tc.svcRes, tc.err)

			file, err := os.CreateTemp("", "ima_measurements")
			require.NoError(t, err)

			t.Cleanup(func() {
				os.Remove(file.Name())
			})

			_, err = sdk.IMAMeasurements(context.Background(), file)

			require.NoError(t, file.Close())

			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, but got: %v", err)
			}

			if tc.err != nil {
				if st.Message() != tc.err.Error() {
					t.Errorf("%s: Expected error message %q, but got %q", tc.name, tc.err.Error(), st.Message())
				}
			}

			res, err := os.ReadFile(file.Name())
			require.NoError(t, err)
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
