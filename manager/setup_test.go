// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/ultravioletrs/cocos/manager"
	managergrpc "github.com/ultravioletrs/cocos/manager/api/grpc"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

const (
	bufSize    = 1024 * 1024
	keyBitSize = 4096
)

var (
	lis         *bufconn.Listener
	algoPath    = "../test/manual/algo/lin_reg.py"
	dataPath    = "../test/manual/data/iris.csv"
	attestedTLS = false
)

type svc struct {
	logger *slog.Logger
	t      *testing.T
}

func TestMain(m *testing.M) {
	logger := mglog.NewMock()

	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()

	manager.RegisterManagerServiceServer(s, managergrpc.NewServer(make(chan *manager.ClientStreamMessage, 1), &svc{logger: logger}))
	go func() {
		if err := s.Serve(lis); err != nil {
			panic(err)
		}
	}()

	code := m.Run()

	s.Stop()
	lis.Close()
	os.Exit(code)
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func (s *svc) Run(ctx context.Context, ipAddress string, sendMessage managergrpc.SendFunc, authInfo credentials.AuthInfo) {
	privKey, err := rsa.GenerateKey(rand.Reader, keyBitSize)
	if err != nil {
		s.t.Fatalf("Error generating public key: %v", err)
	}

	pubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		s.t.Fatalf("Error marshalling public key: %v", err)
	}

	pubPemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKey,
	})

	go func() {
		time.Sleep(time.Millisecond * 100)
		if err := sendMessage(&manager.ServerStreamMessage{
			Message: &manager.ServerStreamMessage_TerminateReq{
				TerminateReq: &manager.Terminate{Message: "test terminate"},
			},
		}); err != nil {
			s.t.Fatalf("failed to send terminate request: %s", err)
		}
	}()

	go func() {
		time.Sleep(time.Millisecond * 100)
		algo, err := os.ReadFile(algoPath)
		if err != nil {
			s.t.Fatalf("failed to read algorithm file: %s", err)
			return
		}
		data, err := os.ReadFile(dataPath)
		if err != nil {
			s.t.Fatalf("failed to read data file: %s", err)
			return
		}

		pubPem, _ := pem.Decode(pubPemBytes)
		algoHash := sha3.Sum256(algo)
		dataHash := sha3.Sum256(data)

		if err := sendMessage(&manager.ServerStreamMessage{
			Message: &manager.ServerStreamMessage_RunReq{
				RunReq: &manager.ComputationRunReq{
					Id:              "1",
					Name:            "sample computation",
					Description:     "sample description",
					Datasets:        []*manager.Dataset{{Hash: dataHash[:], UserKey: pubPem.Bytes}},
					Algorithm:       &manager.Algorithm{Hash: algoHash[:], UserKey: pubPem.Bytes},
					ResultConsumers: []*manager.ResultConsumer{{UserKey: pubPem.Bytes}},
					AgentConfig: &manager.AgentConfig{
						Port:        "7002",
						LogLevel:    "debug",
						AttestedTls: attestedTLS,
					},
				},
			},
		}); err != nil {
			s.t.Fatalf("failed to send run request: %s", err)
		}
	}()
}
