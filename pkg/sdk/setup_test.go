// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/ultravioletrs/cocos/agent"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/mocks"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var (
	lis *bufconn.Listener
	svc = &mocks.Service{}
)

func TestMain(m *testing.M) {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()

	agent.RegisterAgentServiceServer(s, agentgrpc.NewServer(svc))

	go func() {
		if err := s.Serve(lis); err != nil {
			fmt.Println("Server exited with error:", err)
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
