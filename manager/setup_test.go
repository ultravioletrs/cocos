// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager_test

import (
	"os"
	"testing"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/ultravioletrs/cocos/manager"
	managergrpc "github.com/ultravioletrs/cocos/manager/api/grpc"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const (
	bufSize    = 1024 * 1024
	keyBitSize = 4096
)

var lis *bufconn.Listener

func TestMain(m *testing.M) {
	logger := mglog.NewMock()

	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()

	svc, err := manager.New(qemu.Config{}, "", logger, nil, "")
	if err != nil {
		panic(err)
	}
	manager.RegisterManagerServiceServer(s, managergrpc.NewServer(svc))
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
