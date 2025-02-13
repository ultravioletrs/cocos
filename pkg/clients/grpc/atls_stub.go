// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !cgo

package grpc

import (
	"fmt"

	"google.golang.org/grpc/credentials"
)

func setupATLS(cfg AgentClientConfig) (credentials.TransportCredentials, error) {
	return nil, fmt.Errorf("aTLS is not supported without CGO. Please rebuild with CGO_ENABLED=1")
}
