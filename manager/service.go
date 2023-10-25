// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/cenkalti/backoff/v4"
	"github.com/ultravioletrs/cocos-ai/agent"
	"github.com/ultravioletrs/cocos-ai/manager/qemu"
)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")

	// ErrNotFound indicates a non-existent entity request.
	ErrNotFound = errors.New("entity not found")
)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	Run(ctx context.Context, computation []byte) (string, error)
}

type managerService struct {
	agent   agent.AgentServiceClient
	qemuCfg qemu.Config
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(agent agent.AgentServiceClient, qemuCfg qemu.Config) Service {
	return &managerService{
		agent:   agent,
		qemuCfg: qemuCfg,
	}
}

func (ms *managerService) Run(ctx context.Context, computation []byte) (string, error) {
	_, err := qemu.CreateVM(ctx, ms.qemuCfg)
	if err != nil {
		return "", err
	}

	ln, err := ms.allocFreeHostPorts()
	if err != nil {
		return "", err
	}



	var res *agent.RunResponse

	for _, ln := range ln {
		ln.Close()
	}

	err = backoff.Retry(func() error {
		res, err = ms.agent.Run(ctx, &agent.RunRequest{Computation: computation})
		return err
	}, backoff.NewExponentialBackOff())

	if err != nil {
		return "", err
	}
	return res.Computation, nil
}

func (ms *managerService) allocFreeHostPorts() ([]net.Listener, error) {
	var listeners []net.Listener
	ports := []int{0, 0, 0}

	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			return nil, errors.New("unable to find free port")
		}

		_, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}

		ports[i] = port
		listeners = append(listeners, ln)
	}

	ms.qemuCfg.HostFwd1 = ports[0]
	ms.qemuCfg.NetDevConfig.HostFwd2 = ports[1]
	ms.qemuCfg.NetDevConfig.HostFwd3 = ports[2]

	return listeners, nil
}
