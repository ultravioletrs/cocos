// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"errors"

	"github.com/cenkalti/backoff/v4"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager/qemu"
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
	// different VM guests can't forward ports to the same ports on the same host
	ms.qemuCfg.HostFwd1++
	ms.qemuCfg.NetDevConfig.HostFwd2++
	ms.qemuCfg.NetDevConfig.HostFwd3++

	var res *agent.RunResponse

	err = backoff.Retry(func() error {
		res, err = ms.agent.Run(ctx, &agent.RunRequest{Computation: computation})
		return err
	}, backoff.NewExponentialBackOff())

	if err != nil {
		return "", err
	}
	return res.Computation, nil
}
