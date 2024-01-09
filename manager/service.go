// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"errors"
	"time"

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
	Run(ctx context.Context, computation *Computation) error
}

type managerService struct {
	qemuCfg qemu.Config
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(qemuCfg qemu.Config) Service {
	return &managerService{
		qemuCfg: qemuCfg,
	}
}

func (ms *managerService) Run(ctx context.Context, computation *Computation) error {
	agCmp := agent.Computation{
		ID:              computation.Id,
		Name:            computation.Name,
		Description:     computation.Description,
		ResultConsumers: computation.ResultConsumers,
	}
	dur, err := time.ParseDuration(computation.Timeout)
	if err != nil {
		return err
	}
	agCmp.Timeout.Duration = dur
	for _, algo := range computation.Algorithms {
		agCmp.Algorithms = append(agCmp.Algorithms, agent.Algorithm{ID: algo.Id, Provider: algo.Provider})
	}
	for _, data := range computation.Datasets {
		agCmp.Datasets = append(agCmp.Datasets, agent.Dataset{ID: data.Id, Provider: data.Provider})
	}

	if _, err = qemu.CreateVM(ctx, ms.qemuCfg, agCmp); err != nil {
		return err
	}
	// different VM guests can't forward ports to the same ports on the same host
	defer func() {
		ms.qemuCfg.HostFwd1++
		ms.qemuCfg.NetDevConfig.HostFwd2++
		ms.qemuCfg.NetDevConfig.HostFwd3++
	}()

	return nil
}
