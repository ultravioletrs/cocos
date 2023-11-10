// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"errors"
	"net"
	"strconv"
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

const vmPorts = 3

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	Run(ctx context.Context, c *Computation) error
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

func (ms *managerService) Run(ctx context.Context, c *Computation) error {
	ac := agent.Computation{
		ID:              c.Id,
		Name:            c.Name,
		Description:     c.Description,
		ResultConsumers: c.ResultConsumers,
	}
	dur, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return err
	}

	// different VM guests can't forward ports to the same ports on the same host.
	ln, err := ms.allocFreeHostPorts()
	if err != nil {
		return err
	}

	for _, ln := range ln {
		ln.Close()
	}

	ac.Timeout.Duration = dur
	for _, algo := range c.Algorithms {
		ac.Algorithms = append(ac.Algorithms, agent.Algorithm{ID: algo.Id, Provider: algo.Provider})
	}
	for _, data := range c.Datasets {
		ac.Datasets = append(ac.Datasets, agent.Dataset{ID: data.Id, Provider: data.Provider})
	}

	if _, err = qemu.CreateVM(ctx, ms.qemuCfg, ac); err != nil {
		return err
	}

	return nil
}

func (ms *managerService) allocFreeHostPorts() ([]net.Listener, error) {
	var listeners []net.Listener
	ports := []int{0, 0, 0}

	for i := 0; i < vmPorts; i++ {
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
