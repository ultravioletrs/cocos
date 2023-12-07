// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mainflux/mainflux/pkg/messaging"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager/qemu"
)

type state string

const (
	idle              state = "idle"
	running           state = "running"
	notificationTopic       = "manager"
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
	Run(ctx context.Context, c *Computation) error
}

type managerService struct {
	qemuCfg qemu.Config
	state   state
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(qemuCfg qemu.Config) Service {
	return &managerService{
		qemuCfg: qemuCfg,
		state:   idle,
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
	// different VM guests can't forward ports to the same ports on the same host
	defer func() {
		ms.qemuCfg.HostFwd1++
		ms.qemuCfg.NetDevConfig.HostFwd2++
		ms.qemuCfg.NetDevConfig.HostFwd3++
	}()

	return nil
}

func (ms *managerService) Status(ctx context.Context) string {
	switch ms.state {
	case running:
		return fmt.Sprintf("%s:%s", running, ms.computationHash)
	default:
		return string(ms.state)
	}
}

func (ms *managerService) setIdle(ctx context.Context) {
	ms.state = idle
	ms.publishEvent(ctx, string(ms.state), "")
}

func (ms *managerService) publishEvent(ctx context.Context, subtopic, body string) func() {
	return func() {
		if err := ms.publisher.Publish(ctx, notificationTopic, &messaging.Message{
			Subtopic: subtopic,
			Payload:  []byte(body),
		}); err != nil {
			ms.logger.Warn(err.Error())
		}
	}
}
