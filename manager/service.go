// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/internal/events"
	"github.com/ultravioletrs/cocos/manager/qemu"
)

const notificationTopic = "manager"

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
	qemuCfg  qemu.Config
	logger   mglog.Logger
	eventSvc events.Service
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(qemuCfg qemu.Config, logger mglog.Logger, eventSvc events.Service) Service {
	return &managerService{
		qemuCfg:  qemuCfg,
		logger:   logger,
		eventSvc: eventSvc,
	}
}

func (ms *managerService) Run(ctx context.Context, c *Computation) error {
	ms.publishEvent("vm-provision", c.Id, "starting", json.RawMessage{})
	ac := agent.Computation{
		ID:              c.Id,
		Name:            c.Name,
		Description:     c.Description,
		ResultConsumers: c.ResultConsumers,
	}
	dur, err := time.ParseDuration(c.Timeout)
	if err != nil {
		detail := struct {
			Error string `json:"error"`
		}{
			Error: err.Error(),
		}
		detailB, merr := json.Marshal(detail)
		if merr != nil {
			ms.logger.Warn(merr.Error())
			return err
		}
		ms.publishEvent("vm-provision", c.Id, "failed", detailB)
		return err
	}
	ac.Timeout.Duration = dur
	for _, algo := range c.Algorithms {
		ac.Algorithms = append(ac.Algorithms, agent.Algorithm{ID: algo.Id, Provider: algo.Provider})
	}
	for _, data := range c.Datasets {
		ac.Datasets = append(ac.Datasets, agent.Dataset{ID: data.Id, Provider: data.Provider})
	}

	ms.publishEvent("vm-provision", c.Id, "in-progress", json.RawMessage{})
	if _, err = qemu.CreateVM(ctx, ms.qemuCfg, ac); err != nil {
		detail := struct {
			Error string `json:"error"`
		}{
			Error: err.Error(),
		}
		detailB, merr := json.Marshal(detail)
		if merr != nil {
			ms.logger.Warn(merr.Error())
			return err
		}
		ms.publishEvent("vm-provision", c.Id, "failed", detailB)
		return err
	}
	// different VM guests can't forward ports to the same ports on the same host
	defer func() {
		ms.qemuCfg.HostFwd1++
		ms.qemuCfg.NetDevConfig.HostFwd2++
		ms.qemuCfg.NetDevConfig.HostFwd3++
	}()

	ms.publishEvent("vm-provision", c.Id, "complete", json.RawMessage{})
	return nil
}

func (ms *managerService) publishEvent(event, cmpID, status string, details json.RawMessage) {
	if err := ms.eventSvc.SendEvent(event, cmpID, status, details); err != nil {
		ms.logger.Warn(err.Error())
	}
}
