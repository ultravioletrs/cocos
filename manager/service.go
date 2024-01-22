// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/cenkalti/backoff/v4"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/internal/events"
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

	// ErrFailedToAllocatePort indicates no free port was found on host.
	ErrFailedToAllocatePort = errors.New("failed to allocate free port on host")
)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	Run(ctx context.Context, c *Computation) (string, error)
}

type managerService struct {
	qemuCfg  qemu.Config
	logger   *slog.Logger
	eventSvc events.Service
	hostIP   string
	agents   map[int]string // agent map of vsock cid to computationID.
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(qemuCfg qemu.Config, logger *slog.Logger, eventSvc events.Service, hostIP string) Service {
	ms := &managerService{
		qemuCfg:  qemuCfg,
		eventSvc: eventSvc,
		hostIP:   hostIP,
		logger:   logger,
		agents:   make(map[int]string),
	}
	go ms.retrieveAgentLogs()
	return ms
}

func (ms *managerService) Run(ctx context.Context, c *Computation) (string, error) {
	ms.publishEvent("vm-provision", c.Id, "starting", json.RawMessage{})
	ac := agent.Computation{
		ID:              c.Id,
		Name:            c.Name,
		Description:     c.Description,
		ResultConsumers: c.ResultConsumers,
		AgentConfig: agent.AgentConfig{
			Port:       c.AgentConfig.Port,
			Host:       c.AgentConfig.Host,
			KeyFile:    c.AgentConfig.KeyFile,
			CertFile:   c.AgentConfig.CertFile,
			LogLevel:   c.AgentConfig.LogLevel,
			InstanceID: c.AgentConfig.InstanceId,
		},
	}
	for _, algo := range c.Algorithms {
		ac.Algorithms = append(ac.Algorithms, agent.Algorithm{ID: algo.Id, Provider: algo.Provider})
	}
	for _, data := range c.Datasets {
		ac.Datasets = append(ac.Datasets, agent.Dataset{ID: data.Id, Provider: data.Provider})
	}

	agentPort, err := getFreePort()
	if err != nil {
		ms.publishEvent("vm-provision", c.Id, "failed", json.RawMessage{})
		return "", errors.Wrap(ErrFailedToAllocatePort, err)
	}
	ms.qemuCfg.HostFwdAgent = agentPort

	ms.publishEvent("vm-provision", c.Id, "in-progress", json.RawMessage{})
	if _, err = qemu.CreateVM(ctx, ms.qemuCfg); err != nil {
		ms.publishEvent("vm-provision", c.Id, "failed", json.RawMessage{})
		return "", err
	}

	ms.agents[ms.qemuCfg.VSockConfig.GuestCID] = c.Id

	err = backoff.Retry(func() error {
		return SendAgentConfig(uint32(ms.qemuCfg.VSockConfig.GuestCID), ac)
	}, backoff.NewExponentialBackOff())
	if err != nil {
		return "", err
	}
	ms.qemuCfg.VSockConfig.GuestCID++

	ms.publishEvent("vm-provision", c.Id, "complete", json.RawMessage{})
	return fmt.Sprintf("%s:%d", ms.hostIP, ms.qemuCfg.HostFwdAgent), nil
}

func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", "")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	return port, nil
}

func (ms *managerService) publishEvent(event, cmpID, status string, details json.RawMessage) {
	if err := ms.eventSvc.SendEvent(event, cmpID, status, details); err != nil {
		ms.logger.Warn(err.Error())
	}
}
