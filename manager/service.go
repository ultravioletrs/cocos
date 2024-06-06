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
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const hashLength = 32

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

	errInvalidHashLength = errors.New("hash must be of byte length 32")
)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// Run create a computation.
	Run(ctx context.Context, c *manager.ComputationRunReq) (string, error)
	// RetrieveAgentEventsLogs Retrieve and forward agent logs and events via vsock.
	RetrieveAgentEventsLogs()
}

type managerService struct {
	qemuCfg    qemu.Config
	logger     *slog.Logger
	agents     map[int]string // agent map of vsock cid to computationID.
	eventsChan chan *manager.ClientStreamMessage
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(qemuCfg qemu.Config, logger *slog.Logger, eventsChan chan *manager.ClientStreamMessage) Service {
	ms := &managerService{
		qemuCfg:    qemuCfg,
		logger:     logger,
		agents:     make(map[int]string),
		eventsChan: eventsChan,
	}
	return ms
}

func (ms *managerService) Run(ctx context.Context, c *manager.ComputationRunReq) (string, error) {
	ms.publishEvent("vm-provision", c.Id, "starting", json.RawMessage{})
	ac := agent.Computation{
		ID:          c.Id,
		Name:        c.Name,
		Description: c.Description,
		AgentConfig: agent.AgentConfig{
			Port:         c.AgentConfig.Port,
			Host:         c.AgentConfig.Host,
			KeyFile:      c.AgentConfig.KeyFile,
			CertFile:     c.AgentConfig.CertFile,
			ServerCAFile: c.AgentConfig.ServerCaFile,
			ClientCAFile: c.AgentConfig.ClientCaFile,
			LogLevel:     c.AgentConfig.LogLevel,
		},
	}
	ac.Algorithm = agent.Algorithm{Hash: [hashLength]byte(c.Algorithm.Hash), UserKey: c.Algorithm.UserKey}

	for _, data := range c.Datasets {
		if len(data.Hash) != hashLength {
			ms.publishEvent("vm-provision", c.Id, "failed", json.RawMessage{})
			return "", errInvalidHashLength
		}
		ac.Datasets = append(ac.Datasets, agent.Dataset{Hash: [hashLength]byte(data.Hash), UserKey: data.UserKey})
	}

	for _, rc := range c.ResultConsumers {
		ac.ResultConsumers = append(ac.ResultConsumers, agent.ResultConsumer{UserKey: rc.UserKey})
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
	ms.qemuCfg.VSockConfig.Vnc++

	ms.publishEvent("vm-provision", c.Id, "complete", json.RawMessage{})
	return fmt.Sprint(ms.qemuCfg.HostFwdAgent), nil
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
	ms.eventsChan <- &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentEvent{
			AgentEvent: &manager.AgentEvent{
				EventType:     event,
				ComputationId: cmpID,
				Status:        status,
				Details:       details,
				Timestamp:     timestamppb.Now(),
				Originator:    "manager",
			},
		},
	}
}
