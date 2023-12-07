// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/messaging"
	"github.com/cenkalti/backoff/v4"
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
	Run(ctx context.Context, computation []byte) (string, error)
	Status(ctx context.Context) string
}

type managerService struct {
	agent           agent.AgentServiceClient
	qemuCfg         qemu.Config
	state           state
	publisher       messaging.Publisher
	logger          mglog.Logger
	computationHash string
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(agentClient agent.AgentServiceClient, qemuCfg qemu.Config, publisher messaging.Publisher, logger mglog.Logger) Service {
	return &managerService{
		agent:     agentClient,
		qemuCfg:   qemuCfg,
		state:     idle,
		publisher: publisher,
		logger:    logger,
	}
}

func (ms *managerService) Run(ctx context.Context, computation []byte) (string, error) {
	hash := sha256.Sum256(computation)
	ms.computationHash = hex.EncodeToString(hash[:])
	ms.publishEvent(ctx, ms.computationHash, "creating vm")
	ms.state = running
	defer ms.setIdle(ctx)
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
	ms.publishEvent(ctx, ms.computationHash, "created vm")
	return res.Computation, nil
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
