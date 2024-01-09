// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	agentgrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc/agent"
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
	Run(ctx context.Context, computation *Computation, agentConfig grpc.Config) (string, error)
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

func (ms *managerService) Run(ctx context.Context, computation *Computation, agentConfig grpc.Config) (string, error) {
	agCmp := agent.Computation{
		ID:              computation.Id,
		Name:            computation.Name,
		Description:     computation.Description,
		ResultConsumers: computation.ResultConsumers,
	}
	dur, err := time.ParseDuration(computation.Timeout)
	agCmp.Timeout.Duration = dur
	for _, algo := range computation.Algorithms {
		agCmp.Algorithms = append(agCmp.Algorithms, agent.Algorithm{ID: algo.Id, Provider: algo.Provider})
	}
	for _, data := range computation.Datasets {
		agCmp.Datasets = append(agCmp.Datasets, agent.Dataset{ID: data.Id, Provider: data.Provider})
	}

	if _, err = qemu.CreateVM(ctx, ms.qemuCfg, agCmp); err != nil {
		return "", err
	}
	// different VM guests can't forward ports to the same ports on the same host
	defer func() {
		ms.qemuCfg.HostFwd1++
		ms.qemuCfg.NetDevConfig.HostFwd2++
		ms.qemuCfg.NetDevConfig.HostFwd3++
	}()

	runReq := &agent.ComputationReq{
		Id:              computation.Id,
		Name:            computation.Name,
		Description:     computation.Description,
		ResultConsumers: computation.ResultConsumers,
		Timeout:         computation.Timeout,
	}

	for _, algo := range computation.Algorithms {
		runReq.Algorithms = append(runReq.Algorithms, &agent.AlgorithmReq{Id: algo.Id, Provider: algo.Provider})
	}
	for _, data := range computation.Datasets {
		runReq.Datasets = append(runReq.Datasets, &agent.DatasetReq{Id: data.Id, Provider: data.Provider})
	}

	var res *agent.RunResponse

	agentConfig.URL = fmt.Sprintf("localhost:%d", ms.qemuCfg.HostFwd3)

	err = backoff.Retry(func() error {
		agentGRPCClient, agentClient, err := agentgrpc.NewAgentClient(agentConfig)
		if err != nil {
			return err
		}
		defer agentGRPCClient.Close()
		res, err = agentClient.Run(ctx, &agent.RunRequest{
			Computation: runReq,
		})
		return err
	}, backoff.NewExponentialBackOff())

	if err != nil {
		return "", err
	}
	return res.Computation, nil
}
