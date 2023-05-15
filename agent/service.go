// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")
)

type Computation struct {
	ID                 string    `json:"id,omitempty" db:"id"`
	Name               string    `json:"name,omitempty" db:"name"`
	Description        string    `json:"description,omitempty" db:"description"`
	Status             string    `json:"status,omitempty" db:"status"`
	Owner              string    `json:"owner,omitempty" db:"owner"`
	StartTime          time.Time `json:"start_time,omitempty" db:"start_time"`
	EndTime            time.Time `json:"end_time,omitempty" db:"end_time"`
	Datasets           []string  `json:"datasets,omitempty" db:"datasets"`
	Algorithms         []string  `json:"algorithms,omitempty" db:"algorithms"`
	DatasetProviders   []string  `json:"dataset_providers,omitempty" db:"dataset_providers"`
	AlgorithmProviders []string  `json:"algorithm_providers,omitempty" db:"algorithm_providers"`
	ResultConsumers    []string  `json:"result_consumers,omitempty" db:"result_consumers"`
	Ttl                int32     `json:"ttl,omitempty" db:"ttl"`
	Metadata           Metadata  `json:"metadata,omitempty" db:"metadata"`
}

type Metadata map[string]interface{}

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// Ping compares a given string with secret
	Ping(string) (string, error)
	Run(ctx context.Context, cmp Computation) (string, error)
}

type agentService struct {
	secret string
}

var _ Service = (*agentService)(nil)

// New instantiates the agent service implementation.
func New(secret string) Service {
	return &agentService{
		secret: secret,
	}
}

func (ks *agentService) Ping(secret string) (string, error) {
	if ks.secret != secret {
		return "", ErrUnauthorizedAccess
	}
	return "Hello World :)", nil
}

func (ks *agentService) Run(ctx context.Context, cmp Computation) (string, error) {
	cmpJSON, err := json.Marshal(cmp)
	if err != nil {
		return "", err
	}

	fmt.Println(string(cmpJSON)) // log the JSON string to console

	return string(cmpJSON), nil // return the JSON string as the function's string return value
}
