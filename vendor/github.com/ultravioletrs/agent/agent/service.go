// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")
)

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
