// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"errors"
)

type runReq struct {
	Computation []byte `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
}

func (req runReq) validate() error {
	if len(req.Computation) == 0 {
		return errors.New("algorithm binary is required")
	}
	return nil
}

type algoReq struct {
	Algorithm []byte `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
	Provider  string `protobuf:"bytes,2,opt,name=provider,proto3" json:"provider,omitempty"`
	Id        string `protobuf:"bytes,3,opt,name=id,proto3" json:"id,omitempty"`
}

func (req algoReq) validate() error {
	if len(req.Algorithm) == 0 {
		return errors.New("algorithm binary is required")
	}
	if req.Id == "" {
		return errors.New("malformed entity")
	}
	if req.Provider == "" {
		return errors.New("malformed entity")
	}
	return nil
}

type dataReq struct {
	Dataset  []byte `protobuf:"bytes,1,opt,name=dataset,proto3" json:"dataset,omitempty"`
	Provider string `protobuf:"bytes,2,opt,name=provider,proto3" json:"provider,omitempty"`
	Id       string `protobuf:"bytes,3,opt,name=id,proto3" json:"id,omitempty"`
}

func (req dataReq) validate() error {
	if len(req.Dataset) == 0 {
		return errors.New("dataset CSV file is required")
	}
	if req.Id == "" {
		return errors.New("malformed entity")
	}
	if req.Provider == "" {
		return errors.New("malformed entity")
	}
	return nil
}

type resultReq struct {
	Consumer string `protobuf:"bytes,1,opt,name=consumer,proto3" json:"consumer,omitempty"`
}

func (req resultReq) validate() error {
	// No request parameters to validate, so no validation logic needed
	return nil
}

type attestationReq struct {
	// No request parameters needed for retrieving attestation output
}

func (req attestationReq) validate() error {
	// No request parameters to validate, so no validation logic needed
	return nil
}
