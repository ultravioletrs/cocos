// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"errors"
)

type algoReq struct {
	Algorithm    []byte `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
	Requirements []byte
	ResultsFile  []byte
}

func (req algoReq) validate() error {
	if len(req.Algorithm) == 0 {
		return errors.New("algorithm binary is required")
	}
	return nil
}

type dataReq struct {
	Dataset []byte `protobuf:"bytes,1,opt,name=dataset,proto3" json:"dataset,omitempty"`
}

func (req dataReq) validate() error {
	if len(req.Dataset) == 0 {
		return errors.New("dataset CSV file is required")
	}
	return nil
}

type resultReq struct{}

func (req resultReq) validate() error {
	// No request parameters to validate, so no validation logic needed
	return nil
}

type attestationReq struct {
	ReportData [64]byte
}

func (req attestationReq) validate() error {
	return nil
}
