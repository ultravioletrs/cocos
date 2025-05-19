// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"errors"

	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
)

type algoReq struct {
	Algorithm    []byte `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
	Requirements []byte
}

func (req algoReq) validate() error {
	if len(req.Algorithm) == 0 {
		return errors.New("algorithm binary is required")
	}
	return nil
}

type dataReq struct {
	Dataset  []byte `protobuf:"bytes,1,opt,name=dataset,proto3" json:"dataset,omitempty"`
	Filename string
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
	TeeNonce  [quoteprovider.Nonce]byte
	VtpmNonce [vtpm.Nonce]byte
	AttType   attestation.PlatformType
}

func (req attestationReq) validate() error {
	switch req.AttType {
	case attestation.SNP, attestation.VTPM, attestation.SNPvTPM:
		return nil
	default:
		return errors.New("invalid attestation type in attestation request")
	}
}

type imaMeasurementsReq struct{}

func (req imaMeasurementsReq) validate() error {
	// No request parameters to validate, so no validation logic needed
	return nil
}
