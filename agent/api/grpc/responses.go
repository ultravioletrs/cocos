// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

type algoRes struct{}

type dataRes struct{}

type resultRes struct {
	File []byte `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

type attestationRes struct {
	File []byte
}

type fetchAttestationResultRes struct {
	AttestationResult []byte `protobuf:"bytes,1,opt,name=AttestationResult,proto3" json:"AttestationResult,omitempty"`
}
