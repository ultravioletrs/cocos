// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

type algoRes struct{}

type dataRes struct{}

type resultRes struct {
	File []byte
}

type attestationRes struct {
	File []byte
}

type imaMeasurementsRes struct {
	File  []byte
	PCR10 []byte
}

type fetchAttestationTokenRes struct {
	File []byte
}
