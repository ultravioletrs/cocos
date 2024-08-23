// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package algorithm

import (
	"context"

	"google.golang.org/grpc/metadata"
)

type AlgorithType string

const (
	AlgoTypeBin    AlgorithType = "bin"
	AlgoTypePython AlgorithType = "python"
	AlgoTypeWasm   AlgorithType = "wasm"
	AlgoTypeDocker AlgorithType = "docker"
	AlgoTypeKey                 = "algo_type"
	AlgoArgsKey                 = "algo_args"

	ResultsDir     = "results"
	DatasetsDir    = "datasets"
	AlgoWorkingDir = "/cocos"
)

func AlgorithmTypeToContext(ctx context.Context, algoType string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, AlgoTypeKey, algoType)
}

func AlgorithmTypeFromContext(ctx context.Context) string {
	return metadata.ValueFromIncomingContext(ctx, AlgoTypeKey)[0]
}

func AlgorithmArgsToContext(ctx context.Context, algoArgs []string) context.Context {
	for _, arg := range algoArgs {
		ctx = metadata.AppendToOutgoingContext(ctx, AlgoArgsKey, arg)
	}
	return ctx
}

func AlgorithmArgsFromContext(ctx context.Context) []string {
	return metadata.ValueFromIncomingContext(ctx, AlgoArgsKey)
}

// Algorithm is an interface that specifies the API for an algorithm.
type Algorithm interface {
	// Run executes the algorithm and returns the result.
	Run() error
}
