// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package algorithm

import "context"

type AlgorithType string

const (
	AlgoTypeBin    AlgorithType = "bin"
	AlgoTypePython AlgorithType = "python"
)

type AlgorithTypeKey struct{}

func AlgorithmTypeToContext(ctx context.Context, algoType string) context.Context {
	return context.WithValue(ctx, AlgorithTypeKey{}, algoType)
}

func AlgorithmTypeFromContext(ctx context.Context) (string, bool) {
	algoType, ok := ctx.Value(AlgorithTypeKey{}).(string)
	return algoType, ok
}

// Algorithm is an interface that specifies the API for an algorithm.
type Algorithm interface {
	// Run executes the algorithm and returns the result.
	Run() ([]byte, error)

	// Add dataset to algorithm.
	AddDataset(dataset string)
}
