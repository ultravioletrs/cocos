// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package algorithm

// Algorithm is an interface that specifies the API for an algorithm.
type Algorithm interface {
	// Run executes the algorithm and returns the result.
	Run() ([]byte, error)
}
