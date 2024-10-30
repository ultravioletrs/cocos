// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package docker

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/agent/algorithm/logging"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
)

// TestNewAlgorithm tests the NewAlgorithm function.
func TestNewAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventsSvc := new(mocks.Service)
	algoFile := "/path/to/algo.tar"

	algo := NewAlgorithm(logger, eventsSvc, algoFile)

	d, ok := algo.(*docker)
	assert.True(t, ok, "NewAlgorithm should return a *docker")
	assert.Equal(t, algoFile, d.algoFile, "algoFile should be set correctly")
	assert.NotNil(t, d.logger, "logger should be set")
	assert.IsType(t, &logging.Stderr{}, d.stderr, "stderr should be of type *algorithm.Stderr")
	assert.IsType(t, &logging.Stdout{}, d.stdout, "stdout should be of type *algorithm.Stdout")
}
