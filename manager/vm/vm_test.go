// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/pkg/manager"
)

func TestNewVM(t *testing.T) {
	config := qemu.Config{}
	logsChan := make(chan *manager.ClientStreamMessage)
	computationId := "test-computation"

	nvm := NewVM(config, logsChan, computationId)

	assert.NotNil(t, nvm)
	assert.IsType(t, &vm{}, nvm)
}

func TestVM_Stop(t *testing.T) {
	// Setup
	v := &vm{
		cmd: exec.Command("sleep", "1"),
	}

	err := v.cmd.Start()
	assert.NoError(t, err)

	// Test
	err = v.Stop()

	// Assert
	assert.NoError(t, err)
	assert.Error(t, v.cmd.Wait()) // Process should have been killed
}
