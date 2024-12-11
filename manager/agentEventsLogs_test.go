// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/pkg/manager"
)

func TestComputationIDFromAddress(t *testing.T) {
	ms := &managerService{
		vms: map[string]vm.VM{
			"comp1": qemu.NewVM(qemu.VMInfo{Config: qemu.Config{VSockConfig: qemu.VSockConfig{GuestCID: 3}}}, func(event interface{}) error { return nil }, "comp1"),
			"comp2": qemu.NewVM(qemu.VMInfo{Config: qemu.Config{VSockConfig: qemu.VSockConfig{GuestCID: 5}}}, func(event interface{}) error { return nil }, "comp2"),
		},
	}

	tests := []struct {
		name    string
		address string
		want    string
		wantErr bool
	}{
		{"Valid address", "vm(3)", "comp1", false},
		{"Invalid address", "invalid", "", true},
		{"Non-existent CID", "vm(10)", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ms.computationIDFromAddress(tt.address)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestReportBrokenConnection(t *testing.T) {
	ms := &managerService{
		eventsChan: make(chan *ClientStreamMessage, 1),
		vms: map[string]vm.VM{
			"comp1": qemu.NewVM(qemu.VMInfo{Config: qemu.Config{VSockConfig: qemu.VSockConfig{GuestCID: 3}}}, func(event interface{}) error { return nil }, "comp1"),
		},
	}

	ms.reportBrokenConnection("comp1")

	select {
	case msg := <-ms.eventsChan:
		assert.Equal(t, "comp1", msg.GetAgentEvent().ComputationId)
		assert.Equal(t, manager.Disconnected.String(), msg.GetAgentEvent().Status)
		assert.Equal(t, "manager", msg.GetAgentEvent().Originator)
	default:
		t.Error("Expected message in eventsChan, but none received")
	}
}
