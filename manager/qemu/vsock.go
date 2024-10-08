// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"encoding/json"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
)

const VsockConfigPort uint32 = 7777 // CHANGED BY ME

func (v *qemuVM) SendAgentConfig(ac agent.Computation) error {
	conn, err := vsock.Dial(uint32(v.config.GuestCID), VsockConfigPort, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload, err := json.Marshal(ac)
	if err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return nil
}
