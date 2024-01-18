// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"encoding/json"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
)

const VsockConfigPort uint32 = 9999

func SendAgentConfig(cid uint32, ac agent.Computation) error {
	conn, err := vsock.Dial(cid, VsockConfigPort, nil)
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
