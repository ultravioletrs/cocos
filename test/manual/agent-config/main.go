// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Simplified script to pass configs to agent without manager and read logs and events for manager.
// This tool is meant for testing purposes.
package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
)

const VsockConfigPort uint32 = 9999

func main() {
	l, err := vsock.Listen(9997, nil)
	if err != nil {
		log.Fatal(err)
	}
	ac := agent.Computation{
		ID:              "123",
		Datasets:        agent.Datasets{agent.Dataset{ID: "1", Provider: "pr1"}},
		Algorithms:      agent.Algorithms{agent.Algorithm{ID: "1", Provider: "pr1"}},
		ResultConsumers: []string{"1"},
		AgentConfig: agent.AgentConfig{
			LogLevel: "debug",
		},
	}
	fmt.Println(SendAgentConfig(3, ac))

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Println(err)
				continue
			}
			b := make([]byte, 1024)
			n, err := conn.Read(b)
			if err != nil {
				log.Println(err)
				continue
			}
			conn.Close()
			var mes manager.ClientStreamMessage
			if err := proto.Unmarshal(b[:n], &mes); err != nil {
				log.Println(err)
			}
			fmt.Println(mes.String())
		}
	}()
}

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
