// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Simplified script to pass configs to agent without manager and read logs and events for manager.
// This tool is meant for testing purposes.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
)

func main() {
	attestedTLS := false

	if len(os.Args) == 2 {
		attestedTLSParam, err := strconv.ParseBool(os.Args[1])
		if err != nil {
			log.Fatalf("usage: %s <attested-tls> - <attested-tls> must be true or false", os.Args[0])
		}

		attestedTLS = attestedTLSParam
	} else if len(os.Args) > 2 {
		log.Fatalf("usage: %s <attested-tls>", os.Args[0])
	}

	l, err := vsock.Listen(manager.ManagerVsockPort, nil)
	if err != nil {
		log.Fatal(err)
	}
	ac := agent.Computation{
		ID:              "123",
		Datasets:        agent.Datasets{agent.Dataset{ID: "1", Provider: "pr1"}},
		Algorithm:       agent.Algorithm{ID: "1", Provider: "pr1"},
		ResultConsumers: []string{"1"},
		AgentConfig: agent.AgentConfig{
			LogLevel:    "debug",
			Port:        "7002",
			AttestedTls: attestedTLS,
		},
	}
	fmt.Println(SendAgentConfig(3, ac))

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
		var mes pkgmanager.ClientStreamMessage
		if err := proto.Unmarshal(b[:n], &mes); err != nil {
			log.Println(err)
		}
		fmt.Println(mes.String())
	}
}

func SendAgentConfig(cid uint32, ac agent.Computation) error {
	conn, err := vsock.Dial(cid, manager.VsockConfigPort, nil)
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
