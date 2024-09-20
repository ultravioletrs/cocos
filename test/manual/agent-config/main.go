// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Simplified script to pass configs to agent without manager and read logs and events for manager.
// This tool is meant for testing purposes.
package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/qemu"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
)

func main() {
	if len(os.Args) < 5 {
		log.Fatalf("usage: %s <data-path> <algo-path> <public-key-path> <attested-tls-bool>", os.Args[0])
	}
	dataPath := os.Args[1]
	algoPath := os.Args[2]
	pubKeyFile := os.Args[3]
	attestedTLSParam, err := strconv.ParseBool(os.Args[4])
	if err != nil {
		log.Fatalf("usage: %s <data-path> <algo-path> <public-key-path> <attested-tls-bool>, <attested-tls-bool> must be a bool value", os.Args[0])
	}
	attestedTLS := attestedTLSParam

	pubKey, err := os.ReadFile(pubKeyFile)
	if err != nil {
		log.Fatalf("failed to read public key file: %s", err)
	}
	pubPem, _ := pem.Decode(pubKey)
	algoHash, err := internal.Checksum(algoPath)
	if err != nil {
		log.Fatalf("failed to calculate checksum: %s", err)
	}
	dataHash, err := internal.Checksum(dataPath)
	if err != nil {
		log.Fatalf("failed to calculate checksum: %s", err)
	}

	l, err := vsock.Listen(manager.ManagerVsockPort, nil)
	if err != nil {
		log.Fatal(err)
	}
	ac := agent.Computation{
		ID:              "123",
		Datasets:        agent.Datasets{agent.Dataset{Hash: [32]byte(dataHash), UserKey: pubPem.Bytes}},
		Algorithm:       agent.Algorithm{Hash: [32]byte(algoHash), UserKey: pubPem.Bytes},
		ResultConsumers: []agent.ResultConsumer{{UserKey: pubPem.Bytes}},
		AgentConfig: agent.AgentConfig{
			LogLevel:    "debug",
			Port:        "7002",
			AttestedTls: attestedTLS,
		},
	}
	if err := SendAgentConfig(3, ac); err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnections(conn)
	}
}

func SendAgentConfig(cid uint32, ac agent.Computation) error {
	conn, err := vsock.Dial(cid, qemu.VsockConfigPort, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload, err := json.Marshal(ac)
	if err != nil {
		return err
	}

	var ac2 agent.Computation
	if err := json.Unmarshal(payload, &ac2); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return nil
}

func handleConnections(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Println("Connection closed by client")
			} else {
				log.Println("Error reading from connection:", err)
			}
			return
		}

		var message pkgmanager.ClientStreamMessage
		if err := proto.Unmarshal(buf[:n], &message); err != nil {
			log.Println("Failed to unmarshal message:", err)
			continue
		}

		fmt.Println(message.String())
	}
}
