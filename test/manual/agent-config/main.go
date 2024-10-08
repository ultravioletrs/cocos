// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Simplified script to pass configs to agent without manager and read logs and events for manager.
// This tool is meant for testing purposes.
package main

import (
	"encoding/json"
	"encoding/pem"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/internal"
	internalvsock "github.com/ultravioletrs/cocos/internal/vsock"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/events"
	"github.com/ultravioletrs/cocos/manager/qemu"
)

const (
	managerVsockPort = events.ManagerVsockPort
	vsockConfigPort  = qemu.VsockConfigPort
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
	if err := sendAgentConfig(13, ac); err != nil {
		log.Fatal(err)
	}

	listener, err := vsock.Listen(managerVsockPort, nil)
	if err != nil {
		log.Fatalf("failed to listen on vsock: %s", err)
	}
	defer listener.Close()

	log.Printf("Listening on vsock port %d", managerVsockPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %s", err)
			continue
		}

		go handleConnection(conn)
	}
}

func sendAgentConfig(cid uint32, ac agent.Computation) error {
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

func handleConnection(conn net.Conn) {
	defer conn.Close()

	ackReader := internalvsock.NewAckReader(conn)

	for {
		var message manager.ClientStreamMessage
		err := ackReader.ReadProto(&message)
		if err != nil {
			log.Printf("Error reading message: %v", err)
			return
		}

		log.Printf("Received message: %s", message.String())
	}
}
