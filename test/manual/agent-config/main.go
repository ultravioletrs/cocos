// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Simplified script to pass configs to agent without manager and read logs and events for manager.
// This tool is meant for testing purposes.
package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strconv"

	internalvsock "github.com/ultravioletrs/cocos/internal/vsock" // Import your custom vsock package

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/qemu"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
)

const (
	managerVsockPort = manager.ManagerVsockPort
	vsockConfigPort  = qemu.VsockConfigPort
)

func main() {
	if len(os.Args) < 5 {
		log.Fatalf("usage: %s <data-path> <algo-path> <public-key-path> <attested-tls-bool>", os.Args[0])
	}
	dataPath := os.Args[1]
	algoPath := os.Args[2]
	pubKeyFile := os.Args[3]
	attestedTLS, err := strconv.ParseBool(os.Args[4])
	if err != nil {
		log.Fatalf("usage: %s <data-path> <algo-path> <public-key-path> <attested-tls-bool>, <attested-tls-bool> must be a bool value", os.Args[0])
	}

	pubKey, err := os.ReadFile(pubKeyFile)
	if err != nil {
		log.Fatalf("failed to read public key file: %s", err)
	}

	algoHash, err := internal.Checksum(algoPath)
	if err != nil {
		log.Fatalf("failed to calculate algorithm checksum: %s", err)
	}

	dataHash, err := internal.Checksum(dataPath)
	if err != nil {
		log.Fatalf("failed to calculate data checksum: %s", err)
	}

	ac := agent.Computation{
		ID: "123",
		Datasets: agent.Datasets{
			agent.Dataset{
				Hash:    [32]byte(dataHash),
				UserKey: pubKey,
			},
		},
		Algorithm: agent.Algorithm{
			Hash:    [32]byte(algoHash),
			UserKey: pubKey,
		},
		ResultConsumers: []agent.ResultConsumer{
			{UserKey: pubKey},
		},
		AgentConfig: agent.AgentConfig{
			LogLevel:    "debug",
			Port:        "7002",
			AttestedTls: attestedTLS,
		},
	}

	if err := sendAgentConfig(3, ac); err != nil {
		log.Fatalf("failed to send agent config: %s", err)
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
	ackWriter := internalvsock.NewAckWriter(conn)
	go ackWriter.HandleAcknowledgments()

	for {
		var message pkgmanager.ClientStreamMessage
		err := ackReader.ReadProto(&message)
		if err != nil {
			log.Printf("Error reading message: %v", err)
			return
		}

		log.Printf("Received message: %s", message.String())
	}
}
