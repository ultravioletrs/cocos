// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Simplified script to pass configs to agent without manager and read logs and events for manager.
// This tool is meant for testing purposes.
package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/crypto/sha3"
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
		log.Fatalf("usage: %s <data-path> <algo-path> <attested-tls-bool>, <attested-tls-bool> must be a bool value", os.Args[0])
	}
	attestedTLS := attestedTLSParam

	algo, err := os.ReadFile(algoPath)
	if err != nil {
		log.Fatalf(fmt.Sprintf("failed to read algorithm file: %s", err))
	}
	data, err := os.ReadFile(dataPath)
	if err != nil {
		log.Fatalf(fmt.Sprintf("failed to read data file: %s", err))
	}
	pubKey, err := os.ReadFile(pubKeyFile)
	if err != nil {
		log.Fatalf(fmt.Sprintf("failed to read public key file: %s", err))
	}
	pubPem, _ := pem.Decode(pubKey)
	algoHash := sha3.Sum256(algo)
	dataHash := sha3.Sum256(data)

	l, err := vsock.Listen(manager.ManagerVsockPort, nil)
	if err != nil {
		log.Fatal(err)
	}
	ac := agent.Computation{
		ID:              "123",
		Datasets:        agent.Datasets{agent.Dataset{Hash: dataHash, UserKey: pubPem.Bytes}},
		Algorithm:       agent.Algorithm{Hash: algoHash, UserKey: pubPem.Bytes},
		ResultConsumers: []agent.ResultConsumer{{UserKey: pubPem.Bytes}},
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

	var ac2 agent.Computation
	if err := json.Unmarshal(payload, &ac2); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return nil
}
