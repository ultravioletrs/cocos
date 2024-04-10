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
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
)

const VsockConfigPort uint32 = 9999

type AgentConfig struct {
	LogLevel    string `json:"log_level"`
	InstanceID  string `json:"instance_id"`
	Host        string `json:"host"`
	Port        string `json:"port"`
	CertFile    string `json:"cert_file"`
	KeyFile     string `json:"server_key"`
	AttestedTls bool   `json:"attested_tls"`
}

type Computation struct {
	ID              string      `json:"id,omitempty"`
	Name            string      `json:"name,omitempty"`
	Description     string      `json:"description,omitempty"`
	Datasets        Datasets    `json:"datasets,omitempty"`
	Algorithms      Algorithms  `json:"algorithms,omitempty"`
	ResultConsumers []string    `json:"result_consumers,omitempty"`
	AgentConfig     AgentConfig `json:"agent_config,omitempty"`
}

func (d *Datasets) String() string {
	dat, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(dat)
}

func (a *Algorithms) String() string {
	dat, err := json.Marshal(a)
	if err != nil {
		return ""
	}
	return string(dat)
}

type Dataset struct {
	Dataset  []byte `json:"-"`
	Provider string `json:"provider,omitempty"`
	ID       string `json:"id,omitempty"`
}

type Datasets []Dataset

type Algorithm struct {
	Algorithm []byte `json:"-"`
	Provider  string `json:"provider,omitempty"`
	ID        string `json:"id,omitempty"`
}

type Algorithms []Algorithm

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

	l, err := vsock.Listen(9997, nil)
	if err != nil {
		log.Fatal(err)
	}
	ac := Computation{
		ID:              "123",
		Datasets:        Datasets{Dataset{ID: "1", Provider: "pr1"}},
		Algorithms:      Algorithms{Algorithm{ID: "1", Provider: "pr1"}},
		ResultConsumers: []string{"1"},
		AgentConfig: AgentConfig{
			LogLevel:    "debug",
			Port:        "7002",
			AttestedTls: attestedTLS,
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

func SendAgentConfig(cid uint32, ac Computation) error {
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
