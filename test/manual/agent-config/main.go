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
)

const VsockConfigPort uint32 = 9999

type AgentConfig struct {
	LogLevel   string `json:"log_level"`
	InstanceID string `json:"instance_id"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"server_key"`
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
	l, err := vsock.Listen(9997, nil)
	if err != nil {
		log.Fatal(err)
	}
	l2, err := vsock.Listen(9998, nil)
	if err != nil {
		log.Fatal(err)
	}
	ac := Computation{
		ID:              "123",
		Datasets:        Datasets{Dataset{ID: "1", Provider: "pr1"}},
		Algorithms:      Algorithms{Algorithm{ID: "1", Provider: "pr1"}},
		ResultConsumers: []string{"1"},
		AgentConfig: AgentConfig{
			LogLevel: "debug",
			Port:     "7002",
		},
	}
	fmt.Println(SendAgentConfig(3, ac))

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			b := make([]byte, 1024)
			n, err := conn.Read(b)
			if err != nil {
				continue
			}
			conn.Close()
			fmt.Println(string(b[:n]))
		}
	}()
	for {
		conn, err := l2.Accept()
		if err != nil {
			continue
		}
		b := make([]byte, 1024)
		n, err := conn.Read(b)
		if err != nil {
			continue
		}
		conn.Close()
		fmt.Println(string(b[:n]))
	}
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
