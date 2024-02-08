// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"encoding/json"
	"fmt"
	"reflect"
)

var (
	_ fmt.Stringer = (*Datasets)(nil)
	_ fmt.Stringer = (*Algorithms)(nil)
)

type AgentConfig struct {
	LogLevel     string `json:"log_level"`
	Host         string `json:"host"`
	Port         string `json:"port"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"server_key"`
	ServerCAFile string `json:"server_ca_file"`
	ClientCAFile string `json:"client_ca_file"`
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

func containsID(slice interface{}, id string) int {
	rangeOnMe := reflect.ValueOf(slice)
	for i := 0; i < rangeOnMe.Len(); i++ {
		s := rangeOnMe.Index(i)
		f := s.FieldByName("ID")
		if f.IsValid() {
			if f.Interface() == id {
				return i
			}
		}
	}
	return -1
}
