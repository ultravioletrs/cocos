// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"fmt"
)

var _ fmt.Stringer = (*Datasets)(nil)

type AgentConfig struct {
	LogLevel     string `json:"log_level"`
	Host         string `json:"host"`
	Port         string `json:"port"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"server_key"`
	ServerCAFile string `json:"server_ca_file"`
	ClientCAFile string `json:"client_ca_file"`
	AttestedTls  bool   `json:"attested_tls"`
}

type Computation struct {
	ID              string           `json:"id,omitempty"`
	Name            string           `json:"name,omitempty"`
	Description     string           `json:"description,omitempty"`
	Datasets        Datasets         `json:"datasets,omitempty"`
	Algorithm       Algorithm        `json:"algorithm,omitempty"`
	ResultConsumers []ResultConsumer `json:"result_consumers,omitempty"`
	AgentConfig     AgentConfig      `json:"agent_config,omitempty"`
}

type ResultConsumer struct {
	UserKey []byte `json:"user_key,omitempty"`
}

func (d *Datasets) String() string {
	dat, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(dat)
}

type Dataset struct {
	Dataset []byte   `json:"-"`
	Hash    [32]byte `json:"hash,omitempty"`
	UserKey []byte   `json:"user_key,omitempty"`
}

type Datasets []Dataset

type Algorithm struct {
	Algorithm []byte   `json:"-"`
	Hash      [32]byte `json:"hash,omitempty"`
	UserKey   []byte   `json:"user_key,omitempty"`
}

type ManifestIndexKey struct{}

func IndexToContext(ctx context.Context, index int) context.Context {
	return context.WithValue(ctx, ManifestIndexKey{}, index)
}

func IndexFromContext(ctx context.Context) (int, bool) {
	index, ok := ctx.Value(ManifestIndexKey{}).(int)
	return index, ok
}
