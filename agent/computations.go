// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	reflect "reflect"
	"time"
)

type Computation struct {
	ID              string      `json:"id,omitempty"`
	Name            string      `json:"name,omitempty"`
	Description     string      `json:"description,omitempty"`
	Status          string      `json:"status,omitempty"`
	Owner           string      `json:"owner,omitempty"`
	StartTime       time.Time   `json:"start_time,omitempty"`
	EndTime         time.Time   `json:"end_time,omitempty"`
	Datasets        []Dataset   `json:"datasets,omitempty"`
	Algorithms      []Algorithm `json:"algorithms,omitempty"`
	ResultConsumers []string    `json:"result_consumers,omitempty"`
	Ttl             int32       `json:"ttl,omitempty"`
	Metadata        Metadata    `json:"metadata,omitempty"`
}

type Dataset struct {
	Dataset  []byte `json:"-"`
	Provider string `json:"provider,omitempty"`
	ID       string `json:"id,omitempty"`
}

type Algorithm struct {
	Algorithm []byte `json:"-"`
	Provider  string `json:"provider,omitempty"`
	ID        string `json:"id,omitempty"`
}

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
