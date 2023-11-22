// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"
)

var (
	_ fmt.Stringer = (*Datasets)(nil)
	_ fmt.Stringer = (*Algorithms)(nil)
)

type Computation struct {
	ID              string     `json:"id,omitempty"`
	Name            string     `json:"name,omitempty"`
	Description     string     `json:"description,omitempty"`
	Status          string     `json:"status,omitempty"`
	Owner           string     `json:"owner,omitempty"`
	StartTime       time.Time  `json:"start_time,omitempty"`
	EndTime         time.Time  `json:"end_time,omitempty"`
	Datasets        Datasets   `json:"datasets,omitempty"`
	Algorithms      Algorithms `json:"algorithms,omitempty"`
	ResultConsumers []string   `json:"result_consumers,omitempty"`
	Ttl             int32      `json:"ttl,omitempty"`
	Metadata        Metadata   `json:"metadata,omitempty"`
	Timeout         Duration   `json:"timeout,omitempty"`
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

type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}

type Metadata map[string]interface{}

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
