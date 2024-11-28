// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

const jsonExt = ".json"

type VMState struct {
	ID     string
	Config Config
	PID    int
}

type FilePersistence struct {
	dir  string
	lock sync.Mutex
}

// Persistence is an interface for saving and loading VM states.
type Persistence interface {
	SaveVM(state VMState) error
	LoadVMs() ([]VMState, error)
	DeleteVM(id string) error
}

func NewFilePersistence(dir string) (Persistence, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FilePersistence{dir: dir}, nil
}

func (fp *FilePersistence) SaveVM(state VMState) error {
	fp.lock.Lock()
	defer fp.lock.Unlock()

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(fp.dir, state.ID+jsonExt), data, 0o644)
}

func (fp *FilePersistence) LoadVMs() ([]VMState, error) {
	fp.lock.Lock()
	defer fp.lock.Unlock()

	files, err := os.ReadDir(fp.dir)
	if err != nil {
		return nil, err
	}

	var states []VMState
	for _, file := range files {
		if filepath.Ext(file.Name()) != jsonExt {
			continue
		}

		data, err := os.ReadFile(filepath.Join(fp.dir, file.Name()))
		if err != nil {
			return nil, err
		}

		var state VMState
		if err := json.Unmarshal(data, &state); err != nil {
			return nil, err
		}

		states = append(states, state)
	}

	return states, nil
}

func (fp *FilePersistence) DeleteVM(id string) error {
	fp.lock.Lock()
	defer fp.lock.Unlock()

	return os.Remove(filepath.Join(fp.dir, id+jsonExt))
}
