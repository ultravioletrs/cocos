// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestNewFilePersistence(t *testing.T) {
	tempDir := t.TempDir()

	fp, err := NewFilePersistence(tempDir)
	if err != nil {
		t.Fatalf("NewFilePersistence failed: %v", err)
	}

	if _, ok := fp.(*FilePersistence); !ok {
		t.Fatalf("NewFilePersistence didn't return a FilePersistence")
	}
}

func TestSaveVM(t *testing.T) {
	tempDir := t.TempDir()
	fp, _ := NewFilePersistence(tempDir)

	state := VMState{
		ID:     "test-vm",
		VMinfo: VMInfo{Config: Config{}},
		PID:    1234,
	}

	err := fp.SaveVM(state)
	if err != nil {
		t.Fatalf("SaveVM failed: %v", err)
	}

	// Check if file exists
	if _, err := os.Stat(filepath.Join(tempDir, "test-vm.json")); os.IsNotExist(err) {
		t.Fatalf("SaveVM didn't create a file")
	}
}

func TestLoadVMs(t *testing.T) {
	tempDir := t.TempDir()
	fp, _ := NewFilePersistence(tempDir)

	// Save two VMs
	states := []VMState{
		{ID: "vm1", VMinfo: VMInfo{Config: Config{}}, PID: 1234},
		{ID: "vm2", VMinfo: VMInfo{Config: Config{}}, PID: 5678},
	}

	for _, state := range states {
		if err := fp.SaveVM(state); err != nil {
			t.Fatalf("SaveVM failed: %v", err)
		}
	}

	// Load VMs
	loadedStates, err := fp.LoadVMs()
	if err != nil {
		t.Fatalf("LoadVMs failed: %v", err)
	}

	if len(loadedStates) != len(states) {
		t.Fatalf("LoadVMs returned %d states, expected %d", len(loadedStates), len(states))
	}

	// Check if loaded states match saved states
	for i, state := range states {
		if state.ID != loadedStates[i].ID || state.PID != loadedStates[i].PID {
			t.Fatalf("Loaded state %v doesn't match saved state %v", loadedStates[i], state)
		}
	}
}

func TestDeleteVM(t *testing.T) {
	tempDir := t.TempDir()
	fp, _ := NewFilePersistence(tempDir)

	state := VMState{ID: "test-vm", VMinfo: VMInfo{Config: Config{}}, PID: 1234}

	// Save VM
	if err := fp.SaveVM(state); err != nil {
		t.Fatalf("SaveVM failed: %v", err)
	}

	// Delete VM
	if err := fp.DeleteVM(state.ID); err != nil {
		t.Fatalf("DeleteVM failed: %v", err)
	}

	// Check if file is deleted
	if _, err := os.Stat(filepath.Join(tempDir, "test-vm.json")); !os.IsNotExist(err) {
		t.Fatalf("DeleteVM didn't remove the file")
	}
}

func TestLoadVMsWithInvalidFile(t *testing.T) {
	tempDir := t.TempDir()
	fp, _ := NewFilePersistence(tempDir)

	invalidData := []byte("{invalid json")
	if err := os.WriteFile(filepath.Join(tempDir, "invalid.json"), invalidData, 0o644); err != nil {
		t.Fatalf("Failed to create invalid JSON file: %v", err)
	}

	_, err := fp.LoadVMs()
	if err == nil {
		t.Fatalf("LoadVMs should have failed with invalid JSON")
	}
}

func TestConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	fp, _ := NewFilePersistence(tempDir)

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			state := VMState{ID: fmt.Sprintf("vm-%d", id), VMinfo: VMInfo{Config: Config{}}, PID: id}
			if err := fp.SaveVM(state); err != nil {
				t.Errorf("Concurrent SaveVM failed: %v", err)
			}
		}(i)

		go func() {
			defer wg.Done()
			if _, err := fp.LoadVMs(); err != nil {
				t.Errorf("Concurrent LoadVMs failed: %v", err)
			}
		}()
	}

	wg.Wait()
}
