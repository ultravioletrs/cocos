// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	sync "sync"
	"time"
)

// TTLManager handles TTL functionality for VMs.
type TTLManager struct {
	timers map[string]*time.Timer
	mu     sync.RWMutex
}

// NewTTLManager creates a new TTL manager.
func NewTTLManager() *TTLManager {
	return &TTLManager{
		timers: make(map[string]*time.Timer),
	}
}

// SetTTL sets a TTL for a VM and returns a function to cancel it.
func (tm *TTLManager) SetTTL(vmID string, ttl time.Duration, onExpiry func()) context.CancelFunc {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if timer, exists := tm.timers[vmID]; exists {
		timer.Stop()
	}

	timer := time.AfterFunc(ttl, onExpiry)
	tm.timers[vmID] = timer

	return func() {
		tm.mu.Lock()
		defer tm.mu.Unlock()
		if t, exists := tm.timers[vmID]; exists {
			t.Stop()
			delete(tm.timers, vmID)
		}
	}
}

// CancelTTL cancels the TTL for a specific VM.
func (tm *TTLManager) CancelTTL(vmID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if timer, exists := tm.timers[vmID]; exists {
		timer.Stop()
		delete(tm.timers, vmID)
	}
}

// CancelAll cancels all active TTLs.
func (tm *TTLManager) CancelAll() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for vmID, timer := range tm.timers {
		timer.Stop()
		delete(tm.timers, vmID)
	}
}
