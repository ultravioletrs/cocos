// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewTTLManager(t *testing.T) {
	tm := NewTTLManager()

	if tm == nil {
		t.Fatal("NewTTLManager() returned nil")
	}

	if tm.timers == nil {
		t.Fatal("NewTTLManager() did not initialize timers map")
	}

	if len(tm.timers) != 0 {
		t.Errorf("NewTTLManager() timers map should be empty, got %d entries", len(tm.timers))
	}
}

func TestSetTTL_Basic(t *testing.T) {
	tm := NewTTLManager()

	mu := sync.Mutex{}
	expired := false
	vmID := "test-vm-1"
	ttl := 50 * time.Millisecond

	cancelFunc := tm.SetTTL(vmID, ttl, func() {
		mu.Lock()
		defer mu.Unlock()
		expired = true
	})

	tm.mu.RLock()
	if _, exists := tm.timers[vmID]; !exists {
		t.Error("Timer was not created for VM")
	}
	tm.mu.RUnlock()

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if !expired {
		t.Error("TTL did not expire as expected")
	}
	mu.Unlock()

	cancelFunc()

	tm.mu.RLock()
	if _, exists := tm.timers[vmID]; exists {
		t.Error("Timer should be cleaned up after expiry")
	}
	tm.mu.RUnlock()
}

func TestSetTTL_CancelBeforeExpiry(t *testing.T) {
	tm := NewTTLManager()

	expired := false
	vmID := "test-vm-2"
	ttl := 100 * time.Millisecond

	cancelFunc := tm.SetTTL(vmID, ttl, func() {
		expired = true
	})

	time.Sleep(20 * time.Millisecond)
	cancelFunc()

	time.Sleep(150 * time.Millisecond)

	if expired {
		t.Error("TTL should not have expired after being cancelled")
	}

	tm.mu.RLock()
	if _, exists := tm.timers[vmID]; exists {
		t.Error("Timer should be cleaned up after cancellation")
	}
	tm.mu.RUnlock()
}

func TestSetTTL_OverwriteExistingTimer(t *testing.T) {
	tm := NewTTLManager()

	mu := sync.Mutex{}
	firstExpired := false
	secondExpired := false
	vmID := "test-vm-3"

	// Set first TTL
	tm.SetTTL(vmID, 200*time.Millisecond, func() {
		firstExpired = true
	})

	// Immediately overwrite with second TTL
	tm.SetTTL(vmID, 50*time.Millisecond, func() {
		mu.Lock()
		defer mu.Unlock()
		secondExpired = true
	})

	// Wait for second TTL to expire
	time.Sleep(100 * time.Millisecond)

	if firstExpired {
		t.Error("First TTL should not have expired (it was overwritten)")
	}

	mu.Lock()
	if !secondExpired {
		t.Error("Second TTL should have expired")
	}
	mu.Unlock()

	// Verify only one timer entry exists (or none after cleanup)
	tm.mu.RLock()
	count := len(tm.timers)
	tm.mu.RUnlock()

	if count > 1 {
		t.Errorf("Expected at most 1 timer entry, got %d", count)
	}
}

func TestSetTTL_MultipleConcurrentTimers(t *testing.T) {
	tm := NewTTLManager()

	numVMs := 5
	expiredCount := int32(0)
	var mu sync.Mutex

	for i := 0; i < numVMs; i++ {
		vmID := fmt.Sprintf("vm-%d", i)
		tm.SetTTL(vmID, 50*time.Millisecond, func() {
			mu.Lock()
			expiredCount++
			mu.Unlock()
		})
	}

	tm.mu.RLock()
	if len(tm.timers) != numVMs {
		t.Errorf("Expected %d timers, got %d", numVMs, len(tm.timers))
	}
	tm.mu.RUnlock()

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	finalCount := expiredCount
	mu.Unlock()

	if int(finalCount) != numVMs {
		t.Errorf("Expected %d timers to expire, got %d", numVMs, finalCount)
	}
}

func TestCancelTTL_ExistingTimer(t *testing.T) {
	tm := NewTTLManager()

	expired := false
	vmID := "test-vm-4"

	tm.SetTTL(vmID, 100*time.Millisecond, func() {
		expired = true
	})

	// Cancel the timer
	tm.CancelTTL(vmID)

	time.Sleep(150 * time.Millisecond)

	if expired {
		t.Error("TTL should not have expired after being cancelled")
	}

	// Verify timer was removed
	tm.mu.RLock()
	if _, exists := tm.timers[vmID]; exists {
		t.Error("Timer should be removed after cancellation")
	}
	tm.mu.RUnlock()
}

func TestCancelTTL_NonExistentTimer(t *testing.T) {
	tm := NewTTLManager()

	// Should not panic when cancelling non-existent timer
	tm.CancelTTL("non-existent-vm")

	// Verify timers map is still empty
	tm.mu.RLock()
	if len(tm.timers) != 0 {
		t.Errorf("Expected empty timers map, got %d entries", len(tm.timers))
	}
	tm.mu.RUnlock()
}

func TestCancelAll_MultipleTimers(t *testing.T) {
	tm := NewTTLManager()

	numVMs := 3
	expiredCount := int32(0)
	var mu sync.Mutex

	for i := 0; i < numVMs; i++ {
		vmID := fmt.Sprintf("vm-%d", i)
		tm.SetTTL(vmID, 200*time.Millisecond, func() {
			mu.Lock()
			expiredCount++
			mu.Unlock()
		})
	}

	tm.mu.RLock()
	if len(tm.timers) != numVMs {
		t.Errorf("Expected %d timers, got %d", numVMs, len(tm.timers))
	}
	tm.mu.RUnlock()

	tm.CancelAll()

	tm.mu.RLock()
	if len(tm.timers) != 0 {
		t.Errorf("Expected 0 timers after CancelAll, got %d", len(tm.timers))
	}
	tm.mu.RUnlock()

	time.Sleep(250 * time.Millisecond)

	mu.Lock()
	finalCount := expiredCount
	mu.Unlock()

	if finalCount != 0 {
		t.Errorf("Expected 0 timers to expire after CancelAll, got %d", finalCount)
	}
}

func TestCancelAll_EmptyManager(t *testing.T) {
	tm := NewTTLManager()

	tm.CancelAll()

	tm.mu.RLock()
	if len(tm.timers) != 0 {
		t.Errorf("Expected empty timers map, got %d entries", len(tm.timers))
	}
	tm.mu.RUnlock()
}

func TestConcurrentAccess(t *testing.T) {
	tm := NewTTLManager()

	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			vmID := fmt.Sprintf("concurrent-vm-%d", id)
			cancelFunc := tm.SetTTL(vmID, 100*time.Millisecond, func() {})

			// Sometimes cancel immediately
			if id%2 == 0 {
				cancelFunc()
			}
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			vmID := fmt.Sprintf("concurrent-vm-%d", id)
			time.Sleep(10 * time.Millisecond)
			tm.CancelTTL(vmID)
		}(i)
	}

	wg.Wait()

	tm.CancelAll()

	// This test primarily checks that no race conditions occur
	// The actual state at the end is unpredictable due to timing
}

func TestSetTTL_ZeroDuration(t *testing.T) {
	tm := NewTTLManager()

	mu := sync.Mutex{}
	expired := false
	vmID := "zero-duration-vm"

	tm.SetTTL(vmID, 0, func() {
		mu.Lock()
		defer mu.Unlock()
		expired = true
	})

	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	if !expired {
		t.Error("TTL with zero duration should expire immediately")
	}
	mu.Unlock()
}

func TestSetTTL_NegativeDuration(t *testing.T) {
	tm := NewTTLManager()

	mu := sync.Mutex{}
	expired := false
	vmID := "negative-duration-vm"

	tm.SetTTL(vmID, -100*time.Millisecond, func() {
		mu.Lock()
		defer mu.Unlock()
		expired = true
	})

	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if !expired {
		t.Error("TTL with negative duration should expire immediately")
	}
}
