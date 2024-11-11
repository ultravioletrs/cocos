// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	sync "sync"
	"testing"
	"time"

	"github.com/ultravioletrs/cocos/agent/statemachine"
)

type MockState int

type MockEvent int

func (s MockState) String() string {
	return []string{"State1", "State2", "State3"}[s]
}

func (e MockEvent) String() string {
	return []string{"Event1", "Event2", "Event3"}[e]
}

const (
	State1 MockState = iota
	State2
	State3
)

const (
	Event1 MockEvent = iota
	Event2
	Event3
)

func TestNewStateMachine(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	if sm == nil {
		t.Fatal("NewStateMachine returned nil")
	}
	if sm.GetState() != State1 {
		t.Errorf("Initial state not set correctly, got %v, want %v", sm.GetState(), State1)
	}
}

func TestAddTransition(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go func() {
		if err := sm.Start(ctx); err != context.Canceled {
			t.Errorf("Start returned error: %v", err)
		}
	}()

	sm.SendEvent(Event1)

	time.Sleep(50 * time.Millisecond)

	if sm.GetState() != State2 {
		t.Errorf("Transition not applied correctly, got state %v, want %v", sm.GetState(), State2)
	}
}

func TestSetAction(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)

	var wg sync.WaitGroup
	wg.Add(1)

	sm.SetAction(State2, func(s statemachine.State) {
		defer wg.Done()
	})

	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go func() {
		if err := sm.Start(ctx); err != context.Canceled {
			t.Errorf("Start returned error: %v", err)
		}
	}()

	sm.SendEvent(Event1)

	wg.Wait()

	if ctx.Err() != nil {
		t.Error("Action was not called within the expected time")
	}
}

func TestInvalidTransition(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	errChan := make(chan error)
	go func() {
		errChan <- sm.Start(ctx)
	}()

	sm.SendEvent(Event2)

	select {
	case err := <-errChan:
		if err == nil {
			t.Errorf("Expected invalid transition error, got: %v", err)
		}
	case <-time.After(150 * time.Millisecond):
		t.Error("Timeout waiting for invalid transition error")
	}
}

func TestMultipleTransitions(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})
	sm.AddTransition(statemachine.Transition{From: State2, Event: Event2, To: State3})
	sm.AddTransition(statemachine.Transition{From: State3, Event: Event3, To: State1})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go func() {
		if err := sm.Start(ctx); err != context.Canceled {
			t.Errorf("Start returned error: %v", err)
		}
	}()

	transitions := []struct {
		event MockEvent
		want  MockState
	}{
		{Event1, State2},
		{Event2, State3},
		{Event3, State1},
	}

	for _, tt := range transitions {
		sm.SendEvent(tt.event)
		time.Sleep(50 * time.Millisecond)

		if sm.GetState() != tt.want {
			t.Errorf("After event %v, got state %v, want %v", tt.event, sm.GetState(), tt.want)
		}
	}
}

func TestConcurrency(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})
	sm.AddTransition(statemachine.Transition{From: State2, Event: Event2, To: State1})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		if err := sm.Start(ctx); err == nil {
			t.Errorf("Expected context error, got nil")
		}
	}()

	for i := 0; i < 100; i++ {
		go func() {
			sm.SendEvent(Event1)
			sm.SendEvent(Event2)
		}()
	}

	time.Sleep(400 * time.Millisecond)

	finalState := sm.GetState()
	if finalState != State1 && finalState != State2 {
		t.Errorf("Unexpected final state: %v", finalState)
	}
}

func TestAgentEventString(t *testing.T) {
	tests := []struct {
		event AgentEvent
		want  string
	}{
		{Start, "Start"},
		{ManifestReceived, "ManifestReceived"},
		{AlgorithmReceived, "AlgorithmReceived"},
		{DataReceived, "DataReceived"},
		{RunComplete, "RunComplete"},
		{ResultsConsumed, "ResultsConsumed"},
		{RunFailed, "RunFailed"},
		{AgentEvent(-1), "AgentEvent(-1)"},
	}

	for _, tt := range tests {
		if got := tt.event.String(); got != tt.want {
			t.Errorf("AgentEvent.String() = %v, want %v", got, tt.want)
		}
	}
}

func TestAgentStateString(t *testing.T) {
	tests := []struct {
		state AgentState
		want  string
	}{
		{Idle, "Idle"},
		{ReceivingManifest, "ReceivingManifest"},
		{ReceivingAlgorithm, "ReceivingAlgorithm"},
		{ReceivingData, "ReceivingData"},
		{Running, "Running"},
		{ConsumingResults, "ConsumingResults"},
		{Complete, "Complete"},
		{Failed, "Failed"},
		{AgentState(-1), "AgentState(-1)"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("AgentState.String() = %v, want %v", got, tt.want)
		}
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{IdleState, "IdleState"},
		{InProgress, "InProgress"},
		{Ready, "Ready"},
		{Completed, "Completed"},
		{Terminated, "Terminated"},
		{Warning, "Warning"},
		{Starting, "Starting"},
		{Status(uint8(8)), "Status(8)"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("Status.String() = %v, want %v", got, tt.want)
		}
	}
}
