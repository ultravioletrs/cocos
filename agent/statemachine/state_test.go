// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package statemachine

import (
	"context"
	"sync"
	"testing"
	"time"
)

type testState string

func (s testState) String() string {
	return string(s)
}

type testEvent string

func (e testEvent) String() string {
	return string(e)
}

const (
	StateIdle    testState = "idle"
	StateRunning testState = "running"
	StatePaused  testState = "paused"
	StateStopped testState = "stopped"
	StateError   testState = "error"
)

const (
	EventStart testEvent = "start"
	EventPause testEvent = "pause"
	EventStop  testEvent = "stop"
	EventReset testEvent = "reset"
	EventError testEvent = "error"
)

func TestNewStateMachine(t *testing.T) {
	tests := []struct {
		name         string
		initialState State
		want         State
	}{
		{
			name:         "create with idle state",
			initialState: StateIdle,
			want:         StateIdle,
		},
		{
			name:         "create with running state",
			initialState: StateRunning,
			want:         StateRunning,
		},
		{
			name:         "create with custom state",
			initialState: testState("custom"),
			want:         testState("custom"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine(tt.initialState)
			if got := sm.GetState(); got != tt.want {
				t.Errorf("NewStateMachine() initial state = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStateMachine_AddTransition(t *testing.T) {
	tests := []struct {
		name        string
		transitions []Transition
		from        State
		event       Event
		expectTo    State
		expectValid bool
	}{
		{
			name: "single transition",
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
			},
			from:        StateIdle,
			event:       EventStart,
			expectTo:    StateRunning,
			expectValid: true,
		},
		{
			name: "multiple transitions from same state",
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
				{From: StateIdle, Event: EventError, To: StateError},
			},
			from:        StateIdle,
			event:       EventError,
			expectTo:    StateError,
			expectValid: true,
		},
		{
			name: "overwrite existing transition",
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
				{From: StateIdle, Event: EventStart, To: StatePaused}, // Overwrite
			},
			from:        StateIdle,
			event:       EventStart,
			expectTo:    StatePaused,
			expectValid: true,
		},
		{
			name: "transition not found",
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
			},
			from:        StateRunning,
			event:       EventPause,
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine(StateIdle).(*stateMachine)

			for _, transition := range tt.transitions {
				sm.AddTransition(transition)
			}

			sm.mu.Lock()
			nextState, valid := sm.transitions[tt.from][tt.event]
			sm.mu.Unlock()

			if valid != tt.expectValid {
				t.Errorf("Transition validity = %v, want %v", valid, tt.expectValid)
			}

			if tt.expectValid && nextState != tt.expectTo {
				t.Errorf("Transition destination = %v, want %v", nextState, tt.expectTo)
			}
		})
	}
}

func TestStateMachine_SetAction(t *testing.T) {
	tests := []struct {
		name         string
		state        State
		action       Action
		expectAction bool
	}{
		{
			name:  "set action for state",
			state: StateRunning,
			action: func(s State) {
			},
			expectAction: true,
		},
		{
			name:         "set nil action",
			state:        StatePaused,
			action:       nil,
			expectAction: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine(StateIdle).(*stateMachine)
			sm.SetAction(tt.state, tt.action)

			sm.mu.Lock()
			action := sm.actions[tt.state]
			sm.mu.Unlock()

			if tt.expectAction && action == nil {
				t.Error("Expected action to be set, but it was nil")
			}
			if !tt.expectAction && action != nil {
				t.Error("Expected action to be nil, but it was set")
			}
		})
	}
}

func TestStateMachine_GetState(t *testing.T) {
	tests := []struct {
		name         string
		initialState State
		transitions  []Transition
		events       []Event
		finalState   State
	}{
		{
			name:         "get initial state",
			initialState: StateIdle,
			finalState:   StateIdle,
		},
		{
			name:         "get state after transition",
			initialState: StateIdle,
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
			},
			events:     []Event{EventStart},
			finalState: StateRunning,
		},
		{
			name:         "get state after multiple transitions",
			initialState: StateIdle,
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
				{From: StateRunning, Event: EventPause, To: StatePaused},
				{From: StatePaused, Event: EventStart, To: StateRunning},
			},
			events:     []Event{EventStart, EventPause, EventStart},
			finalState: StateRunning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine(tt.initialState)

			for _, transition := range tt.transitions {
				sm.AddTransition(transition)
			}

			smImpl := sm.(*stateMachine)
			for _, event := range tt.events {
				if err := smImpl.handleEvent(event); err != nil {
					t.Fatalf("Failed to handle event %v: %v", event, err)
				}
			}

			if got := sm.GetState(); got != tt.finalState {
				t.Errorf("GetState() = %v, want %v", got, tt.finalState)
			}
		})
	}
}

func TestStateMachine_Start(t *testing.T) {
	tests := []struct {
		name           string
		initialState   State
		transitions    []Transition
		events         []Event
		cancelAfter    time.Duration
		expectError    bool
		expectedStates []State
	}{
		{
			name:         "start and cancel immediately",
			initialState: StateIdle,
			cancelAfter:  10 * time.Millisecond,
			expectError:  true, // context.Canceled
		},
		{
			name:         "process events then cancel",
			initialState: StateIdle,
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
				{From: StateRunning, Event: EventStop, To: StateStopped},
			},
			events:         []Event{EventStart, EventStop},
			cancelAfter:    100 * time.Millisecond,
			expectError:    true, // context.Canceled
			expectedStates: []State{StateRunning, StateStopped},
		},
		{
			name:         "invalid transition error",
			initialState: StateIdle,
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
			},
			events:      []Event{EventPause}, // Invalid from StateIdle
			cancelAfter: 50 * time.Millisecond,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine(tt.initialState)

			for _, transition := range tt.transitions {
				sm.AddTransition(transition)
			}

			var states []State
			var mu sync.Mutex

			for _, state := range tt.expectedStates {
				sm.SetAction(state, func(s State) {
					mu.Lock()
					states = append(states, s)
					mu.Unlock()
				})
			}

			ctx, cancel := context.WithCancel(context.Background())

			errChan := make(chan error, 1)
			go func() {
				errChan <- sm.Start(ctx)
			}()

			for _, event := range tt.events {
				sm.SendEvent(event)
			}

			time.Sleep(tt.cancelAfter)
			cancel()

			err := <-errChan

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			time.Sleep(10 * time.Millisecond)

			mu.Lock()
			if len(states) != len(tt.expectedStates) {
				t.Errorf("Expected %d state changes, got %d", len(tt.expectedStates), len(states))
			}
			for i, expectedState := range tt.expectedStates {
				if i < len(states) && states[i] != expectedState {
					t.Errorf("State change %d = %v, want %v", i, states[i], expectedState)
				}
			}
			mu.Unlock()
		})
	}
}

func TestStateMachine_Reset(t *testing.T) {
	tests := []struct {
		name              string
		initialState      State
		resetState        State
		setupTransitions  []Transition
		eventsBeforeReset []Event
		eventsAfterReset  []Event
		expectedState     State
	}{
		{
			name:          "reset to same state",
			initialState:  StateIdle,
			resetState:    StateIdle,
			expectedState: StateIdle,
		},
		{
			name:          "reset to different state",
			initialState:  StateIdle,
			resetState:    StateRunning,
			expectedState: StateRunning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine(tt.initialState)
			smImpl := sm.(*stateMachine)

			for _, transition := range tt.setupTransitions {
				sm.AddTransition(transition)
			}

			for _, event := range tt.eventsBeforeReset {
				if err := smImpl.handleEvent(event); err != nil {
					// Ignore errors for this test
				}
			}

			for _, event := range tt.eventsBeforeReset {
				sm.SendEvent(event)
			}

			sm.Reset(tt.resetState)

			if got := sm.GetState(); got != tt.expectedState {
				t.Errorf("State after reset = %v, want %v", got, tt.expectedState)
			}

			for _, event := range tt.eventsAfterReset {
				sm.SendEvent(event)
			}

			if len(tt.eventsAfterReset) > 0 && len(smImpl.eventChan) != len(tt.eventsAfterReset) {
				t.Errorf("New event channel size = %d, want %d", len(smImpl.eventChan), len(tt.eventsAfterReset))
			}
		})
	}
}

func TestStateMachine_HandleEvent(t *testing.T) {
	tests := []struct {
		name             string
		initialState     State
		transitions      []Transition
		event            Event
		expectedState    State
		expectError      bool
		expectActionCall bool
	}{
		{
			name:         "valid transition",
			initialState: StateIdle,
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
			},
			event:            EventStart,
			expectedState:    StateRunning,
			expectError:      false,
			expectActionCall: true,
		},
		{
			name:         "invalid transition",
			initialState: StateIdle,
			transitions: []Transition{
				{From: StateRunning, Event: EventPause, To: StatePaused},
			},
			event:            EventStart,
			expectedState:    StateIdle,
			expectError:      true,
			expectActionCall: false,
		},
		{
			name:         "transition with no action",
			initialState: StateIdle,
			transitions: []Transition{
				{From: StateIdle, Event: EventStart, To: StateRunning},
			},
			event:            EventStart,
			expectedState:    StateRunning,
			expectError:      false,
			expectActionCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine(tt.initialState).(*stateMachine)

			for _, transition := range tt.transitions {
				sm.AddTransition(transition)
			}

			var actionCalled bool
			var mu sync.Mutex

			if tt.expectActionCall {
				sm.SetAction(tt.expectedState, func(s State) {
					mu.Lock()
					actionCalled = true
					mu.Unlock()
				})
			}

			err := sm.handleEvent(tt.event)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if sm.GetState() != tt.expectedState {
				t.Errorf("State after handleEvent = %v, want %v", sm.GetState(), tt.expectedState)
			}

			if tt.expectActionCall {
				time.Sleep(10 * time.Millisecond)
				mu.Lock()
				called := actionCalled
				mu.Unlock()
				if !called {
					t.Error("Expected action to be called but it wasn't")
				}
			}
		})
	}
}
