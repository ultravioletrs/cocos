// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package statemachine

import (
	"context"
	"fmt"
	"sync"
)

type State interface {
	String() string
}

type Event interface {
	String() string
}

type Action func(State)

type Transition struct {
	From  State
	Event Event
	To    State
}

type StateMachine interface {
	AddTransition(t Transition)
	SetAction(state State, action Action)
	GetState() State
	SendEvent(event Event)
	Start(ctx context.Context) error
	Reset(initialState State)
}

type stateMachine struct {
	mu           sync.Mutex
	currentState State
	transitions  map[State]map[Event]State
	actions      map[State]Action
	eventChan    chan Event
	resetChan    chan struct{}
}

func NewStateMachine(initialState State) StateMachine {
	return &stateMachine{
		currentState: initialState,
		transitions:  make(map[State]map[Event]State),
		actions:      make(map[State]Action),
		eventChan:    make(chan Event),
		resetChan:    make(chan struct{}),
	}
}

func (sm *stateMachine) AddTransition(t Transition) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, ok := sm.transitions[t.From]; !ok {
		sm.transitions[t.From] = make(map[Event]State)
	}
	sm.transitions[t.From][t.Event] = t.To
}

func (sm *stateMachine) SetAction(state State, action Action) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.actions[state] = action
}

func (sm *stateMachine) GetState() State {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.currentState
}

func (sm *stateMachine) SendEvent(event Event) {
	sm.mu.Lock()
	eventChan := sm.eventChan
	sm.mu.Unlock()

	select {
	case eventChan <- event:
	default:
		// Channel might be closed or full, ignore the event
	}
}

func (sm *stateMachine) Start(ctx context.Context) error {
	for {
		sm.mu.Lock()
		eventChan := sm.eventChan
		resetChan := sm.resetChan
		sm.mu.Unlock()

		select {
		case event := <-eventChan:
			if err := sm.handleEvent(event); err != nil {
				return err
			}
		case <-resetChan:
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (sm *stateMachine) Reset(initialState State) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Reset current state to initial state
	sm.currentState = initialState

	// Close the existing event channel to stop processing events
	close(sm.eventChan)

	// Close the reset channel to signal Start() to restart
	close(sm.resetChan)

	sm.eventChan = make(chan Event)
	sm.resetChan = make(chan struct{})
}

func (sm *stateMachine) handleEvent(event Event) error {
	sm.mu.Lock()
	currentState := sm.currentState
	nextState, valid := sm.transitions[currentState][event]
	sm.mu.Unlock()

	if !valid {
		return fmt.Errorf("invalid transition: %v -> %v", currentState, event)
	}

	sm.mu.Lock()
	sm.currentState = nextState
	action := sm.actions[nextState]
	sm.mu.Unlock()

	if action != nil {
		go action(nextState)
	}

	return nil
}
