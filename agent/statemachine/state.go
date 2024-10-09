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

//go:generate mockery --name StateMachine --output=mocks --filename state.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type StateMachine interface {
	AddTransition(t Transition)
	SetAction(state State, action Action)
	GetState() State
	SendEvent(event Event)
	Start(ctx context.Context) error
}

type stateMachine struct {
	mu           sync.Mutex
	currentState State
	transitions  map[State]map[Event]State
	actions      map[State]Action
	eventChan    chan Event
}

func NewStateMachine(initialState State) StateMachine {
	return &stateMachine{
		currentState: initialState,
		transitions:  make(map[State]map[Event]State),
		actions:      make(map[State]Action),
		eventChan:    make(chan Event),
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
	sm.eventChan <- event
}

func (sm *stateMachine) Start(ctx context.Context) error {
	for {
		select {
		case event := <-sm.eventChan:
			if err := sm.handleEvent(event); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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
