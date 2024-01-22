// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

//go:generate stringer -type=state
type state int

const (
	idle state = iota
	receivingManifests
	receivingAlgorithms
	receivingData
	running
	resultsReady
	complete
)

type event int

const (
	start event = iota
	manifestsReceived
	algorithmsReceived
	dataReceived
	runComplete
	resultsConsumed
)

// StateMachine represents the state machine.
type StateMachine struct {
	mu             sync.Mutex
	State          state
	EventChan      chan event
	Transitions    map[state]map[event]state
	StateFunctions map[state]func()
	logger         *slog.Logger
}

// NewStateMachine creates a new StateMachine.
func NewStateMachine(logger *slog.Logger) *StateMachine {
	sm := &StateMachine{
		State:          idle,
		EventChan:      make(chan event),
		Transitions:    make(map[state]map[event]state),
		StateFunctions: make(map[state]func()),
		logger:         logger,
	}

	sm.Transitions[idle] = make(map[event]state)
	sm.Transitions[idle][start] = receivingManifests

	sm.Transitions[receivingManifests] = make(map[event]state)
	sm.Transitions[receivingManifests][manifestsReceived] = receivingAlgorithms

	sm.Transitions[receivingAlgorithms] = make(map[event]state)
	sm.Transitions[receivingAlgorithms][algorithmsReceived] = receivingData

	sm.Transitions[receivingData] = make(map[event]state)
	sm.Transitions[receivingData][dataReceived] = running

	sm.Transitions[running] = make(map[event]state)
	sm.Transitions[running][runComplete] = resultsReady

	sm.Transitions[resultsReady] = make(map[event]state)
	sm.Transitions[resultsReady][resultsConsumed] = complete

	return sm
}

// Start the state machine.
func (sm *StateMachine) Start(ctx context.Context) {
	for {
		select {
		case event := <-sm.EventChan:
			nextState, valid := sm.Transitions[sm.GetState()][event]
			if valid {
				sm.mu.Lock()
				sm.State = nextState
				sm.mu.Unlock()
				sm.logger.Debug(fmt.Sprintf("Transition: %v -> %v\n", sm.GetState(), nextState))
			} else {
				sm.logger.Error(fmt.Sprintf("Invalid transition: %v -> ???\n", sm.GetState()))
			}
			stateFunc, exists := sm.StateFunctions[sm.GetState()]
			if exists {
				go stateFunc()
			}
		case <-ctx.Done():
			return
		}
	}
}

// SendEvent sends an event to the state machine.
func (sm *StateMachine) SendEvent(event event) {
	sm.EventChan <- event
}

func (sm *StateMachine) GetState() state {
	sm.mu.Lock()
	state := sm.State
	sm.mu.Unlock()
	return state
}

func (sm *StateMachine) SetState(state state) {
	sm.mu.Lock()
	sm.State = state
	sm.mu.Unlock()
}
