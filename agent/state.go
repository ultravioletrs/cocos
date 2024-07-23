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
type state uint8

const (
	idle state = iota
	receivingManifest
	receivingAlgorithm
	receivingData
	running
	resultsReady
	complete
)

type event uint8

const (
	start event = iota
	manifestReceived
	algorithmReceived
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
	wg             *sync.WaitGroup
}

// NewStateMachine creates a new StateMachine.
func NewStateMachine(logger *slog.Logger, cmp Computation) *StateMachine {
	sm := &StateMachine{
		State:          idle,
		EventChan:      make(chan event),
		Transitions:    make(map[state]map[event]state),
		StateFunctions: make(map[state]func()),
		logger:         logger,
		wg:             &sync.WaitGroup{},
	}

	sm.Transitions[idle] = make(map[event]state)
	sm.Transitions[idle][start] = receivingManifest

	sm.Transitions[receivingManifest] = make(map[event]state)
	sm.Transitions[receivingManifest][manifestReceived] = receivingAlgorithm

	sm.Transitions[receivingAlgorithm] = make(map[event]state)
	switch len(cmp.Datasets) {
	case 0:
		sm.Transitions[receivingAlgorithm][algorithmReceived] = running
	default:
		sm.Transitions[receivingAlgorithm][algorithmReceived] = receivingData
	}

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
	sm.wg.Add(1)
	defer sm.wg.Done()
	for {
		select {
		case event := <-sm.EventChan:
			sm.mu.Lock()
			nextState, valid := sm.Transitions[sm.State][event]
			if valid {
				sm.State = nextState
				sm.logger.Debug(fmt.Sprintf("Transition: %v -> %v\n", sm.State, nextState))
			} else {
				sm.logger.Error(fmt.Sprintf("Invalid transition: %v -> ???\n", sm.State))
			}
			sm.mu.Unlock()

			sm.mu.Lock()
			stateFunc, exists := sm.StateFunctions[sm.State]
			sm.mu.Unlock()
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
	defer sm.mu.Unlock()
	return sm.State
}

func (sm *StateMachine) SetState(state state) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.State = state
}
