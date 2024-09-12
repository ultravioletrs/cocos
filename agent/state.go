// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

//go:generate stringer -type=State
type State uint8

const (
	idle State = iota
	receivingManifest
	receivingAlgorithm
	receivingData
	running
	resultFetch
	complete
	failed
)

//go:generate stringer -type=Status
type Status uint8

const (
	idleState Status = iota
	inProgress
	ready
	completed
	terminated
)

type event uint8

const (
	start event = iota
	manifestReceived
	algorithmReceived
	dataReceived
	runComplete
	resultsConsumed
	runFailed
)

// StateMachine represents the state machine.
type StateMachine struct {
	mu             sync.Mutex
	State          State
	EventChan      chan event
	Transitions    map[State]map[event]State
	StateFunctions map[State]func()
	logger         *slog.Logger
	wg             *sync.WaitGroup
}

// NewStateMachine creates a new StateMachine.
func NewStateMachine(logger *slog.Logger, cmp Computation) *StateMachine {
	sm := &StateMachine{
		State:          idle,
		EventChan:      make(chan event),
		Transitions:    make(map[State]map[event]State),
		StateFunctions: make(map[State]func()),
		logger:         logger,
		wg:             &sync.WaitGroup{},
	}

	sm.Transitions[idle] = make(map[event]State)
	sm.Transitions[idle][start] = receivingManifest

	sm.Transitions[receivingManifest] = make(map[event]State)
	sm.Transitions[receivingManifest][manifestReceived] = receivingAlgorithm

	sm.Transitions[receivingAlgorithm] = make(map[event]State)
	switch len(cmp.Datasets) {
	case 0:
		sm.Transitions[receivingAlgorithm][algorithmReceived] = running
	default:
		sm.Transitions[receivingAlgorithm][algorithmReceived] = receivingData
	}

	sm.Transitions[receivingData] = make(map[event]State)
	sm.Transitions[receivingData][dataReceived] = running

	sm.Transitions[running] = make(map[event]State)
	sm.Transitions[running][runComplete] = resultFetch
	sm.Transitions[running][runFailed] = failed

	sm.Transitions[resultFetch] = make(map[event]State)
	sm.Transitions[resultFetch][resultsConsumed] = complete

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

func (sm *StateMachine) GetState() State {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.State
}

func (sm *StateMachine) SetState(state State) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.State = state
}
