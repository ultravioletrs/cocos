// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/mainflux/mainflux/logger"
)

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
	sync.Mutex
	State          state
	EventChan      chan event
	Transitions    map[state]map[event]state
	StateFunctions map[state]func()
	logger         logger.Logger
}

// NewStateMachine creates a new StateMachine.
func NewStateMachine(logger logger.Logger) *StateMachine {
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
				sm.Lock()
				sm.State = nextState
				sm.Unlock()
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
	select {
	case sm.EventChan <- event:
	default:
		sm.logger.Error("event channel is full")
	}
}

func (sm *StateMachine) GetState() state {
	sm.Lock()
	state := sm.State
	sm.Unlock()
	return state
}
