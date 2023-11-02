package agent

import (
	"fmt"

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

// StateMachine represents the state machine
type StateMachine struct {
	State          state
	EventChan      chan event
	Transitions    map[state]map[event]state
	StateFunctions map[state]func()
	logger         logger.Logger
}

// NewStateMachine creates a new StateMachine
func NewStateMachine(logger logger.Logger) *StateMachine {
	sm := &StateMachine{
		State:          idle,
		EventChan:      make(chan event),
		Transitions:    make(map[state]map[event]state),
		StateFunctions: make(map[state]func()),
		logger:         logger,
	}

	// Define state transitions
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

// Start the state machine
func (sm *StateMachine) Start() {
	for event := range sm.EventChan {
		nextState, valid := sm.Transitions[sm.State][event]
		if valid {
			sm.State = nextState
			sm.logger.Debug(fmt.Sprintf("Transition: %v -> %v\n", sm.State, nextState))
		} else {
			sm.logger.Error(fmt.Sprintf("Invalid transition: %v -> ???\n", sm.State))
		}

		stateFunc, exists := sm.StateFunctions[sm.State]
		if exists {
			stateFunc()
		}
	}
}

// SendEvent sends an event to the state machine
func (sm *StateMachine) SendEvent(event event) {
	sm.EventChan <- event
}
