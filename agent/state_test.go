// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"fmt"
	"testing"

	"github.com/mainflux/mainflux/logger"
)

func TestStateMachineTransitions(t *testing.T) {
	testCases := []struct {
		fromState state
		event     event
		expected  state
	}{
		{idle, start, receivingManifests},
		{receivingManifests, manifestsReceived, receivingAlgorithms},
		{receivingAlgorithms, algorithmsReceived, receivingData},
		{receivingData, dataReceived, running},
		{running, runComplete, resultsReady},
		{resultsReady, resultsConsumed, complete},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Transition from %v to %v", testCase.fromState, testCase.expected), func(t *testing.T) {
			sm := NewStateMachine(logger.NewMock())
			done := make(chan struct{})
			go func() {
				sm.Start()
				close(done)
			}()
			sm.State = testCase.fromState

			sm.SendEvent(testCase.event)

			if sm.State != testCase.expected {
				t.Errorf("Expected state %v after the event, but got %v", testCase.expected, sm.State)
			}
			close(sm.EventChan)
			<-done
		})
	}
}

func TestStateMachineInvalidTransition(t *testing.T) {
	sm := NewStateMachine(logger.NewMock())
	go sm.Start()

	sm.State = idle

	sm.SendEvent(dataReceived)

	if sm.State != idle {
		t.Errorf("State should not change on an invalid event, but got %v", sm.State)
	}
}
