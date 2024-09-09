// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"fmt"
	"testing"

	mglog "github.com/absmach/magistrala/logger"
)

var cmp = Computation{
	Datasets: []Dataset{
		{
			Dataset: []byte("test"),
			UserKey: []byte("test"),
		},
	},
}

func TestStateMachineTransitions(t *testing.T) {
	cases := []struct {
		fromState state
		event     event
		expected  state
		cmp       Computation
	}{
		{idle, start, receivingManifest, cmp},
		{receivingManifest, manifestReceived, receivingAlgorithm, cmp},
		{receivingAlgorithm, algorithmReceived, receivingData, cmp},
		{receivingAlgorithm, algorithmReceived, running, Computation{}},
		{receivingData, dataReceived, running, cmp},
		{running, runComplete, results, cmp},
		{results, resultsConsumed, complete, cmp},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("Transition from %v to %v", tc.fromState, tc.expected), func(t *testing.T) {
			sm := NewStateMachine(mglog.NewMock(), tc.cmp)
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				sm.Start(ctx)
			}()
			sm.wg.Wait()
			sm.SetState(tc.fromState)

			sm.SendEvent(tc.event)

			if sm.GetState() != tc.expected {
				t.Errorf("Expected state %v after the event, but got %v", tc.expected, sm.GetState())
			}
			close(sm.EventChan)
			cancel()
		})
	}
}

func TestStateMachineInvalidTransition(t *testing.T) {
	sm := NewStateMachine(mglog.NewMock(), cmp)
	ctx, cancel := context.WithCancel(context.Background())
	go sm.Start(ctx)

	sm.SetState(idle)

	sm.SendEvent(dataReceived)

	if sm.State != idle {
		t.Errorf("State should not change on an invalid event, but got %v", sm.State)
	}
	cancel()
}
