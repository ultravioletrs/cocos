// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"fmt"
	"testing"
	"time"

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
		fromState State
		event     event
		expected  State
		cmp       Computation
	}{
		{Idle, start, ReceivingManifest, cmp},
		{ReceivingManifest, manifestReceived, ReceivingAlgorithm, cmp},
		{ReceivingAlgorithm, algorithmReceived, ReceivingData, cmp},
		{ReceivingAlgorithm, algorithmReceived, Running, Computation{}},
		{ReceivingData, dataReceived, Running, cmp},
		{Running, runComplete, ConsumingResults, cmp},
		{ConsumingResults, resultsConsumed, Complete, cmp},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("Transition from %v to %v", tc.fromState, tc.expected), func(t *testing.T) {
			sm := NewStateMachine(mglog.NewMock(), tc.cmp)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go sm.Start(ctx)

			time.Sleep(50 * time.Millisecond)

			sm.SetState(tc.fromState)
			sm.SendEvent(tc.event)

			time.Sleep(50 * time.Millisecond)

			if sm.GetState() != tc.expected {
				t.Errorf("Expected state %v after the event, but got %v", tc.expected, sm.GetState())
			}
		})
	}
}

func TestStateMachineInvalidTransition(t *testing.T) {
	sm := NewStateMachine(mglog.NewMock(), cmp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go sm.Start(ctx)

	time.Sleep(50 * time.Millisecond)

	sm.SetState(Idle)
	sm.SendEvent(dataReceived)

	time.Sleep(50 * time.Millisecond)

	if sm.GetState() != Idle {
		t.Errorf("State should not change on an invalid event, but got %v", sm.GetState())
	}
}
