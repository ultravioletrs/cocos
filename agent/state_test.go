package agent

import (
	"context"
	"testing"
	"time"

	"github.com/ultravioletrs/cocos/agent/statemachine"
)

type MockState int
type MockEvent int

func (s MockState) String() string {
	return []string{"State1", "State2", "State3"}[s]
}

func (e MockEvent) String() string {
	return []string{"Event1", "Event2", "Event3"}[e]
}

const (
	State1 MockState = iota
	State2
	State3
)

const (
	Event1 MockEvent = iota
	Event2
	Event3
)

func TestNewStateMachine(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	if sm == nil {
		t.Fatal("NewStateMachine returned nil")
	}
	if sm.GetState() != State1 {
		t.Errorf("Initial state not set correctly, got %v, want %v", sm.GetState(), State1)
	}
}

func TestAddTransition(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go sm.Start(ctx)
	sm.SendEvent(Event1)

	time.Sleep(50 * time.Millisecond)

	if sm.GetState() != State2 {
		t.Errorf("Transition not applied correctly, got state %v, want %v", sm.GetState(), State2)
	}
}

func TestSetAction(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	actionCalled := false
	sm.SetAction(State2, func(s statemachine.State) {
		actionCalled = true
	})
	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go sm.Start(ctx)
	sm.SendEvent(Event1)

	time.Sleep(50 * time.Millisecond)

	if !actionCalled {
		t.Error("Action was not called after transition")
	}
}

func TestInvalidTransition(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	errChan := make(chan error)
	go func() {
		errChan <- sm.Start(ctx)
	}()

	sm.SendEvent(Event2)

	select {
	case err := <-errChan:
		if err == nil {
			t.Errorf("Expected invalid transition error, got: %v", err)
		}
	case <-time.After(150 * time.Millisecond):
		t.Error("Timeout waiting for invalid transition error")
	}
}

func TestMultipleTransitions(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})
	sm.AddTransition(statemachine.Transition{From: State2, Event: Event2, To: State3})
	sm.AddTransition(statemachine.Transition{From: State3, Event: Event3, To: State1})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go sm.Start(ctx)

	transitions := []struct {
		event MockEvent
		want  MockState
	}{
		{Event1, State2},
		{Event2, State3},
		{Event3, State1},
	}

	for _, tt := range transitions {
		sm.SendEvent(tt.event)
		time.Sleep(50 * time.Millisecond)

		if sm.GetState() != tt.want {
			t.Errorf("After event %v, got state %v, want %v", tt.event, sm.GetState(), tt.want)
		}
	}
}

func TestConcurrency(t *testing.T) {
	sm := statemachine.NewStateMachine(State1)
	sm.AddTransition(statemachine.Transition{From: State1, Event: Event1, To: State2})
	sm.AddTransition(statemachine.Transition{From: State2, Event: Event2, To: State1})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go sm.Start(ctx)

	for i := 0; i < 100; i++ {
		go func() {
			sm.SendEvent(Event1)
			sm.SendEvent(Event2)
		}()
	}

	time.Sleep(400 * time.Millisecond)

	finalState := sm.GetState()
	if finalState != State1 && finalState != State2 {
		t.Errorf("Unexpected final state: %v", finalState)
	}
}
