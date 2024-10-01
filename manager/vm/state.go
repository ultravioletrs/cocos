package vm

import (
	"errors"
	"sync"

	"github.com/ultravioletrs/cocos/pkg/manager"
)

type sm struct {
	sync.Mutex
	state manager.ManagerState
}

type StateMachine interface {
	Transition(newState manager.ManagerState) error
	State() string
}

func NewStateMachine() StateMachine {
	return &sm{state: manager.VmProvision}
}

func (sm *sm) Transition(newState manager.ManagerState) error {
	sm.Lock()
	defer sm.Unlock()
	switch sm.state {
	case manager.VmProvision:
		if newState == manager.VmRunning || newState == manager.StopComputationRun {
			sm.state = newState
			return nil
		}
	case manager.VmRunning:
		if newState == manager.StopComputationRun {
			sm.state = newState
			return nil
		}
	case manager.StopComputationRun:
		if newState == manager.VmRunning {
			sm.state = newState
			return nil
		}
	}
	return errors.New("invalid state transition")
}

func (sm *sm) State() string {
	sm.Lock()
	defer sm.Unlock()
	return sm.state.String()
}
