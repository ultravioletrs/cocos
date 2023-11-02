package agent

import (
	"testing"
	"time"

	"github.com/mainflux/mainflux/logger"
)

func TestXxx(t *testing.T) {
	sm := NewStateMachine(logger.NewMock())

	go sm.Start()

	sm.SendEvent(start)
	time.Sleep(1 * time.Second)
	sm.SendEvent(manifestsReceived)

	time.Sleep(1 * time.Second)
}
