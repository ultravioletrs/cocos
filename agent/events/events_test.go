// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/agent/cvms"
)

func TestSendEventSuccess(t *testing.T) {
	queue := make(chan *cvms.ClientStreamMessage, 1)
	svc, err := New("test_service", queue)
	assert.NoError(t, err)

	details := json.RawMessage(`{"key": "value"}`)

	go func() {
		msg := <-queue
		assert.NotNil(t, msg)
		assert.NotNil(t, msg.GetAgentEvent())
		assert.Equal(t, "test_event", msg.GetAgentEvent().EventType)
		assert.Equal(t, "testid", msg.GetAgentEvent().ComputationId)
		assert.Equal(t, "test_service", msg.GetAgentEvent().Originator)
		assert.Equal(t, "success", msg.GetAgentEvent().Status)

		now := time.Now()
		eventTimestamp := msg.GetAgentEvent().GetTimestamp().AsTime()
		assert.WithinDuration(t, now, eventTimestamp, 1*time.Second)
	}()

	svc.SendEvent("testid", "test_event", "success", details)

	time.Sleep(1 * time.Second)
}
