// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"errors"

	"github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/messaging"
)

const agentTopic = "channels.agent.>"

var errUnexpectedEvent = errors.New("unexpected event from agent")

func NewAgentEventNotifier(ctx context.Context, pubsub messaging.PubSub, logger logger.Logger) error {
	if err := pubsub.Subscribe(ctx, messaging.SubscriberConfig{
		ID:             "manager",
		Topic:          agentTopic,
		DeliveryPolicy: messaging.DeliverAllPolicy,
		Handler:        &eventHandler{logger: logger},
	}); err != nil {
		return err
	}
	return nil
}

type eventHandler struct {
	logger logger.Logger
}

func (ev *eventHandler) Handle(msg *messaging.Message) error {
	switch msg.Subtopic {
	case "idle":
		ev.logger.Info("agent is running and idle")
	case "run":
		ev.logger.Info("agent is ready to receive computation manifest")
	case "algorithms":
		ev.logger.Info("agent is ready to receive algorithms")
	case "datasets":
		ev.logger.Info("agent is ready to receive datasets")
	case "results":
		ev.logger.Info("agent computation results are ready")
	case "running":
		ev.logger.Info("agent computation is running")
	case "complete":
		ev.logger.Info("agent computation results have been consumed")
	default:
		ev.logger.Error("unexpected event from agent")
		return errUnexpectedEvent
	}
	return nil
}

func (*eventHandler) Cancel() error {
	return nil
}
