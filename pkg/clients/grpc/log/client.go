// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package log

import (
	"context"
	"time"

	"github.com/ultravioletrs/cocos/agent/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Client interface {
	SendLog(ctx context.Context, entry *log.LogEntry) error
	SendEvent(ctx context.Context, entry *log.EventEntry) error
	Close() error
}

type client struct {
	conn   *grpc.ClientConn
	client log.LogCollectorClient
}

func NewClient(socketPath string) (Client, error) {
	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &client{
		conn:   conn,
		client: log.NewLogCollectorClient(conn),
	}, nil
}

func (c *client) Close() error {
	return c.conn.Close()
}

func (c *client) SendLog(ctx context.Context, entry *log.LogEntry) error {
	if entry.Timestamp == nil {
		entry.Timestamp = timestamppb.Now()
	}

	// Retry with exponential backoff for concurrent request handling
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := c.client.SendLog(ctx, entry)
		cancel()

		if err == nil {
			return nil
		}

		// Don't retry on last attempt
		if attempt < maxRetries-1 {
			// Exponential backoff: 10ms, 20ms, 40ms
			backoff := time.Duration(10*(1<<uint(attempt))) * time.Millisecond
			time.Sleep(backoff)
		}
	}

	// Return error after all retries exhausted
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := c.client.SendLog(ctx, entry)
	return err
}

func (c *client) SendEvent(ctx context.Context, entry *log.EventEntry) error {
	if entry.Timestamp == nil {
		entry.Timestamp = timestamppb.Now()
	}

	// Retry with exponential backoff for concurrent request handling
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := c.client.SendEvent(ctx, entry)
		cancel()

		if err == nil {
			return nil
		}

		// Don't retry on last attempt
		if attempt < maxRetries-1 {
			// Exponential backoff: 10ms, 20ms, 40ms
			backoff := time.Duration(10*(1<<uint(attempt))) * time.Millisecond
			time.Sleep(backoff)
		}
	}

	// Return error after all retries exhausted
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := c.client.SendEvent(ctx, entry)
	return err
}
