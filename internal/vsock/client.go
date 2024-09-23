// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vsock

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/vsock"
)

var _ io.Writer = (*AckWriter)(nil)

const (
	maxRetries = 3
	retryDelay = time.Second
)

type Message struct {
	ID      int
	Content string
}

type AckWriter struct {
	conn        *vsock.Conn
	writer      *bufio.Writer
	reader      *bufio.Reader
	ackChannels map[int]chan bool
	ackMu       sync.Mutex
	nextID      int
}

func NewAckWriter(conn *vsock.Conn) *AckWriter {
	aw := &AckWriter{
		conn:        conn,
		writer:      bufio.NewWriter(conn),
		reader:      bufio.NewReader(conn),
		ackChannels: make(map[int]chan bool),
		nextID:      1,
	}
	go aw.handleAcknowledgments()
	return aw
}

func (aw *AckWriter) Write(p []byte) (n int, err error) {
	messageID := aw.nextID
	aw.nextID++

	ackCh := make(chan bool, 1)
	aw.ackMu.Lock()
	aw.ackChannels[messageID] = ackCh
	aw.ackMu.Unlock()

	defer func() {
		aw.ackMu.Lock()
		delete(aw.ackChannels, messageID)
		aw.ackMu.Unlock()
		close(ackCh)
	}()

	for i := 0; i < maxRetries; i++ {
		_, err := aw.writer.WriteString(fmt.Sprintf("%d:%s\n", messageID, string(p)))
		if err != nil {
			return 0, fmt.Errorf("error writing message: %v", err)
		}
		aw.writer.Flush()

		select {
		case <-ackCh:
			return len(p), nil
		case <-time.After(retryDelay):
			// Timeout, retry
		}
	}

	return 0, fmt.Errorf("failed to receive ACK after %d attempts", maxRetries)
}

func (aw *AckWriter) handleAcknowledgments() {
	for {
		ack, err := aw.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("Error reading ACK: %v", err)
			continue
		}

		parts := strings.Split(strings.TrimSpace(ack), ":")
		if len(parts) != 2 || parts[0] != "ACK" {
			log.Printf("Invalid ACK format: %s", ack)
			continue
		}

		messageID := 0
		_, err = fmt.Sscanf(parts[1], "%d", &messageID)
		if err != nil {
			log.Printf("Error parsing message ID from ACK: %v", err)
			continue
		}

		aw.ackMu.Lock()
		ackCh, ok := aw.ackChannels[messageID]
		aw.ackMu.Unlock()

		if ok {
			select {
			case ackCh <- true:
			default:
				// Channel is already closed or full
			}
		} else {
			log.Printf("Received ACK for unknown message ID: %d", messageID)
		}
	}
}
