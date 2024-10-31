// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vsock

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
)

const (
	maxRetries     = 3
	retryDelay     = time.Second
	maxMessageSize = 1 << 20 // 1 MB
	ackTimeout     = 5 * time.Second
	maxConcurrent  = 100
)

type MessageStatus int

const (
	StatusPending MessageStatus = iota
	StatusSent
	StatusAcknowledged
	StatusFailed
)

type Message struct {
	ID      uint32
	Content []byte
	Status  MessageStatus
	Retries int
}

type AckWriter struct {
	conn            net.Conn
	pendingMessages chan *Message
	messageStore    sync.Map // map[uint32]*Message
	nextID          uint32
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

func NewAckWriter(conn net.Conn) io.WriteCloser {
	ctx, cancel := context.WithCancel(context.Background())
	aw := &AckWriter{
		conn:            conn,
		pendingMessages: make(chan *Message, maxConcurrent),
		nextID:          1,
		ctx:             ctx,
		cancel:          cancel,
	}
	aw.wg.Add(2)
	go aw.sendMessages()
	go aw.handleAcknowledgments()
	return aw
}

func (aw *AckWriter) Write(p []byte) (int, error) {
	if len(p) > maxMessageSize {
		return 0, fmt.Errorf("message size exceeds maximum allowed size of %d bytes", maxMessageSize)
	}

	messageID := atomic.AddUint32(&aw.nextID, 1)
	message := &Message{
		ID:      messageID,
		Content: make([]byte, len(p)),
		Status:  StatusPending,
	}
	copy(message.Content, p)

	aw.messageStore.Store(messageID, message)

	select {
	case aw.pendingMessages <- message:
		timer := time.NewTimer(ackTimeout)
		defer timer.Stop()

		for {
			if msg, ok := aw.messageStore.Load(messageID); ok {
				m := msg.(*Message)
				if m.Status == StatusAcknowledged {
					return len(p), nil
				}
				if m.Status == StatusFailed {
					return 0, fmt.Errorf("message delivery failed after %d retries", maxRetries)
				}
			}

			select {
			case <-timer.C:
				return 0, fmt.Errorf("timeout waiting for acknowledgment")
			case <-aw.ctx.Done():
				return 0, fmt.Errorf("writer closed while waiting for acknowledgment")
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
	case <-aw.ctx.Done():
		return 0, fmt.Errorf("writer is closed")
	}
}

func (aw *AckWriter) sendMessages() {
	defer aw.wg.Done()

	for {
		select {
		case <-aw.ctx.Done():
			return
		case msg := <-aw.pendingMessages:
			if err := aw.sendWithRetry(msg); err != nil {
				log.Printf("Failed to send message %d after all retries: %v", msg.ID, err)
				msg.Status = StatusFailed
				aw.messageStore.Store(msg.ID, msg)
			}
		}
	}
}

func (aw *AckWriter) sendWithRetry(msg *Message) error {
	for msg.Retries < maxRetries {
		if err := aw.writeMessage(msg.ID, msg.Content); err != nil {
			msg.Retries++
			msg.Status = StatusPending
			log.Printf("Error writing message %d (attempt %d): %v", msg.ID, msg.Retries, err)
			time.Sleep(retryDelay)
			continue
		}
		msg.Status = StatusSent
		aw.messageStore.Store(msg.ID, msg)
		return nil
	}
	return fmt.Errorf("max retries reached")
}

func (aw *AckWriter) writeMessage(messageID uint32, p []byte) error {
	if err := binary.Write(aw.conn, binary.LittleEndian, messageID); err != nil {
		return fmt.Errorf("failed to write message ID: %w", err)
	}

	messageLen := uint32(len(p))
	if err := binary.Write(aw.conn, binary.LittleEndian, messageLen); err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}

	if _, err := aw.conn.Write(p); err != nil {
		return fmt.Errorf("failed to write message content: %w", err)
	}

	return nil
}

func (aw *AckWriter) handleAcknowledgments() {
	defer aw.wg.Done()

	for {
		select {
		case <-aw.ctx.Done():
			return
		default:
			var ackID uint32
			if err := binary.Read(aw.conn, binary.LittleEndian, &ackID); err != nil {
				if err == io.EOF {
					log.Println("Connection closed, stopping acknowledgment handler")
					return
				}
				log.Printf("Error reading ACK: %v", err)
				time.Sleep(retryDelay)
				continue
			}

			if msg, ok := aw.messageStore.Load(ackID); ok {
				m := msg.(*Message)
				m.Status = StatusAcknowledged
				aw.messageStore.Store(ackID, m)

				// Clean up old messages periodically
				go aw.cleanupOldMessages(ackID)
			} else {
				log.Printf("Received ACK for unknown message ID: %d", ackID)
			}
		}
	}
}

func (aw *AckWriter) cleanupOldMessages(currentID uint32) {
	aw.messageStore.Range(func(key, value interface{}) bool {
		msgID := key.(uint32)
		msg := value.(*Message)

		// Clean up acknowledged messages that are old
		if msg.Status == StatusAcknowledged && msgID < currentID-maxConcurrent {
			aw.messageStore.Delete(msgID)
		}
		return true
	})
}

func (aw *AckWriter) Close() error {
	aw.cancel()
	aw.wg.Wait()
	return aw.conn.Close()
}

type Reader interface {
	Read() ([]byte, error)
	ReadProto(msg proto.Message) error
}

type AckReader struct {
	conn net.Conn
	ctx  context.Context
}

func NewAckReader(conn net.Conn) Reader {
	return &AckReader{
		conn: conn,
		ctx:  context.Background(),
	}
}

func (ar *AckReader) ReadProto(msg proto.Message) error {
	data, err := ar.Read()
	if err != nil {
		return fmt.Errorf("failed to read proto message: %w", err)
	}
	return proto.Unmarshal(data, msg)
}

func (ar *AckReader) Read() ([]byte, error) {
	var messageID uint32
	if err := binary.Read(ar.conn, binary.LittleEndian, &messageID); err != nil {
		return nil, fmt.Errorf("error reading message ID: %w", err)
	}

	var messageLen uint32
	if err := binary.Read(ar.conn, binary.LittleEndian, &messageLen); err != nil {
		return nil, fmt.Errorf("error reading message length: %w", err)
	}

	if messageLen > maxMessageSize {
		return nil, fmt.Errorf("message size %d exceeds maximum allowed size of %d bytes", messageLen, maxMessageSize)
	}

	data := make([]byte, messageLen)
	if _, err := io.ReadFull(ar.conn, data); err != nil {
		return nil, fmt.Errorf("error reading message content: %w", err)
	}

	if err := ar.sendAck(messageID); err != nil {
		return nil, fmt.Errorf("error sending ACK: %w", err)
	}

	return data, nil
}

func (ar *AckReader) sendAck(messageID uint32) error {
	return binary.Write(ar.conn, binary.LittleEndian, messageID)
}
