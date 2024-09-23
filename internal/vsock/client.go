// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vsock

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

const (
	maxRetries     = 3
	retryDelay     = time.Second
	maxMessageSize = 1 << 20 // 1 MB
	ackTimeout     = 5 * time.Second
	maxConcurrent  = 100 // Maximum number of concurrent messages
)

type Message struct {
	ID      uint32
	Content []byte
}

type AckWriter struct {
	conn            net.Conn
	pendingMessages chan *Message
	ackChannels     map[uint32]chan bool
	ackMu           sync.RWMutex
	nextID          uint32
	done            chan struct{}
	wg              sync.WaitGroup
}

func NewAckWriter(conn net.Conn) *AckWriter {
	aw := &AckWriter{
		conn:            conn,
		pendingMessages: make(chan *Message, maxConcurrent),
		ackChannels:     make(map[uint32]chan bool),
		nextID:          1,
		done:            make(chan struct{}),
	}
	aw.wg.Add(2)
	go aw.sendMessages()
	go aw.handleAcknowledgments()
	return aw
}

func (aw *AckWriter) WriteProto(msg proto.Message) (int, error) {
	data, err := proto.Marshal(msg)
	if err != nil {
		return 0, fmt.Errorf("error marshaling protobuf message: %v", err)
	}
	return aw.Write(data)
}

func (aw *AckWriter) Write(p []byte) (int, error) {
	if len(p) > maxMessageSize {
		return 0, fmt.Errorf("message size exceeds maximum allowed size of %d bytes", maxMessageSize)
	}

	aw.ackMu.Lock()
	messageID := aw.nextID
	aw.nextID++

	ackCh := make(chan bool, 1)
	aw.ackChannels[messageID] = ackCh
	aw.ackMu.Unlock()

	message := &Message{ID: messageID, Content: p}

	select {
	case aw.pendingMessages <- message:
		// Message queued successfully
	case <-aw.done:
		return 0, fmt.Errorf("writer is closed")
	}

	select {
	case <-ackCh:
		return len(p), nil
	case <-time.After(ackTimeout):
		return 0, fmt.Errorf("timeout waiting for acknowledgment")
	case <-aw.done:
		return 0, fmt.Errorf("writer closed while waiting for acknowledgment")
	}
}

func (aw *AckWriter) sendMessages() {
	defer aw.wg.Done()
	for {
		select {
		case <-aw.done:
			return
		case msg := <-aw.pendingMessages:
			for i := 0; i < maxRetries; i++ {
				if err := aw.writeMessage(msg.ID, msg.Content); err != nil {
					log.Printf("Error writing message %d (attempt %d): %v", msg.ID, i+1, err)
					time.Sleep(retryDelay)
					continue
				}
				break
			}
		}
	}
}

func (aw *AckWriter) writeMessage(messageID uint32, p []byte) error {
	// Write message ID
	if err := binary.Write(aw.conn, binary.LittleEndian, messageID); err != nil {
		return err
	}

	// Write message length
	messageLen := uint32(len(p))
	if err := binary.Write(aw.conn, binary.LittleEndian, messageLen); err != nil {
		return err
	}

	// Write message content
	if _, err := aw.conn.Write(p); err != nil {
		return err
	}

	return nil
}

func (aw *AckWriter) handleAcknowledgments() {
	defer aw.wg.Done()
	for {
		select {
		case <-aw.done:
			return
		default:
			var ackID uint32
			err := binary.Read(aw.conn, binary.LittleEndian, &ackID)
			if err != nil {
				if err == io.EOF {
					log.Println("Connection closed, stopping acknowledgment handler")
					return
				}
				log.Printf("Error reading ACK: %v", err)
				time.Sleep(retryDelay)
				continue
			}

			aw.ackMu.RLock()
			ackCh, ok := aw.ackChannels[ackID]
			aw.ackMu.RUnlock()

			if ok {
				select {
				case ackCh <- true:
				default:
					// Channel is already closed or full
				}
				aw.ackMu.Lock()
				delete(aw.ackChannels, ackID)
				aw.ackMu.Unlock()
			} else {
				log.Printf("Received ACK for unknown message ID: %d", ackID)
			}
		}
	}
}

func (aw *AckWriter) Close() error {
	close(aw.done)
	aw.wg.Wait()
	return aw.conn.Close()
}

type AckReader struct {
	conn net.Conn
}

func NewAckReader(conn net.Conn) *AckReader {
	return &AckReader{
		conn: conn,
	}
}

func (ar *AckReader) ReadProto(msg proto.Message) error {
	data, err := ar.Read()
	if err != nil {
		return err
	}

	return proto.Unmarshal(data, msg)
}

func (ar *AckReader) Read() ([]byte, error) {
	var messageID uint32
	if err := binary.Read(ar.conn, binary.LittleEndian, &messageID); err != nil {
		return nil, fmt.Errorf("error reading message ID: %v", err)
	}

	var messageLen uint32
	if err := binary.Read(ar.conn, binary.LittleEndian, &messageLen); err != nil {
		return nil, fmt.Errorf("error reading message length: %v", err)
	}

	if messageLen > maxMessageSize {
		return nil, fmt.Errorf("message size exceeds maximum allowed size of %d bytes", maxMessageSize)
	}

	data := make([]byte, messageLen)
	_, err := io.ReadFull(ar.conn, data)
	if err != nil {
		return nil, fmt.Errorf("error reading message content: %v", err)
	}

	if err := ar.sendAck(messageID); err != nil {
		return nil, fmt.Errorf("error sending ACK: %v", err)
	}

	return data, nil
}

func (ar *AckReader) sendAck(messageID uint32) error {
	return binary.Write(ar.conn, binary.LittleEndian, messageID)
}
