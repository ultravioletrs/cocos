// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"bufio"
	"fmt"
	"log"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	ManagerVsockPort     = 9997
	messageSize      int = 1024
)

var (
	errFailedToParseCID    = fmt.Errorf("failed to parse computation ID")
	errComputationNotFound = fmt.Errorf("computation not found")
)

type Client struct {
	id     string
	conn   net.Conn
	outCh  chan string
	reader *bufio.Reader
	writer *bufio.Writer
}

var (
	clients    = make(map[string]*Client)
	clientsMux sync.RWMutex
)

// RetrieveAgentEventsLogs Retrieve and forward agent logs and events via vsock.
func (ms *managerService) RetrieveAgentEventsLogs() {
	l, err := vsock.Listen(ManagerVsockPort, nil)
	if err != nil {
		ms.logger.Warn(err.Error())
		return
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			ms.logger.Warn(err.Error())
			continue
		}

		go ms.handleConnection(conn)
	}
}

func (ms *managerService) handleConnection(conn net.Conn) {
	defer conn.Close()

	cmpID, err := ms.computationIDFromAddress(conn.RemoteAddr().String())
	if err != nil {
		ms.logger.Warn(err.Error())
		return
	}

	client := &Client{
		id:     cmpID,
		conn:   conn,
		outCh:  make(chan string, 100),
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
	}

	clientsMux.Lock()
	clients[client.id] = client
	clientsMux.Unlock()

	defer func() {
		clientsMux.Lock()
		delete(clients, client.id)
		clientsMux.Unlock()
	}()

	go client.writeLoop()
	client.readLoop(ms)
}

func (c *Client) readLoop(ms *managerService) {
	for {
		msg, err := c.reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading from client %s: %v", c.id, err)
			ms.reportBrokenConnection(c.id)
			return
		}

		parts := strings.SplitN(strings.TrimSpace(msg), ":", 2)
		if len(parts) != 2 {
			log.Printf("Invalid message format from client %s: %s", c.id, msg)
			continue
		}

		messageID, content := parts[0], parts[1]
		fmt.Printf("Received message from client %s: ID=%s, Content=%s\n", c.id, messageID, content)

		var message manager.ClientStreamMessage

		if err := proto.Unmarshal([]byte(content), &message); err != nil {
			log.Printf("Error unmarshalling message from client %s: %v", c.id, err)
			continue
		}

		ms.eventsChan <- &message

		args := []any{}

		switch message.Message.(type) {
		case *manager.ClientStreamMessage_AgentEvent:
			args = append(args, slog.Group("agent-event",
				slog.String("event-type", message.GetAgentEvent().GetEventType()),
				slog.String("computation-id", message.GetAgentEvent().GetComputationId()),
				slog.String("status", message.GetAgentEvent().GetStatus()),
				slog.String("originator", message.GetAgentEvent().GetOriginator()),
				slog.String("timestamp", message.GetAgentEvent().GetTimestamp().String()),
				slog.String("details", string(message.GetAgentEvent().GetDetails()))))
		case *manager.ClientStreamMessage_AgentLog:
			args = append(args, slog.Group("agent-log",
				slog.String("computation-id", message.GetAgentLog().GetComputationId()),
				slog.String("level", message.GetAgentLog().GetLevel()),
				slog.String("timestamp", message.GetAgentLog().GetTimestamp().String()),
				slog.String("message", message.GetAgentLog().GetMessage())))
		}

		ms.logger.Info("", args...)

		// Send acknowledgment with the message ID
		c.outCh <- fmt.Sprintf("ACK:%s\n", messageID)
	}
}

func (c *Client) writeLoop() {
	for msg := range c.outCh {
		_, err := c.writer.WriteString(msg)
		if err != nil {
			log.Printf("Error writing to client %s: %v", c.id, err)
			return
		}
		c.writer.Flush()
	}
}

func (ms *managerService) computationIDFromAddress(address string) (string, error) {
	re := regexp.MustCompile(`vm\((\d+)\)`)
	matches := re.FindStringSubmatch(address)

	if len(matches) > 1 {
		cid, err := strconv.Atoi(matches[1])
		if err != nil {
			return "", err
		}
		return ms.findComputationID(cid)
	}
	return "", errFailedToParseCID
}

func (ms *managerService) findComputationID(cid int) (string, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	for cmpID, vm := range ms.vms {
		if vm.GetCID() == cid {
			return cmpID, nil
		}
	}

	return "", errComputationNotFound
}

func (ms *managerService) reportBrokenConnection(cmpID string) {
	ms.eventsChan <- &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentEvent{
			AgentEvent: &manager.AgentEvent{
				EventType:     manager.VmRunning.String(),
				ComputationId: cmpID,
				Status:        manager.Disconnected.String(),
				Timestamp:     timestamppb.Now(),
				Originator:    "manager",
			},
		},
	}
}
