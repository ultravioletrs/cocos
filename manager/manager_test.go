// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/ultravioletrs/cocos/manager"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func TestProcess(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := manager.NewManagerServiceClient(conn)
	stream, err := client.Process(ctx)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	var data bytes.Buffer
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("Failed to receive ServerStreamMessage: %v", err)
		}

		switch m := msg.Message.(type) {
		case *manager.ServerStreamMessage_TerminateReq:
			if m.TerminateReq.Message != "test terminate" {
				t.Fatalf("Unexpected terminate message: %v", m.TerminateReq.Message)
			}
		case *manager.ServerStreamMessage_RunReqChunks:
			if len(m.RunReqChunks.Data) == 0 {
				var runReq manager.ComputationRunReq
				if err = proto.Unmarshal(data.Bytes(), &runReq); err != nil {
					t.Fatalf("Failed to create run request: %v", err)
				}

				runRes := &manager.ClientStreamMessage_AgentLog{
					AgentLog: &manager.AgentLog{
						Message:       "test log",
						ComputationId: "comp1",
						Level:         "DEBUG",
					},
				}
				if runReq.Id != "1" || runReq.Name != "sample computation" || runReq.Description != "sample description" {
					t.Fatalf("Unexpected run request message: %v", &runReq)
				}
				if err := stream.Send(&manager.ClientStreamMessage{Message: runRes}); err != nil {
					t.Fatalf("Failed to send ClientStreamMessage: %v", err)
				}
				return
			}
			data.Write(m.RunReqChunks.Data)
		default:
			t.Fatalf("Unexpected message type: %T", m)
		}
	}
}
