// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package server

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/ultravioletrs/cocos/internal/server/mocks"
)

func TestStopAllServer(t *testing.T) {
	server1 := new(mocks.Server)
	server2 := new(mocks.Server)
	server1.On("Stop").Return(nil)
	server2.On("Stop").Return(errors.New("failed to stop"))
	tests := []struct {
		name          string
		servers       []Server
		expectedError bool
	}{
		{
			name: "All servers stop successfully",
			servers: []Server{
				server1,
				server1,
			},
			expectedError: false,
		},
		{
			name: "One server fails to stop",
			servers: []Server{
				server1,
				server2,
			},
			expectedError: true,
		},
		{
			name:          "No servers",
			servers:       []Server{},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := stopAllServer(tt.servers...)
			if (err != nil) != tt.expectedError {
				t.Errorf("stopAllServer() error = %v, expectedError %v", err, tt.expectedError)
			}
		})
	}
}

func TestStopHandler(t *testing.T) {
	mockServer := new(mocks.Server)
	mockServer.On("Stop").Return(nil)
	tests := []struct {
		name           string
		setupFunc      func() (context.Context, context.CancelFunc, *slog.Logger, string, []Server)
		triggerSignal  bool
		expectedError  bool
		expectCanceled bool
	}{
		{
			name: "Graceful shutdown on signal",
			setupFunc: func() (context.Context, context.CancelFunc, *slog.Logger, string, []Server) {
				ctx, cancel := context.WithCancel(context.Background())
				logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
				return ctx, cancel, logger, "test", []Server{mockServer}
			},
			triggerSignal:  true,
			expectedError:  false,
			expectCanceled: true,
		},
		{
			name: "Context canceled",
			setupFunc: func() (context.Context, context.CancelFunc, *slog.Logger, string, []Server) {
				ctx, cancel := context.WithCancel(context.Background())
				logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
				go func() {
					time.Sleep(100 * time.Millisecond)
					cancel()
				}()
				return ctx, cancel, logger, "test", []Server{mockServer}
			},
			triggerSignal:  false,
			expectedError:  false,
			expectCanceled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel, logger, svcName, servers := tt.setupFunc()
			defer cancel()

			errChan := make(chan error)
			go func() {
				errChan <- StopHandler(ctx, cancel, logger, svcName, servers...)
			}()

			if tt.triggerSignal {
				// Simulate SIGINT
				go func() {
					time.Sleep(100 * time.Millisecond)
					err := syscall.Kill(syscall.Getpid(), syscall.SIGINT)
					if err != nil {
						t.Errorf("failed to send signal: %v", err)
					}
				}()
			}

			select {
			case err := <-errChan:
				if (err != nil) != tt.expectedError {
					t.Errorf("StopHandler() error = %v, expectedError %v", err, tt.expectedError)
				}
			case <-time.After(2 * time.Second):
				t.Error("StopHandler() timed out")
			}

			if tt.expectCanceled {
				select {
				case <-ctx.Done():
					// Context was canceled as expected
				default:
					t.Error("Context was not canceled")
				}
			}
		})
	}
}
