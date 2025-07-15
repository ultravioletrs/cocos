// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent/cvms"
)

// createTempDir creates a temporary directory for testing
func createTempDir(t *testing.T) string {
	tmpDir, err := os.MkdirTemp("", "storage_test_*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})
	return tmpDir
}

// createTestMessage creates a test message for testing
func createTestMessage(content string) *cvms.ClientStreamMessage {
	return &cvms.ClientStreamMessage{
		Message: &cvms.ClientStreamMessage_RunRes{
			RunRes: &cvms.RunResponse{
				Error:         "",
				ComputationId: content,
			},
		},
	}
}

func TestNewFileStorage(t *testing.T) {
	tests := []struct {
		name        string
		storageDir  string
		expectError bool
	}{
		{
			name:        "valid directory",
			storageDir:  createTempDir(t),
			expectError: false,
		},
		{
			name:        "non-existent directory gets created",
			storageDir:  filepath.Join(createTempDir(t), "subdir"),
			expectError: false,
		},
		{
			name:        "invalid directory path",
			storageDir:  "/invalid/path/that/cannot/be/created",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage, err := NewFileStorage(tt.storageDir)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, storage)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, storage)
				assert.Equal(t, filepath.Join(tt.storageDir, "pending_messages.json"), storage.path)
				assert.Empty(t, storage.msgs)
			}
		})
	}
}

func TestFileStorage_Load(t *testing.T) {
	tests := []struct {
		name         string
		setupFile    func(string) error
		expectedMsgs int
		expectError  bool
	}{
		{
			name: "load from non-existent file",
			setupFile: func(path string) error {
				// Don't create file
				return nil
			},
			expectedMsgs: 0,
			expectError:  false,
		},
		{
			name: "load from empty file",
			setupFile: func(path string) error {
				return os.WriteFile(path, []byte("[]"), 0o644)
			},
			expectedMsgs: 0,
			expectError:  false,
		},
		{
			name: "load from corrupted file",
			setupFile: func(path string) error {
				return os.WriteFile(path, []byte("invalid json"), 0o644)
			},
			expectedMsgs: 0,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := createTempDir(t)
			storage, err := NewFileStorage(tmpDir)
			require.NoError(t, err)

			err = tt.setupFile(storage.path)
			require.NoError(t, err)

			msgs, err := storage.Load()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, msgs, tt.expectedMsgs)
			}
		})
	}
}

func TestFileStorage_Save(t *testing.T) {
	tests := []struct {
		name        string
		messages    []Message
		expectError bool
	}{
		{
			name:        "save empty messages",
			messages:    []Message{},
			expectError: false,
		},
		{
			name: "save single message",
			messages: []Message{
				{
					Message: createTestMessage("test"),
					Time:    time.Now(),
				},
			},
			expectError: false,
		},
		{
			name: "save multiple messages",
			messages: []Message{
				{
					Message: createTestMessage("test1"),
					Time:    time.Now(),
				},
				{
					Message: createTestMessage("test2"),
					Time:    time.Now().Add(time.Second),
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := createTempDir(t)
			storage, err := NewFileStorage(tmpDir)
			require.NoError(t, err)

			err = storage.Save(tt.messages)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify file was written correctly
				_, err := os.ReadFile(storage.path)
				assert.NoError(t, err)

				// Verify internal state was updated
				assert.Equal(t, tt.messages, storage.msgs)
			}
		})
	}
}

func TestFileStorage_Add(t *testing.T) {
	tests := []struct {
		name          string
		initialMsgs   []Message
		newMessage    *cvms.ClientStreamMessage
		expectError   bool
		expectedCount int
	}{
		{
			name:          "add to empty storage",
			initialMsgs:   []Message{},
			newMessage:    createTestMessage("new"),
			expectError:   false,
			expectedCount: 1,
		},
		{
			name: "add to existing messages",
			initialMsgs: []Message{
				{
					Message: createTestMessage("existing"),
					Time:    time.Now(),
				},
			},
			newMessage:    createTestMessage("new"),
			expectError:   false,
			expectedCount: 2,
		},
		{
			name:          "add nil message",
			initialMsgs:   []Message{},
			newMessage:    nil,
			expectError:   false,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := createTempDir(t)
			storage, err := NewFileStorage(tmpDir)
			require.NoError(t, err)

			// Setup initial messages
			if len(tt.initialMsgs) > 0 {
				err = storage.Save(tt.initialMsgs)
				require.NoError(t, err)
			}

			beforeTime := time.Now()
			err = storage.Add(tt.newMessage)
			afterTime := time.Now()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify message was added to internal state
				assert.Len(t, storage.msgs, tt.expectedCount)

				// Verify timestamp is reasonable
				if tt.expectedCount > 0 {
					lastMsg := storage.msgs[len(storage.msgs)-1]
					assert.True(t, lastMsg.Time.After(beforeTime) || lastMsg.Time.Equal(beforeTime))
					assert.True(t, lastMsg.Time.Before(afterTime) || lastMsg.Time.Equal(afterTime))
					assert.Equal(t, tt.newMessage, lastMsg.Message)
				}

				_, err := os.ReadFile(storage.path)
				assert.NoError(t, err)
			}
		})
	}
}

func TestFileStorage_Clear(t *testing.T) {
	tests := []struct {
		name        string
		initialMsgs []Message
		expectError bool
	}{
		{
			name:        "clear empty storage",
			initialMsgs: []Message{},
			expectError: false,
		},
		{
			name: "clear storage with messages",
			initialMsgs: []Message{
				{
					Message: createTestMessage("test1"),
					Time:    time.Now(),
				},
				{
					Message: createTestMessage("test2"),
					Time:    time.Now(),
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := createTempDir(t)
			storage, err := NewFileStorage(tmpDir)
			require.NoError(t, err)

			// Setup initial messages
			if len(tt.initialMsgs) > 0 {
				err = storage.Save(tt.initialMsgs)
				require.NoError(t, err)
			}

			err = storage.Clear()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify internal state is cleared
				assert.Empty(t, storage.msgs)

				// Verify file contains empty array
				data, err := os.ReadFile(storage.path)
				assert.NoError(t, err)
				assert.Equal(t, "[]", string(data))
			}
		})
	}
}

func TestFileStorage_ConcurrentAccess(t *testing.T) {
	tmpDir := createTempDir(t)
	storage, err := NewFileStorage(tmpDir)
	require.NoError(t, err)

	// Test concurrent Add operations
	numGoroutines := 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			msg := createTestMessage(string(rune('A' + id)))
			err := storage.Add(msg)
			assert.NoError(t, err)
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all messages were added
	msgs, err := storage.Load()
	assert.NoError(t, err)
	assert.Len(t, msgs, numGoroutines)
}

func TestFileStorage_IntegrationFlow(t *testing.T) {
	tmpDir := createTempDir(t)
	storage, err := NewFileStorage(tmpDir)
	require.NoError(t, err)

	// Test full workflow

	// 1. Load from empty storage
	msgs, err := storage.Load()
	assert.NoError(t, err)
	assert.Empty(t, msgs)

	// 2. Add some messages
	msg1 := createTestMessage("message1")
	err = storage.Add(msg1)
	assert.NoError(t, err)

	msg2 := createTestMessage("message2")
	err = storage.Add(msg2)
	assert.NoError(t, err)

	// 3. Load and verify
	msgs, err = storage.Load()
	assert.NoError(t, err)
	assert.Len(t, msgs, 2)

	// 4. Save new set of messages
	newMsgs := []Message{
		{
			Message: createTestMessage("new1"),
			Time:    time.Now(),
		},
	}
	err = storage.Save(newMsgs)
	assert.NoError(t, err)

	// 5. Load and verify replacement
	msgs, err = storage.Load()
	assert.NoError(t, err)
	assert.Len(t, msgs, 1)

	// 6. Clear storage
	err = storage.Clear()
	assert.NoError(t, err)

	// 7. Verify empty
	msgs, err = storage.Load()
	assert.NoError(t, err)
	assert.Empty(t, msgs)
}

func TestFileStorage_FilePermissions(t *testing.T) {
	tmpDir := createTempDir(t)
	storage, err := NewFileStorage(tmpDir)
	require.NoError(t, err)

	// Add a message to create the file
	msg := createTestMessage("test")
	err = storage.Add(msg)
	assert.NoError(t, err)

	// Check file permissions
	info, err := os.Stat(storage.path)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

func TestFileStorage_ErrorHandling(t *testing.T) {
	tmpDir := createTempDir(t)
	storage, err := NewFileStorage(tmpDir)
	require.NoError(t, err)

	// Make directory read-only to trigger write errors
	err = os.Chmod(tmpDir, 0o555)
	require.NoError(t, err)

	// Restore permissions for cleanup
	t.Cleanup(func() {
		os.Chmod(tmpDir, 0o755)
	})

	// Try to add a message - should fail due to write permissions
	msg := createTestMessage("test")
	err = storage.Add(msg)
	assert.Error(t, err)

	// Try to save - should fail due to write permissions
	err = storage.Save([]Message{})
	assert.Error(t, err)

	// Try to clear - should fail due to write permissions
	err = storage.Clear()
	assert.Error(t, err)
}
