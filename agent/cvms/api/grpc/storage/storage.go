// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ultravioletrs/cocos/agent/cvms"
)

// Message represents a pending message with its timestamp.
type Message struct {
	Message *cvms.ClientStreamMessage
	Time    time.Time
}

// Storage defines the interface for message persistence operations.
type Storage interface {
	// Load retrieves all pending messages from storage.
	Load() ([]Message, error)

	// Save persists the given messages to storage.
	Save(messages []Message) error

	// Add appends a new message to storage.
	Add(msg *cvms.ClientStreamMessage) error

	// Clear removes all messages from storage.
	Clear() error
}

// FileStorage implements Storage interface using file-based persistence.
type FileStorage struct {
	mu   sync.Mutex
	path string
	msgs []Message
}

// NewFileStorage creates a new file-based storage instance.
func NewFileStorage(storageDir string) (*FileStorage, error) {
	if err := os.MkdirAll(storageDir, 0o755); err != nil {
		return nil, err
	}

	return &FileStorage{
		path: filepath.Join(storageDir, "pending_messages.json"),
		msgs: make([]Message, 0),
	}, nil
}

func (fs *FileStorage) Load() ([]Message, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := os.ReadFile(fs.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &fs.msgs); err != nil {
		return nil, err
	}

	return fs.msgs, nil
}

func (fs *FileStorage) Save(messages []Message) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.msgs = messages

	data, err := json.Marshal(messages)
	if err != nil {
		return err
	}

	return os.WriteFile(fs.path, data, 0o644)
}

func (fs *FileStorage) Add(msg *cvms.ClientStreamMessage) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.msgs = append(fs.msgs, Message{
		Message: msg,
		Time:    time.Now(),
	})

	data, err := json.Marshal(fs.msgs)
	if err != nil {
		return err
	}

	return os.WriteFile(fs.path, data, 0o644)
}

func (fs *FileStorage) Clear() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.msgs = make([]Message, 0)
	return os.WriteFile(fs.path, []byte("[]"), 0o644)
}
