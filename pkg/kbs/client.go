// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package kbs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/absmach/supermq/pkg/errors"
)

var (
	// ErrAttestationFailed indicates attestation with KBS failed.
	ErrAttestationFailed = errors.New("attestation with KBS failed")
	// ErrResourceNotFound indicates the requested resource was not found in KBS.
	ErrResourceNotFound = errors.New("resource not found in KBS")
	// ErrInvalidResponse indicates KBS returned an invalid response.
	ErrInvalidResponse = errors.New("invalid response from KBS")
)

// Client defines the interface for KBS (Key Broker Service) communication.
type Client interface {
	// GetChallenge initiates the attestation handshake and returns the nonce.
	GetChallenge(ctx context.Context) (string, error)

	// Attest performs attestation with KBS and returns a token.
	Attest(ctx context.Context, evidence []byte, runtimeData RuntimeData) (string, error)

	// GetResource retrieves a resource from KBS using an attestation token.
	GetResource(ctx context.Context, token, resourcePath string) ([]byte, error)
}

// Config holds configuration for KBS client.
type Config struct {
	// URL is the KBS endpoint (e.g., "http://kbs:8080")
	URL string
	// Timeout for HTTP requests
	Timeout time.Duration
}

// RuntimeData contains the runtime data for attestation.
type RuntimeData struct {
	// Nonce from KBS challenge
	Nonce string `json:"nonce"`
	// TEEPubKey is the TEE public key
	TEEPubKey string `json:"tee-pubkey,omitempty"`
}

// AuthRequest is the request to initiate attestation.
type AuthRequest struct {
	Version     string      `json:"version"`
	TEE         string      `json:"tee"`
	ExtraParams interface{} `json:"extra-params"`
}

// AuthResponse is the response from KBS auth endpoint.
type AuthResponse struct {
	Nonce       string      `json:"nonce"`
	ExtraParams interface{} `json:"extra-params,omitempty"`
}

// AttestRequest is the request to submit evidence.
type AttestRequest struct {
	TEEEvidence json.RawMessage `json:"tee-evidence"`
	RuntimeData RuntimeData     `json:"runtime-data"`
	InitData    *string         `json:"init-data,omitempty"`
}

// AttestResponse is the response from KBS attest endpoint.
type AttestResponse struct {
	Token string `json:"token"`
}

// kbsClient implements the Client interface.
type kbsClient struct {
	config Config
	client *http.Client
}

// NewClient creates a new KBS client.
func NewClient(config Config) Client {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	jar, _ := cookiejar.New(nil)

	return &kbsClient{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
			Jar:     jar,
		},
	}
}

// GetChallenge initiates the RCAR handshake calling /kbs/v0/auth
func (c *kbsClient) GetChallenge(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/kbs/v0/auth", c.config.URL)

	authReq := AuthRequest{
		Version:     "0.1.0",
		TEE:         "sample",
		ExtraParams: map[string]interface{}{}, // KBS expects an object
	}

	reqBody, err := json.Marshal(authReq)
	if err != nil {
		return "", errors.Wrap(ErrAttestationFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", errors.Wrap(ErrAttestationFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", errors.Wrap(ErrAttestationFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.Wrap(ErrAttestationFailed,
			fmt.Errorf("auth HTTP %d: %s", resp.StatusCode, string(body)))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", errors.Wrap(ErrInvalidResponse, err)
	}

	return authResp.Nonce, nil
}

// Attest performs attestation with KBS and returns a token.
func (c *kbsClient) Attest(ctx context.Context, evidence []byte, runtimeData RuntimeData) (string, error) {
	// Build attest request
	attestReq := AttestRequest{
		TEEEvidence: json.RawMessage(evidence),
		RuntimeData: runtimeData,
	}

	reqBody, err := json.Marshal(attestReq)
	if err != nil {
		return "", errors.Wrap(ErrAttestationFailed, err)
	}

	// Send attest request
	url := fmt.Sprintf("%s/kbs/v0/attest", c.config.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", errors.Wrap(ErrAttestationFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Cookie jar handles the session cookie automatically
	resp, err := c.client.Do(req)
	if err != nil {
		return "", errors.Wrap(ErrAttestationFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Try to parse error details if JSON
		return "", errors.Wrap(ErrAttestationFailed,
			fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body)))
	}

	// Parse response
	var attestResp AttestResponse
	if err := json.NewDecoder(resp.Body).Decode(&attestResp); err != nil {
		return "", errors.Wrap(ErrInvalidResponse, err)
	}

	return attestResp.Token, nil
}

// GetResource retrieves a resource from KBS using an attestation token.
func (c *kbsClient) GetResource(ctx context.Context, token, resourcePath string) ([]byte, error) {
	url := fmt.Sprintf("%s/kbs/v0/resource/%s", c.config.URL, resourcePath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(ErrResourceNotFound, err)
	}

	// Add authorization header with token
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(ErrResourceNotFound, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.Wrap(ErrResourceNotFound,
			fmt.Errorf("resource not found: %s", resourcePath))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Wrap(ErrResourceNotFound,
			fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body)))
	}

	// Read resource data
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidResponse, err)
	}

	return data, nil
}
