// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	sync "sync"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/events"
	runnerpb "github.com/ultravioletrs/cocos/agent/runner"
	"github.com/ultravioletrs/cocos/agent/statemachine"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	attestation_client "github.com/ultravioletrs/cocos/pkg/clients/grpc/attestation"
	runner_client "github.com/ultravioletrs/cocos/pkg/clients/grpc/runner"
	"github.com/ultravioletrs/cocos/pkg/crypto"
	"github.com/ultravioletrs/cocos/pkg/kbs"
	"github.com/ultravioletrs/cocos/pkg/registry"
	"golang.org/x/crypto/sha3"
)

var _ Service = (*agentService)(nil)

//go:generate stringer -type=AgentState
type AgentState int

const (
	Idle AgentState = iota
	ReceivingManifest
	ReceivingAlgorithm
	ReceivingData
	Running
	ConsumingResults
	Complete
	Failed
)

//go:generate stringer -type=AgentEvent
type AgentEvent int

const (
	Start AgentEvent = iota
	ManifestReceived
	AlgorithmReceived
	DataReceived
	RunComplete
	ResultsConsumed
	RunFailed
)

//go:generate stringer -type=Status
type Status uint8

const (
	IdleState Status = iota
	InProgress
	Ready
	Completed
	Terminated
	Warning
	Starting
)

const (
	algoFilePermission = 0o700
)

const (
	ImaMeasurementsFilePath = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
	ImaPcrIndex             = 10
)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")
	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")
	// ErrUndeclaredAlgorithm indicates algorithm was not declared in computation manifest.
	ErrUndeclaredDataset = errors.New("dataset not declared in computation manifest")
	// ErrAllManifestItemsReceived indicates no new computation manifest items expected.
	ErrAllManifestItemsReceived = errors.New("all expected manifest Items have been received")
	// ErrUndeclaredConsumer indicates the consumer requesting results in not declared in computation manifest.
	ErrUndeclaredConsumer = errors.New("result consumer is undeclared in computation manifest")
	// ErrResultsNotReady indicates the computation results are not ready.
	ErrResultsNotReady = errors.New("computation results are not yet ready")
	// ErrStateNotReady agent received a request in the wrong state.
	ErrStateNotReady = errors.New("agent not expecting this operation in the current state")
	// ErrHashMismatch provided algorithm/dataset does not match hash in manifest.
	ErrHashMismatch = errors.New("malformed data, hash does not match manifest")
	// ErrFileNameMismatch provided dataset filename does not match filename in manifest.
	ErrFileNameMismatch = errors.New("malformed data, filename does not match manifest")
	// ErrAllResultsConsumed indicates all results have been consumed.
	ErrAllResultsConsumed = errors.New("all results have been consumed by declared consumers")
	// ErrAttestationFailed attestation failed.
	ErrAttestationFailed = errors.New("failed to get raw quote")
	// ErrAttestationVTpmFailed vTPM attestation failed.
	ErrAttestationVTpmFailed = errors.New("failed to get vTPM quote")
	// ErrFetchAzureToken azure token fetch failed.
	ErrFetchAzureToken = errors.New("failed to get azure token")
	// ErrAttType indicates that the attestation type that is requested does not exist or is not supported.
	ErrAttestationType = errors.New("attestation type does not exist or is not supported")
)

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	InitComputation(ctx context.Context, cmp Computation) error
	StopComputation(ctx context.Context) error
	Algo(ctx context.Context, algorithm Algorithm) error
	Data(ctx context.Context, dataset Dataset) error
	Result(ctx context.Context) ([]byte, error)
	Attestation(ctx context.Context, reportData [vtpm.SEVNonce]byte, nonce [vtpm.Nonce]byte, attType attestation.PlatformType) ([]byte, error)
	IMAMeasurements(ctx context.Context) ([]byte, []byte, error)
	AzureAttestationToken(ctx context.Context, nonce [vtpm.Nonce]byte) ([]byte, error)
	State() string
}

type agentService struct {
	mu                sync.Mutex
	computation       Computation // Holds the current computation request details.
	runnerClient      runner_client.Client
	algoType          string
	algoArgs          []string
	algoRequirements  []byte
	algoReceived      bool
	result            []byte                    // Stores the result of the computation.
	sm                statemachine.StateMachine // Manages the state transitions of the agent service.
	runError          error                     // Stores any error encountered during the computation run.
	eventSvc          events.Service            // Service for publishing events related to computation.
	attestationClient attestation_client.Client // Client for attestation service.
	logger            *slog.Logger              // Logger for the agent service.
	resultsConsumed   bool                      // Indicates if the results have been consumed.
	cancel            context.CancelFunc        // Cancels the computation context.
	vmpl              int                       // VMPL at which the Agent is running.
}

var _ Service = (*agentService)(nil)

// New instantiates the agent service implementation.
func New(ctx context.Context, logger *slog.Logger, eventSvc events.Service, attestationClient attestation_client.Client, runnerClient runner_client.Client, vmlp int) Service {
	sm := statemachine.NewStateMachine(Idle)
	ctx, cancel := context.WithCancel(ctx)
	svc := &agentService{
		sm:                sm,
		eventSvc:          eventSvc,
		attestationClient: attestationClient,
		runnerClient:      runnerClient,
		logger:            logger,
		cancel:            cancel,
		vmpl:              vmlp,
	}

	transitions := []statemachine.Transition{
		{From: Idle, Event: Start, To: ReceivingManifest},
		{From: ReceivingManifest, Event: ManifestReceived, To: ReceivingAlgorithm},
	}

	transitions = append(transitions, []statemachine.Transition{
		{From: ReceivingAlgorithm, Event: RunFailed, To: Failed},
		{From: ReceivingData, Event: RunFailed, To: Failed},
		{From: Running, Event: RunComplete, To: ConsumingResults},
		{From: Running, Event: RunFailed, To: Failed},
		{From: ConsumingResults, Event: ResultsConsumed, To: Complete},
	}...)

	for _, t := range transitions {
		sm.AddTransition(t)
	}

	sm.SetAction(ReceivingAlgorithm, svc.downloadAlgorithmIfRemote)
	sm.SetAction(ReceivingData, svc.downloadDatasetsIfRemote)
	sm.SetAction(Running, svc.runComputation)
	sm.SetAction(ConsumingResults, svc.publishEvent(Ready.String()))
	sm.SetAction(Complete, svc.publishEvent(Completed.String()))
	sm.SetAction(Failed, svc.publishEvent(Failed.String()))

	go func() {
		if err := sm.Start(ctx); err != nil {
			logger.Error(err.Error())
		}
	}()

	time.Sleep(100 * time.Millisecond)
	sm.SendEvent(Start)

	time.Sleep(100 * time.Millisecond)

	return svc
}

func (as *agentService) State() string {
	return as.sm.GetState().String()
}

func (as *agentService) InitComputation(ctx context.Context, cmp Computation) error {
	if as.sm.GetState() != ReceivingManifest {
		return ErrStateNotReady
	}
	defer as.sm.SendEvent(ManifestReceived)

	as.mu.Lock()
	defer as.mu.Unlock()

	as.computation = cmp

	// Debug: Log manifest details
	as.logger.Info("received computation manifest",
		"computation_id", cmp.ID,
		"kbs_enabled", cmp.KBS.Enabled,
		"kbs_url", cmp.KBS.URL,
		"algo_has_source", cmp.Algorithm.Source != nil,
		"dataset_count", len(cmp.Datasets))

	if cmp.Algorithm.Source != nil {
		as.logger.Info("algorithm remote source configured",
			"url", cmp.Algorithm.Source.URL,
			"kbs_resource_path", cmp.Algorithm.Source.KBSResourcePath)
	} else {
		as.logger.Info("algorithm remote source NOT configured - will wait for direct upload")
	}

	if cmp.KBS.Enabled {
		as.logger.Info("KBS is ENABLED", "url", cmp.KBS.URL)
	} else {
		as.logger.Info("KBS is NOT ENABLED")
	}

	for i, d := range cmp.Datasets {
		if d.Source != nil {
			as.logger.Info("dataset remote source configured",
				"index", i,
				"filename", d.Filename,
				"url", d.Source.URL,
				"kbs_resource_path", d.Source.KBSResourcePath)
		}
	}

	transitions := []statemachine.Transition{}

	if len(cmp.Datasets) == 0 {
		transitions = append(transitions, statemachine.Transition{From: ReceivingAlgorithm, Event: AlgorithmReceived, To: Running})
	} else {
		transitions = append(transitions, statemachine.Transition{From: ReceivingAlgorithm, Event: AlgorithmReceived, To: ReceivingData})
		transitions = append(transitions, statemachine.Transition{From: ReceivingData, Event: DataReceived, To: Running})
	}

	for _, t := range transitions {
		as.sm.AddTransition(t)
	}

	return nil
}

func (as *agentService) StopComputation(ctx context.Context) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.eventSvc.SendEvent(as.computation.ID, "Stopped", "Stopped", json.RawMessage{})

	as.cancel()

	if _, err := as.runnerClient.Stop(ctx, &runnerpb.StopRequest{ComputationId: as.computation.ID}); err != nil {
		as.logger.Warn("failed to stop runner", "error", err)
		// proceed to cleanup
	}

	if err := os.RemoveAll(algorithm.DatasetsDir); err != nil {
		return fmt.Errorf("error removing datasets directory: %v", err)
	}

	if err := os.RemoveAll(algorithm.ResultsDir); err != nil {
		return fmt.Errorf("error removing results directory: %v", err)
	}

	as.sm.Reset(Idle)

	as.computation = Computation{}
	as.algoReceived = false
	as.algoType = ""
	as.algoArgs = nil
	as.algoRequirements = nil
	as.result = nil
	as.runError = nil
	as.resultsConsumed = false

	ctx, cancel := context.WithCancel(ctx)
	as.cancel = cancel

	go func() {
		if err := as.sm.Start(ctx); err != nil {
			as.logger.Error(err.Error())
		}
	}()

	time.Sleep(100 * time.Millisecond)
	as.sm.SendEvent(Start)

	time.Sleep(100 * time.Millisecond)

	return nil
}

// downloadAlgorithmIfRemote automatically downloads the algorithm if it has a remote source.
// This is called as an action when entering the ReceivingAlgorithm state.
func (as *agentService) downloadAlgorithmIfRemote(state statemachine.State) {
	as.publishEvent(InProgress.String())(state)

	as.mu.Lock()
	defer as.mu.Unlock()

	// Debug: Log decision point
	as.logger.Info("checking if algorithm should be downloaded automatically",
		"algo_has_source", as.computation.Algorithm.Source != nil,
		"kbs_enabled", as.computation.KBS.Enabled)

	// Check if algorithm should be downloaded from remote source
	if as.computation.Algorithm.Source != nil && as.computation.KBS.Enabled {
		as.logger.Info("downloading algorithm from remote source",
			"url", as.computation.Algorithm.Source.URL,
			"kbs_resource_path", as.computation.Algorithm.Source.KBSResourcePath)

		// Use background context for download operation
		ctx := context.Background()

		downloadedData, err := as.downloadAndDecryptResource(ctx, as.computation.Algorithm.Source)
		if err != nil {
			as.runError = fmt.Errorf("failed to download and decrypt algorithm: %w", err)
			as.logger.Error(as.runError.Error())
			as.sm.SendEvent(RunFailed)
			return
		}

		// Verify hash
		hash := sha3.Sum256(downloadedData)
		if hash != as.computation.Algorithm.Hash {
			as.runError = fmt.Errorf("algorithm hash mismatch: expected %x, got %x", as.computation.Algorithm.Hash, hash)
			as.logger.Error(as.runError.Error())
			as.sm.SendEvent(RunFailed)
			return
		}

		// Write algorithm to file
		currentDir, err := os.Getwd()
		if err != nil {
			as.runError = fmt.Errorf("error getting current directory: %w", err)
			as.logger.Error(as.runError.Error())
			as.sm.SendEvent(RunFailed)
			return
		}

		f, err := os.Create(filepath.Join(currentDir, "algo"))
		if err != nil {
			as.runError = fmt.Errorf("error creating algorithm file: %w", err)
			as.logger.Error(as.runError.Error())
			as.sm.SendEvent(RunFailed)
			return
		}

		if _, err := f.Write(downloadedData); err != nil {
			as.runError = fmt.Errorf("error writing algorithm to file: %w", err)
			as.logger.Error(as.runError.Error())
			f.Close()
			as.sm.SendEvent(RunFailed)
			return
		}

		if err := os.Chmod(f.Name(), algoFilePermission); err != nil {
			as.runError = fmt.Errorf("error changing file permissions: %w", err)
			as.logger.Error(as.runError.Error())
			f.Close()
			as.sm.SendEvent(RunFailed)
			return
		}

		if err := f.Close(); err != nil {
			as.runError = fmt.Errorf("error closing file: %w", err)
			as.logger.Error(as.runError.Error())
			as.sm.SendEvent(RunFailed)
			return
		}

		as.algoReceived = true

		// Create datasets directory
		if err := os.Mkdir(algorithm.DatasetsDir, 0o755); err != nil {
			as.runError = fmt.Errorf("error creating datasets directory: %w", err)
			as.logger.Error(as.runError.Error())
			as.sm.SendEvent(RunFailed)
			return
		}

		as.logger.Info("algorithm downloaded and saved successfully")
		as.sm.SendEvent(AlgorithmReceived)
	} else {
		// If no remote source, do nothing - wait for direct upload via Algo() RPC call
		as.logger.Info("algorithm automatic download not triggered, waiting for direct upload",
			"reason", "no remote source or KBS not enabled")
	}
}

// downloadDatasetsIfRemote automatically downloads datasets that have remote sources.
// This is called as an action when entering the ReceivingData state.
func (as *agentService) downloadDatasetsIfRemote(state statemachine.State) {
	as.publishEvent(InProgress.String())(state)

	as.mu.Lock()
	defer as.mu.Unlock()

	// Check if any datasets should be downloaded from remote sources
	hasRemoteDatasets := false
	for _, d := range as.computation.Datasets {
		if d.Source != nil && as.computation.KBS.Enabled {
			hasRemoteDatasets = true
			break
		}
	}

	if !hasRemoteDatasets {
		// No remote datasets, wait for direct uploads via Data() RPC calls
		return
	}

	// Download all remote datasets
	ctx := context.Background()
	for i := len(as.computation.Datasets) - 1; i >= 0; i-- {
		d := as.computation.Datasets[i]
		if d.Source != nil && as.computation.KBS.Enabled {
			as.logger.Info("downloading dataset from remote source", "filename", d.Filename)

			downloadedData, err := as.downloadAndDecryptResource(ctx, d.Source)
			if err != nil {
				as.logger.Error("failed to download and decrypt dataset", "error", err, "filename", d.Filename)
				as.sm.SendEvent(RunFailed)
				return
			}

			// Verify hash
			hash := sha3.Sum256(downloadedData)
			if hash != d.Hash {
				as.logger.Error("dataset hash mismatch", "filename", d.Filename)
				as.sm.SendEvent(RunFailed)
				return
			}

			// Write dataset to file
			f, err := os.Create(fmt.Sprintf("%s/%s", algorithm.DatasetsDir, d.Filename))
			if err != nil {
				as.logger.Error("error creating dataset file", "error", err, "filename", d.Filename)
				as.sm.SendEvent(RunFailed)
				return
			}

			if _, err := f.Write(downloadedData); err != nil {
				as.logger.Error("error writing dataset to file", "error", err, "filename", d.Filename)
				f.Close()
				as.sm.SendEvent(RunFailed)
				return
			}

			if err := f.Close(); err != nil {
				as.logger.Error("error closing file", "error", err, "filename", d.Filename)
				as.sm.SendEvent(RunFailed)
				return
			}

			// Remove from pending datasets
			as.computation.Datasets = slices.Delete(as.computation.Datasets, i, i+1)
			as.logger.Info("dataset downloaded and saved successfully", "filename", d.Filename)
		}
	}

	// If all datasets are downloaded, send DataReceived event
	if len(as.computation.Datasets) == 0 {
		as.logger.Info("all datasets downloaded successfully")
		as.sm.SendEvent(DataReceived)
	}
	// Otherwise, wait for remaining datasets to be uploaded via Data() RPC calls
}

// downloadAndDecryptResource downloads an encrypted resource from a registry and decrypts it using KBS.
func (as *agentService) downloadAndDecryptResource(ctx context.Context, source *ResourceSource) ([]byte, error) {
	// 1. Download encrypted resource from registry
	as.logger.Info("downloading encrypted resource", "url", source.URL)

	var encData []byte
	var err error

	if strings.HasPrefix(source.URL, "s3://") {
		// S3 registry
		s3Config := registry.S3Config{
			Region:          os.Getenv("AWS_REGION"),
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			Endpoint:        os.Getenv("AWS_ENDPOINT_URL"),
		}

		s3Reg, err := registry.NewS3Registry(ctx, registry.DefaultConfig(), s3Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create S3 registry: %w", err)
		}

		encData, err = s3Reg.Download(ctx, source.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to download from S3: %w", err)
		}
	} else {
		// HTTP/HTTPS registry
		httpReg := registry.NewHTTPRegistry(registry.DefaultConfig())
		encData, err = httpReg.Download(ctx, source.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to download from HTTP: %w", err)
		}
	}

	as.logger.Info("resource downloaded", "size", len(encData))

	// 2. Get TEE evidence for KBS attestation
	as.logger.Info("getting TEE evidence for KBS attestation")

	// Initialize KBS client first to get the challenge (nonce)
	as.logger.Info("initiating KBS attestation handshake", "kbs_url", as.computation.KBS.URL)
	kbsClient := kbs.NewClient(kbs.Config{
		URL:     as.computation.KBS.URL,
		Timeout: 30 * time.Second,
	})

	// Start RCAR handshake - get nonce and establish session cookie
	nonceStr, err := kbsClient.GetChallenge(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get KBS challenge: %w", err)
	}
	as.logger.Info("received KBS challenge nonce")

	// Decode nonce for runtime-data
	nonceBytes, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode KBS nonce: %w", err)
	}

	// Auto-detect the platform type
	platform := attestation.CCPlatform()
	as.logger.Info("detected platform type", "platform", platform)

	// RCAR Protocol Step 1: Generate ephemeral TEE key (EC P-256) for runtime-data
	as.logger.Info("generating ephemeral key pair for RCAR protocol")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	xBuf := make([]byte, 32)
	yBuf := make([]byte, 32)
	key.X.FillBytes(xBuf)
	key.Y.FillBytes(yBuf)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"alg": "ES256",
		"x":   base64.RawURLEncoding.EncodeToString(xBuf),
		"y":   base64.RawURLEncoding.EncodeToString(yBuf),
	}

	// RCAR Protocol Step 2: Create runtime-data with nonce and tee-pubkey
	runtimeData := kbs.RuntimeData{
		Nonce:     nonceStr,
		TEEPubKey: jwk,
	}

	// RCAR Protocol Step 3: Hash runtime-data to use as report_data
	// This binds the tee-pubkey to the TEE evidence
	runtimeDataJSON, err := json.Marshal(runtimeData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal runtime-data: %w", err)
	}

	runtimeDataHash := sha256.Sum256(runtimeDataJSON)
	as.logger.Info("runtime-data hash computed for report_data",
		"runtime_data_json", string(runtimeDataJSON),
		"hash_hex", hex.EncodeToString(runtimeDataHash[:]))

	var reportData [64]byte
	var nonce [32]byte

	// Use hash of runtime-data as report_data (binds tee-pubkey to evidence)
	copy(reportData[:], runtimeDataHash[:])
	// Use KBS provided nonce
	copy(nonce[:], nonceBytes)

	var kbsEvidence []byte

	// Get raw binary evidence from attestation service
	evidence, err := as.attestationClient.GetRawEvidence(ctx, reportData, nonce, platform)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation evidence: %w", err)
	}
	// Debug: Show raw evidence details
	previewLen := len(evidence)
	if previewLen > 200 {
		previewLen = 200
	}
	as.logger.Info("raw binary evidence received from service",
		"evidence_len", len(evidence),
		"evidence_hex_preview", hex.EncodeToString(evidence[:previewLen]),
		"evidence_string_preview", string(evidence[:previewLen]))

	// KBS expects tee_evidence as JSON, so we need to wrap the binary evidence
	// For NoCC/sample attestation, the evidence is already JSON from the AA sample attester
	if platform == attestation.NoCC {
		as.logger.Info("wrapping binary evidence in JSON for KBS (NoCC platform)")

		// Parse the JSON evidence from the attestation service
		// It should be: {"svn":"1","report_data":"base64..."}
		var sampleQuote map[string]interface{}
		if err := json.Unmarshal(evidence, &sampleQuote); err != nil {
			return nil, fmt.Errorf("failed to parse sample evidence JSON: %w", err)
		}

		// For sample TEE, primary_evidence IS the sample quote directly
		// The 'tee' field is already in the Request payload sent during RCAR handshake
		teeEvidenceMap := map[string]interface{}{
			"primary_evidence":    sampleQuote, // Just {"svn": "1", "report_data": "..."}
			"additional_evidence": "{}",        // Empty map as JSON string
		}
		kbsEvidence, err = json.Marshal(teeEvidenceMap)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal evidence to JSON: %w", err)
		}
	} else {
		// For real TEE platforms, the evidence must also be wrapped in the correct JSON structure
		// For now, assume it mirrors the structure but with real platform data
		// TODO: verify exact primary_evidence structure for TDX/SNP
		primaryEvidence := map[string]interface{}{
			"quote": base64.StdEncoding.EncodeToString(evidence),
		}
		teeEvidenceMap := map[string]interface{}{
			"primary_evidence":    primaryEvidence,
			"additional_evidence": "{}",
		}
		kbsEvidence, err = json.Marshal(teeEvidenceMap)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal real TEE evidence to JSON: %w", err)
		}
	}

	// Debug: Show KBS evidence details
	previewLen = len(kbsEvidence)
	if previewLen > 1000 {
		previewLen = 1000
	}
	as.logger.Info("evidence prepared for KBS",
		"kbs_evidence_len", len(kbsEvidence),
		"kbs_evidence_json", string(kbsEvidence[:previewLen]))

	// 3. Attest with KBS and get token
	as.logger.Info("attesting with KBS")

	token, err := kbsClient.Attest(ctx, kbsEvidence, runtimeData)
	if err != nil {
		return nil, fmt.Errorf("failed to attest with KBS: %w", err)
	}

	as.logger.Info("KBS attestation successful, token received")

	// 4. Get decryption key from KBS using the token
	as.logger.Info("retrieving decryption key", "resource_path", source.KBSResourcePath)

	keyData, err := kbsClient.GetResource(ctx, token, source.KBSResourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource from KBS: %w", err)
	}

	as.logger.Info("decryption key retrieved", "key_size", len(keyData))

	// 5. Parse encrypted resource and decrypt
	as.logger.Info("decrypting resource")

	encResource, err := crypto.ParseEncryptedResource(encData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted resource: %w", err)
	}

	// Generate ephemeral private key for ECDH
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	plaintext, err := crypto.DecryptWithWrappedKey(*encResource, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt resource: %w", err)
	}

	as.logger.Info("resource decrypted successfully", "plaintext_size", len(plaintext))

	return plaintext, nil
}

func (as *agentService) Algo(ctx context.Context, algo Algorithm) error {
	if as.sm.GetState() != ReceivingAlgorithm {
		return ErrStateNotReady
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.algoReceived {
		return ErrAllManifestItemsReceived
	}

	var algoData []byte

	// Check if algorithm should be downloaded from remote source
	if as.computation.Algorithm.Source != nil && as.computation.KBS.Enabled {
		as.logger.Info("downloading algorithm from remote source")

		downloadedData, err := as.downloadAndDecryptResource(ctx, as.computation.Algorithm.Source)
		if err != nil {
			return fmt.Errorf("failed to download and decrypt algorithm: %w", err)
		}

		algoData = downloadedData
	} else {
		// Use directly uploaded algorithm
		algoData = algo.Algorithm
	}

	hash := sha3.Sum256(algoData)

	if hash != as.computation.Algorithm.Hash {
		return ErrHashMismatch
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current directory: %v", err)
	}

	f, err := os.Create(filepath.Join(currentDir, "algo"))
	if err != nil {
		return fmt.Errorf("error creating algorithm file: %v", err)
	}

	if _, err := f.Write(algoData); err != nil {
		return fmt.Errorf("error writing algorithm to file: %v", err)
	}

	if err := os.Chmod(f.Name(), algoFilePermission); err != nil {
		return fmt.Errorf("error changing file permissions: %v", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("error closing file: %v", err)
	}

	algoType := algorithm.AlgorithmTypeFromContext(ctx)
	if algoType == "" {
		algoType = string(algorithm.AlgoTypeBin)
	}

	args := algorithm.AlgorithmArgsFromContext(ctx)

	as.algoType = algoType
	as.algoArgs = args
	as.algoRequirements = algo.Requirements
	as.algoReceived = true

	if err := os.Mkdir(algorithm.DatasetsDir, 0o755); err != nil {
		return fmt.Errorf("error creating datasets directory: %v", err)
	}

	if as.algoReceived {
		as.sm.SendEvent(AlgorithmReceived)
	}

	return nil
}

func (as *agentService) Data(ctx context.Context, dataset Dataset) error {
	if as.sm.GetState() != ReceivingData {
		return ErrStateNotReady
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.computation.Datasets) == 0 {
		return ErrAllManifestItemsReceived
	}

	var datasetData []byte
	var datasetFilename string

	// Check if any dataset should be downloaded from remote source
	var matchedIndex = -1
	for i, d := range as.computation.Datasets {
		if d.Source != nil && as.computation.KBS.Enabled {
			as.logger.Info("downloading dataset from remote source", "filename", d.Filename)

			downloadedData, err := as.downloadAndDecryptResource(ctx, d.Source)
			if err != nil {
				return fmt.Errorf("failed to download and decrypt dataset: %w", err)
			}

			datasetData = downloadedData
			datasetFilename = d.Filename
			matchedIndex = i
			break
		}
	}

	// If no remote dataset, use uploaded dataset
	if matchedIndex == -1 {
		datasetData = dataset.Dataset
		datasetFilename = dataset.Filename
	}

	hash := sha3.Sum256(datasetData)

	matched := false
	for i, d := range as.computation.Datasets {
		if hash == d.Hash {
			if d.Filename != "" && d.Filename != datasetFilename {
				return ErrFileNameMismatch
			}

			as.computation.Datasets = slices.Delete(as.computation.Datasets, i, i+1)

			if DecompressFromContext(ctx) {
				if err := internal.UnzipFromMemory(datasetData, algorithm.DatasetsDir); err != nil {
					return fmt.Errorf("error decompressing dataset: %v", err)
				}
			} else {
				f, err := os.Create(fmt.Sprintf("%s/%s", algorithm.DatasetsDir, datasetFilename))
				if err != nil {
					return fmt.Errorf("error creating dataset file: %v", err)
				}

				if _, err := f.Write(datasetData); err != nil {
					return fmt.Errorf("error writing dataset to file: %v", err)
				}
				if err := f.Close(); err != nil {
					return fmt.Errorf("error closing file: %v", err)
				}
			}

			matched = true
			break
		}
	}

	if !matched {
		return ErrUndeclaredDataset
	}

	if len(as.computation.Datasets) == 0 {
		defer as.sm.SendEvent(DataReceived)
	}

	return nil
}

func (as *agentService) Result(ctx context.Context) ([]byte, error) {
	currentState := as.sm.GetState()
	if currentState != ConsumingResults && currentState != Complete && currentState != Failed {
		return []byte{}, ErrResultsNotReady
	}

	index, ok := IndexFromContext(ctx)
	if !ok {
		return []byte{}, ErrUndeclaredConsumer
	}

	as.mu.Lock()
	defer as.mu.Unlock()
	if index < 0 || index >= len(as.computation.ResultConsumers) {
		return []byte{}, ErrUndeclaredConsumer
	}

	if !as.resultsConsumed && currentState == ConsumingResults {
		as.resultsConsumed = true
		defer as.sm.SendEvent(ResultsConsumed)
	}

	return as.result, as.runError
}

func (as *agentService) Attestation(ctx context.Context, reportData [vtpm.SEVNonce]byte, nonce [vtpm.Nonce]byte, attType attestation.PlatformType) ([]byte, error) {
	rawQuote, err := as.attestationClient.GetAttestation(ctx, reportData, nonce, attType)
	if err != nil {
		return []byte{}, errors.Wrap(ErrAttestationFailed, err)
	}
	return rawQuote, nil
}

func (as *agentService) AzureAttestationToken(ctx context.Context, nonce [vtpm.Nonce]byte) ([]byte, error) {
	token, err := as.attestationClient.GetAzureToken(ctx, nonce)
	if err != nil {
		return []byte{}, err
	}
	return token, nil
}

func (as *agentService) runComputation(state statemachine.State) {
	as.publishEvent(Starting.String())(state)
	as.logger.Debug("computation run started")
	defer func() {
		if as.runError != nil {
			as.sm.SendEvent(RunFailed)
		} else {
			as.sm.SendEvent(RunComplete)
		}
	}()

	if err := os.Mkdir(algorithm.ResultsDir, 0o755); err != nil {
		as.runError = fmt.Errorf("error creating results directory: %s", err.Error())
		as.logger.Warn(as.runError.Error())
		as.publishEvent(Failed.String())(state)
		return
	}

	defer func() {
		if err := os.RemoveAll(algorithm.ResultsDir); err != nil {
			as.logger.Warn(fmt.Sprintf("error removing results directory and its contents: %s", err.Error()))
		}
		if err := os.RemoveAll(algorithm.DatasetsDir); err != nil {
			as.logger.Warn(fmt.Sprintf("error removing datasets directory and its contents: %s", err.Error()))
		}
	}()

	// Read algo file
	currentDir, _ := os.Getwd()
	algoFile := filepath.Join(currentDir, "algo")
	algoBytes, err := os.ReadFile(algoFile)
	if err != nil {
		as.runError = fmt.Errorf("failed to read algo file: %w", err)
		as.logger.Warn(as.runError.Error())
		as.publishEvent(Failed.String())(state)
		return
	}

	as.publishEvent(InProgress.String())(state)

	// Call Runner
	resp, err := as.runnerClient.Run(context.Background(), &runnerpb.RunRequest{
		ComputationId: as.computation.ID,
		AlgoType:      as.algoType,
		Algorithm:     algoBytes,
		Requirements:  as.algoRequirements,
		Args:          as.algoArgs,
		// Datasets implicit on shared FS
	})
	if err != nil {
		as.runError = err
		as.logger.Warn(fmt.Sprintf("failed to run computation: %s", err.Error()))
		as.publishEvent(Failed.String())(state)
		return
	}

	if resp.Error != "" {
		as.runError = errors.New(resp.Error)
		as.logger.Warn(fmt.Sprintf("failed to run computation: %s", resp.Error))
		as.publishEvent(Failed.String())(state)
		return
	}

	results, err := internal.ZipDirectoryToMemory(algorithm.ResultsDir)
	if err != nil {
		as.runError = err
		as.logger.Warn(fmt.Sprintf("failed to zip results: %s", err.Error()))
		as.publishEvent(Failed.String())(state)
		return
	}

	as.publishEvent(Completed.String())(state)

	as.result = results
}

func (as *agentService) publishEvent(status string) statemachine.Action {
	return func(state statemachine.State) {
		as.eventSvc.SendEvent(as.computation.ID, state.String(), status, json.RawMessage{})
	}
}

func (as *agentService) IMAMeasurements(ctx context.Context) ([]byte, []byte, error) {
	data, err := os.ReadFile(ImaMeasurementsFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading Linux IMA measurements file: %s", err.Error())
	}

	pcr10, err := vtpm.GetPCRSHA1Value(ImaPcrIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading TPM PCR #10: %s", err.Error())
	}

	return data, pcr10, nil
}
