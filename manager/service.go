// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"syscall"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	hashLength     = 32
	persistenceDir = "/tmp/cocos"
)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")

	// ErrNotFound indicates a non-existent entity request.
	ErrNotFound = errors.New("entity not found")

	// ErrFailedToAllocatePort indicates no free port was found on host.
	ErrFailedToAllocatePort = errors.New("failed to allocate free port on host")

	errInvalidHashLength = errors.New("hash must be of byte length 32")

	// ErrFailedToCalculateHash indicates that agent computation returned an error while calculating the hash of the computation.
	ErrFailedToCalculateHash = errors.New("error while calculating the hash of the computation")

	// ErrFailedToCreateAttestationPolicy indicates that the script to create the attestation policy failed to execute.
	ErrFailedToCreateAttestationPolicy = errors.New("error while creating attestation policy")

	// ErrFailedToReadPolicy indicates that the file for attestation policy could not be opened.
	ErrFailedToReadPolicy = errors.New("error while opening file attestation policy")

	// ErrUnmarshalFailed indicates that the file for the attestation policy could not be unmarshaled.
	ErrUnmarshalFailed = errors.New("error while unmarshaling the attestation policy")
)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// Run create a computation.
	Run(ctx context.Context, c *ComputationRunReq) (string, error)
	// Stop stops a computation.
	Stop(ctx context.Context, computationID string) error
	// FetchAttestationPolicy measures and fetches the attestation policy.
	FetchAttestationPolicy(ctx context.Context, computationID string) ([]byte, error)
	// ReportBrokenConnection reports a broken connection.
	ReportBrokenConnection(addr string)
	// ReturnSVMInfo returns SVM information needed for attestation verification and validation.
	ReturnSVMInfo(ctx context.Context) (string, int, string, string)
}

type managerService struct {
	mu                          sync.Mutex
	ap                          sync.Mutex
	qemuCfg                     qemu.Config
	attestationPolicyBinaryPath string
	logger                      *slog.Logger
	eventsChan                  chan *ClientStreamMessage
	vms                         map[string]vm.VM
	vmFactory                   vm.Provider
	portRangeMin                int
	portRangeMax                int
	persistence                 qemu.Persistence
	eosVersion                  string
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(cfg qemu.Config, attestationPolicyBinPath string, logger *slog.Logger, eventsChan chan *ClientStreamMessage, vmFactory vm.Provider, eosVersion string) (Service, error) {
	start, end, err := decodeRange(cfg.HostFwdRange)
	if err != nil {
		return nil, err
	}

	persistence, err := qemu.NewFilePersistence(persistenceDir)
	if err != nil {
		return nil, err
	}

	ms := &managerService{
		qemuCfg:                     cfg,
		logger:                      logger,
		vms:                         make(map[string]vm.VM),
		eventsChan:                  eventsChan,
		vmFactory:                   vmFactory,
		attestationPolicyBinaryPath: attestationPolicyBinPath,
		portRangeMin:                start,
		portRangeMax:                end,
		persistence:                 persistence,
		eosVersion:                  eosVersion,
	}

	if err := ms.restoreVMs(); err != nil {
		return nil, err
	}

	return ms, nil
}

func (ms *managerService) Run(ctx context.Context, c *ComputationRunReq) (string, error) {
	ms.mu.Lock()
	cfg := qemu.VMInfo{
		Config:    ms.qemuCfg,
		LaunchTCB: 0,
	}
	ms.mu.Unlock()

	if ms.qemuCfg.EnableSEVSNP || ms.qemuCfg.EnableSEV {
		cmd := exec.Command("sudo", fmt.Sprintf("%s/attestation_policy", ms.attestationPolicyBinaryPath), "--policy", "196608")

		ms.ap.Lock()
		_, err := cmd.Output()
		ms.ap.Unlock()
		if err != nil {
			return "", errors.Wrap(ErrFailedToCreateAttestationPolicy, err)
		}

		ms.ap.Lock()
		f, err := os.ReadFile("./attestation_policy.json")
		ms.ap.Unlock()
		if err != nil {
			return "", errors.Wrap(ErrFailedToReadPolicy, err)
		}

		var attestationPolicy check.Config

		if err = protojson.Unmarshal(f, &attestationPolicy); err != nil {
			return "", errors.Wrap(ErrUnmarshalFailed, err)
		}

		// Define the TCB that was present at launch of the VM.
		cfg.LaunchTCB = attestationPolicy.Policy.MinimumLaunchTcb
	}
	ms.publishEvent(manager.VmProvision.String(), c.Id, manager.Starting.String(), json.RawMessage{})
	ac := agent.Computation{
		ID:          c.Id,
		Name:        c.Name,
		Description: c.Description,
		AgentConfig: agent.AgentConfig{
			Port:         c.AgentConfig.Port,
			Host:         c.AgentConfig.Host,
			KeyFile:      c.AgentConfig.KeyFile,
			CertFile:     c.AgentConfig.CertFile,
			ServerCAFile: c.AgentConfig.ServerCaFile,
			ClientCAFile: c.AgentConfig.ClientCaFile,
			LogLevel:     c.AgentConfig.LogLevel,
			AttestedTls:  c.AgentConfig.AttestedTls,
		},
	}
	if len(c.Algorithm.Hash) != hashLength {
		ms.publishEvent(manager.VmProvision.String(), c.Id, agent.Failed.String(), json.RawMessage{})
		return "", errInvalidHashLength
	}

	ac.Algorithm = agent.Algorithm{Hash: [hashLength]byte(c.Algorithm.Hash), UserKey: c.Algorithm.UserKey}

	for _, data := range c.Datasets {
		if len(data.Hash) != hashLength {
			ms.publishEvent(manager.VmProvision.String(), c.Id, agent.Failed.String(), json.RawMessage{})
			return "", errInvalidHashLength
		}
		ac.Datasets = append(ac.Datasets, agent.Dataset{Hash: [hashLength]byte(data.Hash), UserKey: data.UserKey, Filename: data.Filename})
	}

	for _, rc := range c.ResultConsumers {
		ac.ResultConsumers = append(ac.ResultConsumers, agent.ResultConsumer{UserKey: rc.UserKey})
	}

	agentPort, err := getFreePort(ms.portRangeMin, ms.portRangeMax)
	if err != nil {
		ms.publishEvent(manager.VmProvision.String(), c.Id, agent.Failed.String(), json.RawMessage{})
		return "", errors.Wrap(ErrFailedToAllocatePort, err)
	}
	cfg.Config.HostFwdAgent = agentPort

	var cid int = qemu.BaseGuestCID
	for {
		available := true
		for _, vm := range ms.vms {
			if vm.GetCID() == cid {
				available = false
				break
			}
		}
		if available {
			break
		}
		cid++
	}
	cfg.Config.VSockConfig.GuestCID = cid

	if cfg.Config.EnableSEVSNP {
		ch, err := computationHash(ac)
		if err != nil {
			ms.publishEvent(manager.VmProvision.String(), c.Id, agent.Failed.String(), json.RawMessage{})
			return "", errors.Wrap(ErrFailedToCalculateHash, err)
		}

		// Define host-data value of QEMU for SEV-SNP, with a base64 encoding of the computation hash.
		cfg.Config.SevConfig.HostData = base64.StdEncoding.EncodeToString(ch[:])
	}

	cvm := ms.vmFactory(cfg, ms.eventsLogsSender, c.Id)
	ms.publishEvent(manager.VmProvision.String(), c.Id, agent.InProgress.String(), json.RawMessage{})
	if err = cvm.Start(); err != nil {
		ms.publishEvent(manager.VmProvision.String(), c.Id, agent.Failed.String(), json.RawMessage{})
		return "", err
	}
	ms.mu.Lock()
	ms.vms[c.Id] = cvm
	ms.mu.Unlock()

	pid := cvm.GetProcess()

	state := qemu.VMState{
		ID:     c.Id,
		VMinfo: cfg,
		PID:    pid,
	}
	if err := ms.persistence.SaveVM(state); err != nil {
		ms.logger.Error("Failed to persist VM state", "error", err)
	}

	err = backoff.Retry(func() error {
		return cvm.SendAgentConfig(ac)
	}, backoff.NewExponentialBackOff())
	if err != nil {
		return "", err
	}

	ms.mu.Lock()
	if err := ms.vms[c.Id].Transition(manager.VmRunning); err != nil {
		ms.logger.Warn("Failed to transition VM state", "computation", c.Id, "error", err)
	}
	ms.mu.Unlock()

	ms.publishEvent(manager.VmProvision.String(), c.Id, agent.Completed.String(), json.RawMessage{})

	return fmt.Sprint(agentPort), nil
}

func (ms *managerService) Stop(ctx context.Context, computationID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	cvm, ok := ms.vms[computationID]
	if !ok {
		defer ms.publishEvent(manager.StopComputationRun.String(), computationID, agent.Failed.String(), json.RawMessage{})
		return ErrNotFound
	}
	if err := cvm.Stop(); err != nil {
		defer ms.publishEvent(manager.StopComputationRun.String(), computationID, agent.Failed.String(), json.RawMessage{})
		return err
	}
	delete(ms.vms, computationID)

	if err := ms.persistence.DeleteVM(computationID); err != nil {
		ms.logger.Error("Failed to delete persisted VM state", "error", err)
	}

	defer ms.publishEvent(manager.StopComputationRun.String(), computationID, agent.Completed.String(), json.RawMessage{})
	return nil
}

func (ms *managerService) ReturnSVMInfo(ctx context.Context) (string, int, string, string) {
	return ms.qemuCfg.OVMFCodeConfig.Version, ms.qemuCfg.SMPCount, ms.qemuCfg.CPU, ms.eosVersion
}

func getFreePort(minPort, maxPort int) (int, error) {
	if checkPortisFree(minPort) {
		return minPort, nil
	}

	var wg sync.WaitGroup
	portCh := make(chan int, 1)

	for port := minPort; port <= maxPort; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if checkPortisFree(p) {
				select {
				case portCh <- p:
				default:
				}
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(portCh)
	}()

	port, ok := <-portCh
	if !ok {
		return 0, fmt.Errorf("failed to find free port in range %d-%d", minPort, maxPort)
	}

	return port, nil
}

func checkPortisFree(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	defer listener.Close()

	return true
}

func (ms *managerService) publishEvent(event, cmpID, status string, details json.RawMessage) {
	ms.eventsChan <- &ClientStreamMessage{
		Message: &ClientStreamMessage_AgentEvent{
			AgentEvent: &AgentEvent{
				EventType:     event,
				ComputationId: cmpID,
				Status:        status,
				Details:       details,
				Timestamp:     timestamppb.Now(),
				Originator:    "manager",
			},
		},
	}
}

func computationHash(ac agent.Computation) ([32]byte, error) {
	jsonData, err := json.Marshal(ac)
	if err != nil {
		return [32]byte{}, err
	}

	return sha3.Sum256(jsonData), nil
}

func decodeRange(input string) (int, int, error) {
	re := regexp.MustCompile(`(\d+)-(\d+)`)
	matches := re.FindStringSubmatch(input)
	if len(matches) != 3 {
		return 0, 0, fmt.Errorf("invalid input format: %s", input)
	}

	start, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, err
	}

	end, err := strconv.Atoi(matches[2])
	if err != nil {
		return 0, 0, err
	}

	if start > end {
		return 0, 0, fmt.Errorf("invalid range: %d-%d", start, end)
	}

	return start, end, nil
}

func (ms *managerService) restoreVMs() error {
	states, err := ms.persistence.LoadVMs()
	if err != nil {
		return err
	}

	for _, state := range states {
		if !ms.processExists(state.PID) {
			if err := ms.persistence.DeleteVM(state.ID); err != nil {
				ms.logger.Error("Failed to delete persisted VM state", "computation", state.ID, "error", err)
			}
			ms.logger.Info("Deleted persisted state for non-existent process", "computation", state.ID, "pid", state.PID)
			continue
		}

		cvm := ms.vmFactory(state.VMinfo, ms.eventsLogsSender, state.ID)

		if err = cvm.SetProcess(state.PID); err != nil {
			ms.logger.Warn("Failed to reattach to process", "computation", state.ID, "pid", state.PID, "error", err)
			continue
		}

		if err := cvm.Transition(manager.VmRunning); err != nil {
			ms.logger.Warn("Failed to transition VM state", "computation", state.ID, "error", err)
		}

		ms.vms[state.ID] = cvm
		ms.logger.Info("Successfully restored VM state", "id", state.ID, "computationId", state.ID, "pid", state.PID)
	}

	return nil
}

func (ms *managerService) processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		ms.logger.Warn("Failed to find process", "pid", pid, "error", err)
		return false
	}

	if err = process.Signal(syscall.Signal(0)); err == nil {
		return true
	}
	if err == syscall.ESRCH {
		return false
	}
	return false
}

func (ms *managerService) eventsLogsSender(e interface{}) error {
	switch msg := e.(type) {
	case *vm.Event:
		ms.eventsChan <- &ClientStreamMessage{
			Message: &ClientStreamMessage_AgentEvent{
				AgentEvent: &AgentEvent{
					EventType:     msg.EventType,
					Timestamp:     msg.Timestamp,
					ComputationId: msg.ComputationId,
					Originator:    msg.Originator,
					Status:        msg.Status,
					Details:       msg.Details,
				},
			},
		}
	case *vm.Log:
		ms.eventsChan <- &ClientStreamMessage{
			Message: &ClientStreamMessage_AgentLog{
				AgentLog: &AgentLog{
					ComputationId: msg.ComputationId,
					Level:         msg.Level,
					Timestamp:     msg.Timestamp,
					Message:       msg.Message,
				},
			},
		}
	}
	return nil
}
