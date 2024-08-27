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
	"regexp"
	"strconv"
	"sync"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/cenkalti/backoff/v4"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/crypto/sha3"
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
)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// Run create a computation.
	Run(ctx context.Context, c *manager.ComputationRunReq) (string, error)
	// Stop stops a computation.
	Stop(ctx context.Context, computationID string) error
	// RetrieveAgentEventsLogs Retrieve and forward agent logs and events via vsock.
	RetrieveAgentEventsLogs()
	// FetchBackendInfo measures and fetches the backend information.
	FetchBackendInfo() ([]byte, error)
}

type managerService struct {
	qemuCfg                      qemu.Config
	backendMeasurementBinaryPath string
	logger                       *slog.Logger
	eventsChan                   chan *manager.ClientStreamMessage
	vms                          map[string]vm.VM
	vmFactory                    vm.Provider
	portRangeMin                 int
	portRangeMax                 int
	persistence                  qemu.Persistence
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(cfg qemu.Config, backendMeasurementBinPath string, logger *slog.Logger, eventsChan chan *manager.ClientStreamMessage, vmFactory vm.Provider) (Service, error) {
	start, end, err := decodeRange(cfg.HostFwdRange)
	if err != nil {
		return nil, err
	}

	persistence, err := qemu.NewFilePersistence(persistenceDir)
	if err != nil {
		return nil, err
	}

	ms := &managerService{
		qemuCfg:                      cfg,
		logger:                       logger,
		vms:                          make(map[string]vm.VM),
		eventsChan:                   eventsChan,
		vmFactory:                    vmFactory,
		backendMeasurementBinaryPath: backendMeasurementBinPath,
		portRangeMin:                 start,
		portRangeMax:                 end,
		persistence:                  persistence,
	}

	if err := ms.restoreVMs(); err != nil {
		return nil, err
	}

	return ms, nil
}

func (ms *managerService) Run(ctx context.Context, c *manager.ComputationRunReq) (string, error) {
	ms.publishEvent("vm-provision", c.Id, "starting", json.RawMessage{})
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
		},
	}
	ac.Algorithm = agent.Algorithm{Hash: [hashLength]byte(c.Algorithm.Hash), UserKey: c.Algorithm.UserKey}

	for _, data := range c.Datasets {
		if len(data.Hash) != hashLength {
			ms.publishEvent("vm-provision", c.Id, "failed", json.RawMessage{})
			return "", errInvalidHashLength
		}
		ac.Datasets = append(ac.Datasets, agent.Dataset{Hash: [hashLength]byte(data.Hash), UserKey: data.UserKey, Filename: data.Filename})
	}

	for _, rc := range c.ResultConsumers {
		ac.ResultConsumers = append(ac.ResultConsumers, agent.ResultConsumer{UserKey: rc.UserKey})
	}

	agentPort, err := getFreePort(ms.portRangeMin, ms.portRangeMax)
	if err != nil {
		ms.publishEvent("vm-provision", c.Id, "failed", json.RawMessage{})
		return "", errors.Wrap(ErrFailedToAllocatePort, err)
	}
	ms.qemuCfg.HostFwdAgent = agentPort
	ms.qemuCfg.VSockConfig.GuestCID = qemu.BaseGuestCID + len(ms.vms)

	ch, err := computationHash(ac)
	if err != nil {
		ms.publishEvent("vm-provision", c.Id, "failed", json.RawMessage{})
		return "", errors.Wrap(ErrFailedToCalculateHash, err)
	}

	// Define host-data value of QEMU for SEV-SNP, with a base64 encoding of the computation hash.
	ms.qemuCfg.SevConfig.HostData = base64.StdEncoding.EncodeToString(ch[:])

	cvm := ms.vmFactory(ms.qemuCfg, ms.eventsChan, c.Id)
	ms.publishEvent("vm-provision", c.Id, "in-progress", json.RawMessage{})
	if err = cvm.Start(); err != nil {
		ms.publishEvent("vm-provision", c.Id, "failed", json.RawMessage{})
		return "", err
	}
	ms.vms[c.Id] = cvm

	pid := cvm.GetProcess()

	state := qemu.VMState{
		ID:     c.Id,
		Config: ms.qemuCfg,
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

	ms.qemuCfg.VSockConfig.Vnc++

	ms.publishEvent("vm-provision", c.Id, "complete", json.RawMessage{})
	return fmt.Sprint(ms.qemuCfg.HostFwdAgent), nil
}

func (ms *managerService) Stop(ctx context.Context, computationID string) error {
	cvm, ok := ms.vms[computationID]
	if !ok {
		defer ms.publishEvent("stop-computation", computationID, "failed", json.RawMessage{})
		return ErrNotFound
	}
	if err := cvm.Stop(); err != nil {
		defer ms.publishEvent("stop-computation", computationID, "failed", json.RawMessage{})
		return err
	}
	delete(ms.vms, computationID)

	if err := ms.persistence.DeleteVM(computationID); err != nil {
		ms.logger.Error("Failed to delete persisted VM state", "error", err)
	}

	defer ms.publishEvent("stop-computation", computationID, "complete", json.RawMessage{})
	return nil
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
	ms.eventsChan <- &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentEvent{
			AgentEvent: &manager.AgentEvent{
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
		cvm := ms.vmFactory(state.Config, ms.eventsChan, state.ID)

		err := cvm.SetProcess(state.PID)
		if err != nil {
			ms.logger.Warn("Failed to reattach to process, VM may not be running", "computation", state.ID, "pid", state.PID, "error", err)
		} else {
			ms.logger.Info("Successfully reattached to VM process", "computation", state.ID, "pid", state.PID)
		}

		ms.vms[state.ID] = cvm

		ms.logger.Info("Restored VM state", "id", state.ID, "computationId", state.ID)
	}

	return nil
}
