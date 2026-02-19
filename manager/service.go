// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/uuid"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/crypto/sha3"
)

const (
	persistenceDir          = "/tmp/cocos"
	agentLogLevelKey        = "AGENT_LOG_LEVEL"
	agentCvmGrpcUrlKey      = "AGENT_CVM_GRPC_URL"
	agentCvmClientCertKey   = "AGENT_CVM_GRPC_CLIENT_CERT"
	agentCvmClientKey       = "AGENT_CVM_GRPC_CLIENT_KEY"
	agentCvmServerCaCertKey = "AGENT_CVM_GRPC_SERVER_CA_CERTS"
	agentCvmId              = "AGENT_CVM_ID"
	agentCaToken            = "AGENT_CERTS_TOKEN"
	agentCvmCaUrl           = "AGENT_CVM_CA_URL"
	awsAccessKeyIdKey       = "AWS_ACCESS_KEY_ID"
	awsSecretAccessKeyKey   = "AWS_SECRET_ACCESS_KEY"
	awsEndpointUrlKey       = "AWS_ENDPOINT_URL"
	awsRegionKey            = "AWS_REGION"
	defClientCertPath       = "/etc/certs/cert.pem"
	defClientKeyPath        = "/etc/certs/key.pem"
	defServerCaCertPath     = "/etc/certs/ca.pem"
	cvmEnvironmentFile      = "environment"
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

	// ErrFailedToCalculateHash indicates that agent computation returned an error while calculating the hash of the computation.
	ErrFailedToCalculateHash = errors.New("error while calculating the hash of the computation")

	// ErrFailedToCreateAttestationPolicy indicates that the script to create the attestation policy failed to execute.
	ErrFailedToCreateAttestationPolicy = errors.New("error while creating attestation policy")

	// ErrFailedToReadPolicy indicates that the file for attestation policy could not be opened.
	ErrFailedToReadPolicy = errors.New("error while opening file attestation policy")

	// ErrUnmarshalFailed indicates that the file for the attestation policy could not be unmarshaled.
	ErrUnmarshalFailed = errors.New("error while unmarshaling the attestation policy")

	// ErrMaxVMsExceeded indicates that the maximum number of VMs has been reached.
	ErrMaxVMsExceeded = errors.New("maximum number of VMs exceeded")
)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// Run create a computation.
	CreateVM(ctx context.Context, req *CreateReq) (string, string, error)
	// Stop stops a computation.
	RemoveVM(ctx context.Context, computationID string) error
	// FetchAttestationPolicy measures and fetches the attestation policy.
	FetchAttestationPolicy(ctx context.Context, computationID string) ([]byte, error)
	// ReturnCVMInfo returns CVM information needed for attestation verification and validation.
	ReturnCVMInfo(ctx context.Context) (string, int, string, string)
	// Shutdown gracefully shuts down the service
	Shutdown() error
}

type managerService struct {
	mu                          sync.Mutex
	ap                          sync.Mutex
	qemuCfg                     qemu.Config
	attestationPolicyBinaryPath string
	igvmMeasurementBinaryPath   string
	pcrValuesFilePath           string
	logger                      *slog.Logger
	vms                         map[string]vm.VM
	vmFactory                   vm.Provider
	portRangeMin                int
	portRangeMax                int
	persistence                 qemu.Persistence
	eosVersion                  string
	ttlManager                  *TTLManager
	maxVMs                      int
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(cfg qemu.Config, attestationPolicyBinPath string, igvmMeasurementBinaryPath string, pcrValuesFilePath string, logger *slog.Logger, vmFactory vm.Provider, eosVersion string, maxVMs int) (Service, error) {
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
		vmFactory:                   vmFactory,
		attestationPolicyBinaryPath: attestationPolicyBinPath,
		igvmMeasurementBinaryPath:   igvmMeasurementBinaryPath,
		pcrValuesFilePath:           pcrValuesFilePath,
		portRangeMin:                start,
		portRangeMax:                end,
		persistence:                 persistence,
		eosVersion:                  eosVersion,
		ttlManager:                  NewTTLManager(),
		maxVMs:                      maxVMs,
	}

	if err := ms.restoreVMs(); err != nil {
		return nil, err
	}

	return ms, nil
}

func (ms *managerService) CreateVM(ctx context.Context, req *CreateReq) (string, string, error) {
	id := uuid.New().String()

	ms.mu.Lock()
	if ms.maxVMs > 0 && len(ms.vms) >= ms.maxVMs {
		ms.mu.Unlock()
		return "", id, ErrMaxVMsExceeded
	}

	cfg := qemu.VMInfo{
		Config:    ms.qemuCfg,
		LaunchTCB: 0,
	}
	if req.AaKbsParams != "" {
		cfg.Config.KernelCommandLine = fmt.Sprintf("%s agent.aa_kbc_params=%s", cfg.Config.KernelCommandLine, req.AaKbsParams)
	}
	ms.mu.Unlock()

	tmpCertsDir, err := tempCertMount(id, req)
	if err != nil {
		return "", id, err
	}

	tmpEnvDir, err := tmpEnvironment(id, req)
	if err != nil {
		return "", id, err
	}

	cfg.Config.CertsMount = tmpCertsDir
	cfg.Config.EnvMount = tmpEnvDir

	if ms.qemuCfg.EnableSEVSNP {
		attestPolicyCmd, err := fetchSNPAttestationPolicy(ms)
		if err != nil {
			return "", id, err
		}

		var stdOutByte []byte
		ms.ap.Lock()
		stdOutByte, err = attestPolicyCmd.Run(ms.attestationPolicyBinaryPath)
		ms.ap.Unlock()
		if err != nil {
			return "", id, errors.Wrap(ErrFailedToCreateAttestationPolicy, err)
		}

		attestationPolicy := attestation.Config{Config: &check.Config{RootOfTrust: &check.RootOfTrust{}, Policy: &check.Policy{}}, PcrConfig: &attestation.PcrConfig{}}

		if err = vtpm.ReadPolicyFromByte(stdOutByte, &attestationPolicy); err != nil {
			return "", id, errors.Wrap(ErrUnmarshalFailed, err)
		}

		// Define the TCB that was present at launch of the VM.
		cfg.LaunchTCB = attestationPolicy.Config.Policy.MinimumLaunchTcb
	}

	agentPort, err := getFreePort(ms.portRangeMin, ms.portRangeMax)
	if err != nil {
		return "", id, errors.Wrap(ErrFailedToAllocatePort, err)
	}
	cfg.Config.HostFwdAgent = agentPort

	if cfg.Config.EnableSEVSNP {
		todo := sha3.Sum256([]byte("TODO"))
		// Define host-data value of QEMU for SEV-SNP, with a base64 encoding of the computation hash.
		cfg.Config.SEVSNPConfig.HostData = base64.StdEncoding.EncodeToString(todo[:])
	}

	cvm := ms.vmFactory(cfg, id, ms.logger)
	if err = cvm.Start(); err != nil {
		return "", id, err
	}

	ms.mu.Lock()
	if ms.maxVMs > 0 && len(ms.vms) >= ms.maxVMs {
		ms.mu.Unlock()
		if stopErr := cvm.Stop(); stopErr != nil {
			ms.logger.Error("Failed to stop VM after exceeding max limit", "vmID", id, "error", stopErr)
		}
		return "", id, ErrMaxVMsExceeded
	}
	ms.vms[id] = cvm
	ms.mu.Unlock()

	if req.Ttl != "" {
		ttl, err := time.ParseDuration(req.Ttl)
		if err != nil {
			return "", id, err
		}

		ms.ttlManager.SetTTL(id, ttl, func() { //nolint:contextcheck
			if err := ms.RemoveVM(context.Background(), id); err != nil {
				ms.logger.Error("Failed to remove VM after TTL expiry", "vmID", id, "error", err)
			} else {
				ms.logger.Info("Successfully removed VM after TTL expiry", "vmID", id)
			}
		})
	}

	pid := cvm.GetProcess()

	state := qemu.VMState{
		ID:     id,
		VMinfo: cfg,
		PID:    pid,
	}
	if err := ms.persistence.SaveVM(state); err != nil {
		ms.logger.Error("Failed to persist VM state", "error", err)
	}

	ms.mu.Lock()
	if err := ms.vms[id].Transition(manager.VmRunning); err != nil {
		ms.logger.Warn("Failed to transition VM state", "cvm", id, "error", err)
	}
	ms.mu.Unlock()

	return fmt.Sprint(agentPort), id, nil
}

func (ms *managerService) RemoveVM(ctx context.Context, computationID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.ttlManager.CancelTTL(computationID)

	cvm, ok := ms.vms[computationID]
	if !ok {
		return ErrNotFound
	}
	if err := cvm.Stop(); err != nil {
		return err
	}
	delete(ms.vms, computationID)

	if err := ms.persistence.DeleteVM(computationID); err != nil {
		ms.logger.Error("Failed to delete persisted VM state", "error", err)
	}

	return nil
}

func (ms *managerService) ReturnCVMInfo(ctx context.Context) (string, int, string, string) {
	return ms.qemuCfg.OVMFCodeConfig.Version, ms.qemuCfg.SMPCount, ms.qemuCfg.CPU, ms.eosVersion
}

// Shutdown gracefully shuts down the service.
func (ms *managerService) Shutdown() error {
	ms.logger.Info("Shutting down manager service")

	ms.ttlManager.CancelAll()

	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.vms = make(map[string]vm.VM)

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

		cvm := ms.vmFactory(state.VMinfo, state.ID, ms.logger)

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

func tempCertMount(id string, req *CreateReq) (string, error) {
	dir, err := os.MkdirTemp("/tmp", id)
	if err != nil {
		return "", err
	}

	if err = os.WriteFile(fmt.Sprintf("%s/%s", dir, "cert.pem"), req.AgentCvmClientCert, 0o644); err != nil {
		return "", err
	}

	if err = os.WriteFile(fmt.Sprintf("%s/%s", dir, "key.pem"), req.AgentCvmClientKey, 0o644); err != nil {
		return "", err
	}

	if err = os.WriteFile(fmt.Sprintf("%s/%s", dir, "ca.pem"), req.AgentCvmServerCaCert, 0o644); err != nil {
		return "", err
	}

	return dir, nil
}

func tmpEnvironment(id string, req *CreateReq) (string, error) {
	dir, err := os.MkdirTemp("/tmp", id)
	if err != nil {
		return "", err
	}

	envMap := map[string]string{
		agentLogLevelKey:   req.AgentLogLevel,
		agentCvmGrpcUrlKey: req.AgentCvmServerUrl,
		agentCvmId:         id,
		agentCaToken:       req.AgentCertsToken,
		agentCvmCaUrl:      req.AgentCvmCaUrl,
	}

	if req.AgentCvmClientCert != nil {
		envMap[agentCvmClientCertKey] = defClientCertPath
	}
	if req.AgentCvmClientKey != nil {
		envMap[agentCvmClientKey] = defClientKeyPath
	}
	if req.AgentCvmServerCaCert != nil {
		envMap[agentCvmServerCaCertKey] = defServerCaCertPath
	}

	// Add AWS credentials if provided
	if req.AwsAccessKeyId != "" {
		envMap[awsAccessKeyIdKey] = req.AwsAccessKeyId
	}
	if req.AwsSecretAccessKey != "" {
		envMap[awsSecretAccessKeyKey] = req.AwsSecretAccessKey
	}
	if req.AwsEndpointUrl != "" {
		envMap[awsEndpointUrlKey] = req.AwsEndpointUrl
	}
	if req.AwsRegion != "" {
		envMap[awsRegionKey] = req.AwsRegion
	}

	envFile, err := os.OpenFile(fmt.Sprintf("%s/%s", dir, cvmEnvironmentFile), os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}

	for k, v := range envMap {
		if _, err = envFile.WriteString(fmt.Sprintf("%s=%s\n", k, v)); err != nil {
			return "", err
		}
	}

	if err = envFile.Close(); err != nil {
		return "", err
	}

	return dir, nil
}
