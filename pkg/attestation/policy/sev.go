// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/cmdconfig"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	sevIssueCmdIOCTL = iowr(uintptr('S'), 0x0, 16)

	ErrSNPPlatformStatus = errors.New("SNP platform status")
	ErrGetID2Sev         = errors.New("ID2 IOCTAL error")
	ErrEPYCDetection     = errors.New("failed to detect EPYC generation")
	ErrPCRFile           = errors.New("failed to read PCR file")
	ErrFailedToParse     = errors.New("failed to parse PCR JSON file")
	ErrDecodeHostData    = errors.New("failed to decode host data")
	ErrMeasurement       = errors.New("failed to calculate measurement")
)

const (
	DevSev      = "/dev/sev"
	ProcCpuInfo = "/proc/cpuinfo"

	iocNrbits   = 8
	iocTypebits = 8
	iocSizebits = 14
	iocDirbits  = 2

	iocNrshift   = 0
	iocTypeshift = iocNrshift + iocNrbits
	iocSizeshift = iocTypeshift + iocTypebits
	iocDirshift  = iocSizeshift + iocSizebits

	iocWrite = 1
	iocRead  = 2

	SEV_GET_ID2              = 8
	SNP_PLATFORM_STATUS_UAPI = 9
	SEV_RET_INVALID_LEN      = 4
)

func ioc(dir, typ, nr, size uintptr) uintptr {
	return (dir << iocDirshift) |
		(typ << iocTypeshift) |
		(nr << iocNrshift) |
		(size << iocSizeshift)
}

func iowr(typ, nr, size uintptr) uintptr {
	return ioc(iocRead|iocWrite, typ, nr, size)
}

type TcbVersion struct {
	Bootloader uint8
	TEE        uint8
	Reserved   [4]uint8
	SNP        uint8
	Microcode  uint8
}

func (t *TcbVersion) ToUint64() uint64 {
	return uint64(t.Bootloader) |
		(uint64(t.TEE) << 8) |
		(uint64(t.SNP) << 48) |
		(uint64(t.Microcode) << 56)
}

type SnpPlatformStatusABI struct {
	APIVersion  [2]uint8
	State       uint8
	IsRMPInit   uint8
	BuildID     uint32
	MaskChipID  uint32
	GuestCount  uint32
	CurrentTCB  TcbVersion
	ReportedTCB TcbVersion
}

type SevUserDataGetID2 struct {
	Address uint64
	Length  uint32
}

type SevIssueCmd struct {
	Cmd     uint32
	DataPtr unsafe.Pointer
	FwErr   uint32
}

func issueSevCommand(fd int, cmd *SevIssueCmd) error {
	// Pack the sev_issue_cmd struct (16 bytes)
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], cmd.Cmd)
	binary.LittleEndian.PutUint64(buf[4:12], uint64(uintptr(cmd.DataPtr)))
	binary.LittleEndian.PutUint32(buf[12:16], 0)

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), sevIssueCmdIOCTL, uintptr(unsafe.Pointer(&buf[0])))

	runtime.KeepAlive(cmd)
	runtime.KeepAlive(&buf)

	// Read back firmware error
	cmd.FwErr = binary.LittleEndian.Uint32(buf[12:16])

	if errno != 0 {
		return errno
	}
	return nil
}

func GetSnpPlatformStatus(dev string) (*SnpPlatformStatusABI, error) {
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dev, err)
	}
	defer f.Close()

	var status SnpPlatformStatusABI

	cmd := &SevIssueCmd{
		Cmd:     SNP_PLATFORM_STATUS_UAPI,
		DataPtr: unsafe.Pointer(&status),
	}

	if err := issueSevCommand(int(f.Fd()), cmd); err != nil {
		return nil, fmt.Errorf("ioctl SEV_ISSUE_CMD(SNP_PLATFORM_STATUS): %w (fwErr=%d)", err, cmd.FwErr)
	}

	return &status, nil
}

func GetID2FromDevSev(dev string) ([]byte, error) {
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dev, err)
	}
	defer f.Close()

	var getData SevUserDataGetID2

	cmd := &SevIssueCmd{
		Cmd:     SEV_GET_ID2,
		DataPtr: unsafe.Pointer(&getData),
	}

	err = issueSevCommand(int(f.Fd()), cmd)

	if err != nil && cmd.FwErr != SEV_RET_INVALID_LEN {
		return nil, fmt.Errorf("GET_ID2 initial ioctl failed: %w (fwErr=%d)", err, cmd.FwErr)
	}

	if getData.Length == 0 {
		return nil, fmt.Errorf("GET_ID2 did not report required length (fwErr=%d)", cmd.FwErr)
	}

	// Second call: fetch actual data
	idBuf := make([]byte, getData.Length)
	getData2 := SevUserDataGetID2{
		Address: uint64(uintptr(unsafe.Pointer(&idBuf[0]))),
		Length:  getData.Length,
	}

	cmd2 := &SevIssueCmd{
		Cmd:     SEV_GET_ID2,
		DataPtr: unsafe.Pointer(&getData2),
	}

	if err := issueSevCommand(int(f.Fd()), cmd2); err != nil {
		return nil, fmt.Errorf("GET_ID2 fetch ioctl failed: %w (fwErr=%d)", err, cmd2.FwErr)
	}

	n := getData2.Length
	if n > uint32(len(idBuf)) {
		n = uint32(len(idBuf))
	}

	return idBuf[:n], nil
}

func EpycGenerationName(product sevsnp.SevProduct_SevProductName) string {
	switch product {
	case sevsnp.SevProduct_SEV_PRODUCT_MILAN:
		return "Milan"
	case sevsnp.SevProduct_SEV_PRODUCT_GENOA:
		return "Genoa"
	default:
		return "Unknown"
	}
}

func DetectEpycGeneration() (sevsnp.SevProduct, error) {
	family, model, modelName, err := readFirstCPUFamilyModel(ProcCpuInfo)
	if err != nil {
		return sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN}, err
	}

	if family != 25 {
		return sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN}, fmt.Errorf("not AMD Family 19h (cpu family=%d, model=%d, model name=%q)", family, model, modelName)
	}

	switch {
	case model >= 0 && model <= 15:
		return sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_MILAN}, nil
	case model >= 16 && model <= 31:
		return sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_GENOA}, nil
	default:
		return sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN}, fmt.Errorf("AMD Family 19h but model out of expected Milan/Genoa ranges: model=%d (model name=%q)", model, modelName)
	}
}

func readFirstCPUFamilyModel(path string) (family int, model int, modelName string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	gotFamily := false
	gotModel := false

	for sc.Scan() {
		line := sc.Text()

		if strings.TrimSpace(line) == "" && (gotFamily || gotModel || modelName != "") {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "cpu family":
			n, e := strconv.Atoi(val)
			if e != nil {
				return 0, 0, "", fmt.Errorf("parse cpu family %q: %w", val, e)
			}
			family = n
			gotFamily = true

		case "model":
			n, e := strconv.Atoi(val)
			if e != nil {
				return 0, 0, "", fmt.Errorf("parse model %q: %w", val, e)
			}
			model = n
			gotModel = true

		case "model name":
			modelName = val
		}
	}

	if err := sc.Err(); err != nil {
		return 0, 0, "", fmt.Errorf("scan %s: %w", path, err)
	}
	if !gotFamily || !gotModel {
		return 0, 0, modelName, fmt.Errorf("missing cpu family/model in %s (family=%v model=%v model name=%q)", path, gotFamily, gotModel, modelName)
	}

	return family, model, modelName, nil
}

func FetchSEVSNPAttestationPolicy(policy uint64, pcrPath string, igvmFile string, igvmMeasurementBinary string, hostDataEnable bool, hostData string) (*attestation.Config, error) {
	st, err := GetSnpPlatformStatus(DevSev)
	if err != nil {
		return nil, errors.Wrap(ErrSNPPlatformStatus, err)
	}

	id, err := GetID2FromDevSev(DevSev)
	if err != nil {
		return nil, errors.Wrap(ErrGetID2Sev, err)
	}

	reportIdMa := make([]byte, 32)
	for i := 0; i < 32; i++ {
		reportIdMa[i] = 0xFF
	}

	product, err := DetectEpycGeneration()
	if err != nil {
		return nil, errors.Wrap(ErrEPYCDetection, err)
	}

	Policy := &check.Policy{
		Policy:                    policy,
		FamilyId:                  make([]byte, 16),
		ImageId:                   make([]byte, 16),
		Vmpl:                      wrapperspb.UInt32(2),
		MinimumTcb:                st.ReportedTCB.ToUint64(),
		MinimumLaunchTcb:          st.ReportedTCB.ToUint64(),
		RequireAuthorKey:          false,
		Measurement:               make([]byte, 48),
		HostData:                  make([]byte, 32),
		ReportIdMa:                reportIdMa,
		ChipId:                    id,
		MinimumBuild:              st.BuildID,
		MinimumVersion:            fmt.Sprintf("%d.%d", st.APIVersion[0], st.APIVersion[1]),
		PermitProvisionalFirmware: true,
		RequireIdBlock:            false,
		Product:                   &product,
	}

	rootOfTrust := &check.RootOfTrust{
		Product:         EpycGenerationName(product.Name),
		CheckCrl:        true,
		DisallowNetwork: false,
		ProductLine:     EpycGenerationName(product.Name),
	}

	snpPolicy := check.Config{
		Policy:      Policy,
		RootOfTrust: rootOfTrust,
	}

	config := &attestation.Config{
		Config:    &snpPolicy,
		PcrConfig: &attestation.PcrConfig{},
	}

	if pcrPath != "" {
		pcrContent, err := os.ReadFile(pcrPath)
		if err != nil {
			return nil, errors.Wrap(ErrPCRFile, err)
		}

		if err := json.Unmarshal(pcrContent, &config.PcrConfig); err != nil {
			return nil, errors.Wrap(ErrFailedToParse, err)
		}
	}

	if hostDataEnable {
		hostDataBynary, err := base64.StdEncoding.DecodeString(hostData)
		if err != nil {
			return nil, errors.Wrap(ErrDecodeHostData, err)
		}

		config.Config.Policy.HostData = hostDataBynary
	}

	measurement, err := calculateMeasurement(igvmFile, igvmMeasurementBinary)
	if err != nil {
		return nil, errors.Wrap(ErrMeasurement, err)
	}

	config.Config.Policy.Measurement = measurement

	return config, nil
}

func calculateMeasurement(igvmFile string, igvmMeasurementBinary string) ([]byte, error) {
	var stderrBuffer bytes.Buffer
	stderr := bufio.NewWriter(&stderrBuffer)
	options := cmdconfig.IgvmMeasureOptions

	igvmMeasurement, err := cmdconfig.NewCmdConfig(igvmMeasurementBinary, options, stderr)
	if err != nil {
		return []byte{}, err
	}

	outputByte, err := igvmMeasurement.Run(igvmFile)
	if err != nil {
		return []byte{}, err
	}

	outputString := string(outputByte)
	lines := strings.Split(strings.TrimSpace(outputString), "\n")

	if len(lines) == 1 {
		outputString = strings.TrimSpace(outputString)
		outputString = strings.ToLower(outputString)
	} else {
		return []byte{}, fmt.Errorf("error: %s", outputString)
	}

	return hex.DecodeString(outputString)
}
