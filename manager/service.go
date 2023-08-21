// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/digitalocean/go-libvirt"
	"github.com/ultravioletrs/agent/agent"
	"github.com/ultravioletrs/manager/internal"
	"github.com/ultravioletrs/manager/manager/qemu"

	"github.com/gofrs/uuid"
)

const firmwareVars = "OVMF_VARS"
const qcow2Img = "focal-server-cloudimg-amd64"

const bootTime = 15 * time.Second

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")

	// ErrNotFound indicates a non-existent entity request.
	ErrNotFound = errors.New("entity not found")
)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	Run(ctx context.Context, computation []byte) (string, error)
}

type managerService struct {
	libvirt *libvirt.Libvirt
	agent   agent.AgentServiceClient
	qemuCfg qemu.Config
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(libvirtConn *libvirt.Libvirt, agent agent.AgentServiceClient, qemuCfg qemu.Config) Service {
	return &managerService{
		libvirt: libvirtConn,
		agent:   agent,
		qemuCfg: qemuCfg,
	}
}

func (ms *managerService) createLibvirtDomain(ctx context.Context, poolXML, volXML, domXML string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	poolStr, err := readXMLFile(poolXML, "pool.xml")
	if err != nil {
		return "", err
	}
	poolStr = replaceSubstring(poolStr, "./", wd+"/")

	volStr, err := readXMLFile(volXML, "vol.xml")
	if err != nil {
		return "", err
	}
	volStr = replaceSubstring(volStr, "./", wd+"/")

	domStr, err := readXMLFile(domXML, "dom.xml")
	if err != nil {
		return "", err
	}
	domStr = replaceSubstring(domStr, "./", wd+"/")

	dom, err := createDomain(ms.libvirt, poolStr, volStr, domStr)
	if err != nil {
		return "", ErrMalformedEntity
	}

	return dom.Name, nil
}

func (ms *managerService) createQemuVM(ctx context.Context) (*exec.Cmd, error) {
	// create unique emu device identifiers
	id, err := uuid.NewV4()
	if err != nil {
		return &exec.Cmd{}, err
	}
	qemuCfg := ms.qemuCfg
	qemuCfg.NetDevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.NetDevConfig.ID, id)
	qemuCfg.DiskImgConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.DiskImgConfig.ID, id)
	qemuCfg.VirtioScsiPciConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.VirtioScsiPciConfig.ID, id)
	qemuCfg.SevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.SevConfig.ID, id)

	// copy firmware vars file
	srcFile := qemuCfg.OVMFVarsConfig.File
	dstFile := fmt.Sprintf("%s/%s-%s.fd", ms.qemuCfg.TmpFileLoc, firmwareVars, id)
	err = internal.CopyFile(srcFile, dstFile)
	if err != nil {
		return &exec.Cmd{}, err
	}
	qemuCfg.OVMFVarsConfig.File = dstFile

	// copy qcow2 img file
	srcFile = qemuCfg.DiskImgConfig.File
	dstFile = fmt.Sprintf("%s/%s-%s.img", ms.qemuCfg.TmpFileLoc, qcow2Img, id)
	err = internal.CopyFile(srcFile, dstFile)
	if err != nil {
		return &exec.Cmd{}, err
	}
	qemuCfg.DiskImgConfig.File = dstFile

	exe, args, err := qemu.ExecutableAndArgs(qemuCfg)
	if err != nil {
		return &exec.Cmd{}, err
	}
	cmd, err := qemu.RunQemuVM(exe, args)
	if err != nil {
		return cmd, err
	}

	// different VM guests can't forward ports to the same ports on the same host
	ms.qemuCfg.NetDevConfig.HostFwd1++
	ms.qemuCfg.NetDevConfig.HostFwd2++
	ms.qemuCfg.NetDevConfig.HostFwd3++

	return cmd, nil
}

func (ms *managerService) Run(ctx context.Context, computation []byte) (string, error) {
	_, err := ms.createQemuVM(ctx)
	if err != nil {
		return "", err
	}
	time.Sleep(bootTime)

	res, err := ms.agent.Run(ctx, &agent.RunRequest{Computation: computation})
	if err != nil {
		return "", err
	}

	return res.Computation, nil
}

func readXMLFile(filename string, defaultFilename string) (string, error) {
	if filename == "" {
		filename = "./xml/" + defaultFilename
	}

	xmlBytes, err := os.ReadFile(filename)
	if err != nil {
		return "", ErrNotFound
	}

	return string(xmlBytes), nil
}

func replaceSubstring(xml, substring, replacement string) string {
	// Split the file text into lines
	lines := strings.Split(xml, "\n")

	// Create a variable to hold the resulting string
	var result strings.Builder

	// Iterate over each line
	for _, line := range lines {
		// Replace the substring with the replacement
		newLine := strings.ReplaceAll(line, substring, replacement)

		// Append the modified line to the resulting string
		result.WriteString(newLine)
		result.WriteString("\n")
	}

	return result.String()
}
