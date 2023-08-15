// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"

	"github.com/digitalocean/go-libvirt"
	"github.com/ultravioletrs/agent/agent"
	"github.com/ultravioletrs/manager/manager/qemu"
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
)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	CreateLibvirtDomain(ctx context.Context, pool, volume, domain string) (string, error)
	CreateQemuVM(ctx context.Context) (*exec.Cmd, error)
	Run(ctx context.Context, computation []byte) (string, error)
}

type qemuCmd struct {
	exe  string   // The path to the QEMU executable
	args []string // List of arguments for the QEMU command
}

type managerService struct {
	libvirt *libvirt.Libvirt
	agent   agent.AgentServiceClient
	qemuCmd qemuCmd
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(libvirtConn *libvirt.Libvirt, agent agent.AgentServiceClient, exe string, args []string) Service {
	return &managerService{
		libvirt: libvirtConn,
		agent:   agent,
		qemuCmd: qemuCmd{exe: exe, args: args},
	}
}

func (ms *managerService) CreateLibvirtDomain(ctx context.Context, poolXML, volXML, domXML string) (string, error) {
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

func (ms *managerService) CreateQemuVM(ctx context.Context) (*exec.Cmd, error) {
	cmd, err := qemu.RunQemuVM(ms.qemuCmd.exe, ms.qemuCmd.args)
	if err != nil {
		return cmd, err
	}
	return cmd, nil
}

func (ms *managerService) Run(ctx context.Context, computation []byte) (string, error) {
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
