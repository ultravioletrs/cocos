// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package manager

import (
	"fmt"
	"os"
	"os/exec"
)

func (ms *managerService) FetchBackendInfo() ([]byte, error) {
	cmd := exec.Command("sudo", fmt.Sprintf("%s/backend_info", ms.backendMeasurementBinaryPath), "--policy", "1966081")

	_, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	f, err := os.ReadFile("./backend_info.json")
	if err != nil {
		return nil, err
	}

	return f, nil
}
