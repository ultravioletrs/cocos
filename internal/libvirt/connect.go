// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package libvirt

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/absmach/magistrala/logger"
	"github.com/digitalocean/go-libvirt"
)

func Connect(logger logger.Logger) *libvirt.Libvirt {
	// This dials libvirt on the local machine, but you can substitute the first
	// two parameters with "tcp", "<ip address>:<port>" to connect to libvirt on
	// a remote machine.
	c, err := net.DialTimeout("unix", "/var/run/libvirt/libvirt-sock", 2*time.Second)
	if err != nil {
		log.Fatalf("failed to dial libvirt: %v", err)
	}

	l := libvirt.New(c)
	if err := l.Connect(); err != nil {
		log.Fatalf("failed to connect: %v", err)
	}

	v, err := l.Version()
	if err != nil {
		logger.Error(fmt.Sprintf("failed to retrieve libvirt version: %v", err))
	}
	logger.Info(fmt.Sprintf("Retrieved libvirt version: %s", v))

	domains, err := l.Domains()
	if err != nil {
		logger.Error(fmt.Sprintf("failed to retrieve domains: %v", err))
	}

	for _, d := range domains {
		logger.Info(fmt.Sprintf("%d\t%s\t%x\n", d.ID, d.Name, d.UUID))
	}

	return l
}
