// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"errors"
	"os"

	"github.com/digitalocean/go-libvirt"
)

const (
	poolXML = "xml/pool.xml"
	volXML  = "xml/vol.xml"
	domXML  = "xml/dom.xml"
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

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	CreateDomain(pool, volume, domain string) (string, error)
}

type managerService struct {
	secret  string
	libvirt *libvirt.Libvirt
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(secret string, libvirtConn *libvirt.Libvirt) Service {
	return &managerService{
		secret:  secret,
		libvirt: libvirtConn,
	}
}

func (ks *managerService) CreateDomain(poolXML, volXML, domXML string) (string, error) {
	poolBytes, err := os.ReadFile(poolXML)
	if err != nil {
		return "", ErrNotFound
	}
	poolStr := string(poolBytes)

	volBytes, err := os.ReadFile(volXML)
	if err != nil {
		return "", ErrNotFound
	}
	volStr := string(volBytes)

	domBytes, err := os.ReadFile(domXML)
	if err != nil {
		return "", ErrNotFound
	}
	domStr := string(domBytes)

	dom, err := createDomain(ks.libvirt, poolStr, volStr, domStr)
	if err != nil {
		return "", ErrMalformedEntity
	}

	return dom.Name, nil
}
