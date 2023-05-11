// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"errors"
	"os"

	"github.com/digitalocean/go-libvirt"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/mainflux/mainflux"
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
	Run(comp Computation) (string, error)
}

type managerService struct {
	secret     string
	libvirt    *libvirt.Libvirt
	idProvider mainflux.IDProvider
}

var _ Service = (*managerService)(nil)

// New instantiates the manager service implementation.
func New(secret string, libvirtConn *libvirt.Libvirt, idp mainflux.IDProvider) Service {
	return &managerService{
		secret:     secret,
		libvirt:    libvirtConn,
		idProvider: idp,
	}
}

func (ms *managerService) CreateDomain(poolXML, volXML, domXML string) (string, error) {
	poolStr, err := readXMLFile(poolXML, "pool.xml")
	if err != nil {
		return "", err
	}

	volStr, err := readXMLFile(volXML, "vol.xml")
	if err != nil {
		return "", err
	}

	domStr, err := readXMLFile(domXML, "dom.xml")
	if err != nil {
		return "", err
	}

	dom, err := createDomain(ms.libvirt, poolStr, volStr, domStr)
	if err != nil {
		return "", ErrMalformedEntity
	}

	return dom.Name, nil
}

func (ms *managerService) Run(comp Computation) (string, error) {
	// Generate a unique ID for the computation
	runID, err := ms.idProvider.ID()
	if err != nil {
		return "", err
	}

	// Initialize the Computation object
	comp.ID = runID
	comp.Status = ""
	comp.StartTime = &timestamp.Timestamp{}
	comp.EndTime = &timestamp.Timestamp{}

	// // Save the Computation object to the database
	// if err := ms.db.SaveComputation(comp); err != nil {
	// 	return "", err
	// }

	// // Start the computation process
	// go ms.processComputation(comp)

	return runID, nil
}

func readXMLFile(filename string, defaultFilename string) (string, error) {
	if filename == "" {
		filename = defaultFilename
	}

	xmlBytes, err := os.ReadFile("./xml/" + filename)
	if err != nil {
		return "", ErrNotFound
	}

	return string(xmlBytes), nil
}
