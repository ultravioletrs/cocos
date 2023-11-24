// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package libvirt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

var re = regexp.MustCompile(`'([^']*)'`)

func CreateDomain(ctx context.Context, libvirt *golibvirt.Libvirt, poolXML, volXML, domXML string) (string, error) {
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

	dom, err := createDomain(libvirt, poolStr, volStr, domStr)
	if err != nil {
		return "", fmt.Errorf("failed to create domain: %s", err)
	}

	return dom.Name, nil
}

func createDomain(libvirtConn *golibvirt.Libvirt, poolXML, volXML, domXML string) (golibvirt.Domain, error) {
	pool, err := libvirtConn.StoragePoolCreateXML(poolXML, 0)
	_ = pool
	if err != nil {
		lvErr := err.(golibvirt.Error)
		if lvErr.Code == 9 {
			name, err := entityName(lvErr.Message)
			if err != nil {
				return golibvirt.Domain{}, err
			}
			pool, err = libvirtConn.StoragePoolLookupByName(name)
			if err != nil {
				return golibvirt.Domain{}, err
			}

			goto pool_exists
		}

		return golibvirt.Domain{}, err
	}
pool_exists:

	_, err = libvirtConn.StorageVolCreateXML(pool, volXML, 0)
	if err != nil {
		lvErr := err.(golibvirt.Error)
		if lvErr.Code == 90 {
			name, err := entityName(lvErr.Message)
			if err != nil {
				return golibvirt.Domain{}, err
			}
			_, err = libvirtConn.StorageVolLookupByName(pool, name)
			if err != nil {
				return golibvirt.Domain{}, err
			}

			goto vol_exists
		}

		return golibvirt.Domain{}, err
	}

vol_exists:

	dom, err := libvirtConn.DomainDefineXMLFlags(domXML, 0)
	if err != nil {
		return golibvirt.Domain{}, err
	}

	err = libvirtConn.DomainCreate(dom)
	if err != nil {
		lvErr := err.(golibvirt.Error)
		if lvErr.Code == 55 {
			return dom, nil
		}

		return golibvirt.Domain{}, err
	}

	// extra flags; not used yet, so callers should always pass 0
	current, err := libvirtConn.DomainSnapshotCurrent(dom, 0)
	if err != nil {
		lvErr := err.(golibvirt.Error)
		if lvErr.Code == 72 {
			return dom, nil
		}

		return golibvirt.Domain{}, err
	}

	err = libvirtConn.DomainRevertToSnapshot(current, uint32(golibvirt.DomainSnapshotRevertRunning))
	if err != nil {
		return golibvirt.Domain{}, err
	}

	return dom, nil
}

func entityName(msg string) (string, error) {
	match := re.FindStringSubmatch(msg)
	if len(match) < 1 {
		return "", errors.New("entity not found")
	}

	return match[1], nil
}

func readXMLFile(filename, defaultFilename string) (string, error) {
	if filename == "" {
		filename = "./xml/" + defaultFilename
	}

	xmlBytes, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("failed to read XML file: %s", err)
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
