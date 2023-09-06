package libvirt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	libvirt "github.com/digitalocean/go-libvirt"
)

var re = regexp.MustCompile(`'([^']*)'`)

func entityName(msg string) (string, error) {
	match := re.FindStringSubmatch(msg)
	if len(match) < 1 {
		return "", errors.New("entity not found")
	}

	return match[1], nil
}

func createDomain(libvirtConn *libvirt.Libvirt, poolXML string, volXML string, domXML string) (libvirt.Domain, error) {
	pool, err := libvirtConn.StoragePoolCreateXML(poolXML, 0)
	_ = pool
	if err != nil {
		lvErr := err.(libvirt.Error)
		if lvErr.Code == 9 {
			name, err := entityName(lvErr.Message)
			if err != nil {
				return libvirt.Domain{}, err
			}
			pool, err = libvirtConn.StoragePoolLookupByName(name)
			if err != nil {
				return libvirt.Domain{}, err
			}

			goto pool_exists
		}

		return libvirt.Domain{}, err
	}
pool_exists:

	_, err = libvirtConn.StorageVolCreateXML(pool, volXML, 0)
	if err != nil {
		lvErr := err.(libvirt.Error)
		if lvErr.Code == 90 {
			name, err := entityName(lvErr.Message)
			if err != nil {
				return libvirt.Domain{}, err
			}
			_, err = libvirtConn.StorageVolLookupByName(pool, name)
			if err != nil {
				return libvirt.Domain{}, err
			}

			goto vol_exists
		}

		return libvirt.Domain{}, err
	}

vol_exists:

	dom, err := libvirtConn.DomainDefineXMLFlags(domXML, 0)
	if err != nil {
		return libvirt.Domain{}, err
	}

	err = libvirtConn.DomainCreate(dom)
	if err != nil {
		lvErr := err.(libvirt.Error)
		if lvErr.Code == 55 {

			return dom, nil
		}

		return libvirt.Domain{}, err
	}

	// extra flags; not used yet, so callers should always pass 0
	current, err := libvirtConn.DomainSnapshotCurrent(dom, 0)
	if err != nil {
		lvErr := err.(libvirt.Error)
		if lvErr.Code == 72 {

			return dom, nil
		}

		return libvirt.Domain{}, err
	}

	err = libvirtConn.DomainRevertToSnapshot(current, uint32(libvirt.DomainSnapshotRevertRunning))
	if err != nil {
		return libvirt.Domain{}, err
	}

	return dom, nil
}

func CreateDomain(ctx context.Context, libvirt *libvirt.Libvirt, poolXML, volXML, domXML string) (string, error) {
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

func readXMLFile(filename string, defaultFilename string) (string, error) {
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
