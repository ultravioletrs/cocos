package manager

import (
	"regexp"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

var re = regexp.MustCompile(`'([^']*)'`)

func entityName(msg string) (string, error) {
	match := re.FindStringSubmatch(msg)
	if len(match) < 1 {
		return "", ErrNotFound
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
			time.Sleep(bootTime)

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
