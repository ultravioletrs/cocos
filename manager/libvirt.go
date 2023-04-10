package manager

import "github.com/digitalocean/go-libvirt"

func createDomain(libvirtConn *libvirt.Libvirt, poolXML string, volXML string, domXML string) (libvirt.Domain, error) {
	pool, err := libvirtConn.StoragePoolCreateXML(poolXML, 0)
	if err != nil {
		return libvirt.Domain{}, err
	}

	_, err = libvirtConn.StorageVolCreateXML(pool, volXML, 0)
	if err != nil {
		return libvirt.Domain{}, err
	}

	dom, err := libvirtConn.DomainDefineXMLFlags(domXML, 0)
	if err != nil {
		return libvirt.Domain{}, err
	}

	err = libvirtConn.DomainCreate(dom)
	if err != nil {
		return libvirt.Domain{}, err
	}

	return dom, nil
}
