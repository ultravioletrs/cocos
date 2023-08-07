package manager

import (
	"regexp"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
)

type Config struct {
	HDAFile          string `env:"HDA_FILE" envDefault:"cmd/manager/img/focal-server-cloudimg-amd64.qcow2"`
	GuestSizeInMB    int    `env:"GUEST_SIZE_IN_MB" envDefault:"4096"`
	SevGuest         int    `env:"SEV_GUEST" envDefault:"1"`
	SmpNCPUs         int    `env:"SMP_NCPUS" envDefault:"4"`
	Console          string `env:"CONSOLE" envDefault:"serial"`
	VNCPort          string `env:"VNC_PORT"`
	UseVirtio        int    `env:"USE_VIRTIO" envDefault:"1"`
	UEFIBiosCode     string `env:"UEFI_BIOS_CODE" envDefault:"/usr/share/OVMF/OVMF_CODE.fd"`
	UEFIBiosVarsOrig string `env:"UEFI_BIOS_VARS_ORIG" envDefault:"/usr/share/OVMF/OVMF_VARS.fd"`
	UEFIBiosVarsCopy string `env:"UEFI_BIOS_VARS_COPY" envDefault:"cmd/manager/img/OVMF_VARS.fd"`
	CBitPos          int    `env:"CBITPOS" envDefault:"51"`
	HostHTTPPort     int    `env:"HOST_HTTP_PORT" envDefault:"9301"`
	GuestHTTPPort    int    `env:"GUEST_HTTP_PORT" envDefault:"9031"`
	HostGRPCPort     int    `env:"HOST_GRPC_PORT" envDefault:"7020"`
	GuestGRPCPort    int    `env:"GUEST_GRPC_PORT" envDefault:"7002"`
	EnableFileLog    int    `env:"ENABLE_FILE_LOG" envDefault:"0"`
	ExecQemuCmdLine  int    `env:"EXEC_QEMU_CMDLINE" envDefault:"1"`
}

var re = regexp.MustCompile(`'([^']*)'`)

const bootTime = 5 * time.Second

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
