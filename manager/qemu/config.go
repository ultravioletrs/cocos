package qemu

import "fmt"

type MemoryConfig struct {
	Size  string `env:"MEMORY_SIZE" envDefault:"4096M"`
	Slots int    `env:"MEMORY_SLOTS" envDefault:"5"`
	Max   string `env:"MAX_MEMORY" envDefault:"30G"`
}

type OVMFCodeConfig struct {
	If       string `env:"OVMF_CODE_IF" envDefault:"pflash"`
	Format   string `env:"OVMF_CODE_FORMAT" envDefault:"raw"`
	Unit     int    `env:"OVMF_CODE_UNIT" envDefault:"0"`
	File     string `env:"OVMF_CODE_FILE" envDefault:"/usr/share/OVMF/OVMF_CODE.fd"`
	ReadOnly string `env:"OVMF_CODE_READONLY" envDefault:"on"`
}

type OVMFVarsConfig struct {
	If     string `env:"OVMF_VARS_IF" envDefault:"pflash"`
	Format string `env:"OVMF_VARS_FORMAT" envDefault:"raw"`
	Unit   int    `env:"OVMF_VARS_UNIT" envDefault:"1"`
	File   string `env:"OVMF_VARS_FILE" envDefault:"cmd/manager/img/OVMF_VARS.fd"`
}

type NetDevConfig struct {
	Type      string `env:"NETDEV_TYPE" envDefault:"user"`
	ID        string `env:"NETDEV_ID" envDefault:"vmnic"`
	HostFwd1  string `env:"HOST_FWD_1" envDefault:"2222"`
	GuestFwd1 string `env:"GUEST_FWD_1" envDefault:"22"`
	HostFwd2  string `env:"HOST_FWD_2" envDefault:"9301"`
	GuestFwd2 string `env:"GUEST_FWD_2" envDefault:"9031"`
	HostFwd3  string `env:"HOST_FWD_3" envDefault:"7020"`
	GuestFwd3 string `env:"GUEST_FWD_3" envDefault:"7002"`
}

type VirtioNetPciConfig struct {
	Type          string `env:"VIRTIO_NET_PCI_TYPE" envDefault:"virtio-net-pci"`
	DisableLegacy string `env:"VIRTIO_NET_PCI_DISABLE_LEGACY" envDefault:"on"`
	IOMMUPlatform bool   `env:"VIRTIO_NET_PCI_IOMMU_PLATFORM" envDefault:"true"`
	NetDev        string `env:"VIRTIO_NET_PCI_NETDEV" envDefault:"vmnic"`
	ROMFile       string `env:"VIRTIO_NET_PCI_ROMFILE"`
}

type DiskDriveConfig struct {
	File   string `env:"DISK_DRIVE_FILE" envDefault:"cmd/manager/img/focal-server-cloudimg-amd64.qcow2"`
	If     string `env:"DISK_DRIVE_IF" envDefault:"none"`
	ID     string `env:"DISK_DRIVE_ID" envDefault:"disk0"`
	Format string `env:"DISK_DRIVE_FORMAT" envDefault:"qcow2"`
}

type VirtioScsiPciConfig struct {
	Type          string `env:"VIRTIO_SCSI_PCI_TYPE" envDefault:"virtio-scsi-pci"`
	ID            string `env:"VIRTIO_SCSI_PCI_ID" envDefault:"scsi"`
	DisableLegacy string `env:"VIRTIO_SCSI_PCI_DISABLE_LEGACY" envDefault:"on"`
	IOMMUPlatform bool   `env:"VIRTIO_SCSI_PCI_IOMMU_PLATFORM" envDefault:"true"`
}

type ScsiHdConfig struct {
	Drive string `env:"SCSI_HD_DRIVE" envDefault:"disk0"`
}

type SevConfig struct {
	ID              string `env:"SEV_ID" envDefault:"sev0"`
	CBitPos         int    `env:"SEV_CBITPOS" envDefault:"51"`
	ReducedPhysBits int    `env:"SEV_REDUCED_PHYS_BITS" envDefault:"1"`
}

type MemoryEncryptionConfig struct {
	SEV0 string `env:"MEMORY_ENCRYPTION_SEV0" envDefault:"sev0"`
}

type Config struct {
	Machine  string `env:"MACHINE" envDefault:"q35"`
	CPU      string `env:"CPU" envDefault:"EPYC"`
	SmpCount int    `env:"SMP_COUNT" envDefault:"4"`
	MaxCpus  int    `env:"SMP_MAXCPUS" envDefault:"64"`

	Monitor   string `env:"MONITOR" envDefault:"pty"`
	NoGraphic bool   `env:"NO_GRAPHIC" envDefault:"true"`

	EnableKVM bool `env:"ENABLE_KVM" envDefault:"true"`
	EnableSEV bool `env:"ENABLE_SEV" envDefault:"true"`

	MemoryConfig

	OVMFCodeConfig
	OVMFVarsConfig

	NetDevConfig
	DiskDriveConfig
	VirtioNetPciConfig
	VirtioScsiPciConfig
	ScsiHdConfig
	SevConfig
	MemoryEncryptionConfig
}

func constructQemuCmd(config Config) []string {
	args := []string{}

	if config.EnableKVM {
		args = append(args, "-enable-kvm")
	}

	if config.NoGraphic {
		args = append(args, "-nographic")
	}

	args = append(args, "-monitor", config.Monitor)

	if config.CPU != "" {
		args = append(args, "-cpu", config.CPU)
	}

	if config.Machine != "" {
		args = append(args, "-machine", config.Machine)
	}

	args = append(args, "-smp", fmt.Sprintf("%d,maxcpus=%d", config.SmpCount, config.MaxCpus))

	args = append(args, "-m", fmt.Sprintf("%s,slots=%d,maxmem=%s",
		config.MemoryConfig.Size,
		config.MemoryConfig.Slots,
		config.MemoryConfig.Max))

	args = append(args, "-drive",
		fmt.Sprintf("if=%s,format=%s,unit=%d,file=%s,readonly=%s",
			config.OVMFCodeConfig.If,
			config.OVMFCodeConfig.Format,
			config.OVMFCodeConfig.Unit,
			config.OVMFCodeConfig.File,
			config.OVMFCodeConfig.ReadOnly))

	args = append(args, "-drive",
		fmt.Sprintf("if=%s,format=%s,unit=%d,file=%s",
			config.OVMFVarsConfig.If,
			config.OVMFVarsConfig.Format,
			config.OVMFVarsConfig.Unit,
			config.OVMFVarsConfig.File))

	args = append(args, "-netdev",
		fmt.Sprintf("user,id=%s,hostfwd=tcp::%s-:%s,hostfwd=tcp::%s-:%s,hostfwd=tcp::%s-:%s",
			config.NetDevConfig.ID,
			config.NetDevConfig.HostFwd1, config.NetDevConfig.GuestFwd1,
			config.NetDevConfig.HostFwd2, config.NetDevConfig.GuestFwd2,
			config.NetDevConfig.HostFwd3, config.NetDevConfig.GuestFwd3))

	args = append(args, "-device",
		fmt.Sprintf("%s,disable-legacy=%s,iommu_platform=%v,netdev=%s,romfile=%s",
			config.VirtioNetPciConfig.Type,
			config.VirtioNetPciConfig.DisableLegacy,
			config.VirtioNetPciConfig.IOMMUPlatform,
			config.VirtioNetPciConfig.NetDev,
			config.VirtioNetPciConfig.ROMFile))

	args = append(args, "-drive",
		fmt.Sprintf("file=%s,if=%s,id=%s,format=%s",
			config.DiskDriveConfig.File,
			config.DiskDriveConfig.If,
			config.DiskDriveConfig.ID,
			config.DiskDriveConfig.Format))

	args = append(args, "-device",
		fmt.Sprintf("%s,id=%s,disable-legacy=%s,iommu_platform=%t",
			config.VirtioScsiPciConfig.Type,
			config.VirtioScsiPciConfig.ID,
			config.VirtioScsiPciConfig.DisableLegacy,
			config.VirtioScsiPciConfig.IOMMUPlatform))

	args = append(args, "-device",
		fmt.Sprintf("scsi-hd,drive=%s", config.ScsiHdConfig.Drive))

	if config.EnableSEV {
		args = append(args, "-object",
			fmt.Sprintf("sev-guest,id=%s,cbitpos=%d,reduced-phys-bits=%d",
				config.SevConfig.ID,
				config.SevConfig.CBitPos,
				config.SevConfig.ReducedPhysBits))

		args = append(args, "-machine",
			fmt.Sprintf("memory-encryption=%s", config.MemoryEncryptionConfig.SEV0))
	}

	return args

}
