package qemu

import "fmt"

type MemoryConfig struct {
	Size  string `json:"memory_size,omitempty" env:"MEMORY_SIZE" envDefault:"4096M"`
	Slots int    `json:"memory_slots,omitempty" env:"MEMORY_SLOTS" envDefault:"5"`
	Max   string `json:"max_memory,omitempty" env:"MAX_MEMORY" envDefault:"30G"`
}

type OVMFCodeConfig struct {
	If       string `json:"ovmf_code_if,omitempty" env:"OVMF_CODE_IF" envDefault:"pflash"`
	Format   string `json:"ovmf_code_format,omitempty" env:"OVMF_CODE_FORMAT" envDefault:"raw"`
	Unit     int    `json:"ovmf_code_unit,omitempty" env:"OVMF_CODE_UNIT" envDefault:"0"`
	File     string `json:"ovmf_code_file,omitempty" env:"OVMF_CODE_FILE" envDefault:"/usr/share/OVMF/OVMF_CODE.fd"`
	ReadOnly string `json:"ovmf_code_readonly,omitempty" env:"OVMF_CODE_READONLY" envDefault:"on"`
}

type OVMFVarsConfig struct {
	If     string `json:"ovmf_vars_if,omitempty" env:"OVMF_VARS_IF" envDefault:"pflash"`
	Format string `json:"ovmf_vars_format,omitempty" env:"OVMF_VARS_FORMAT" envDefault:"raw"`
	Unit   int    `json:"ovmf_vars_unit,omitempty" env:"OVMF_VARS_UNIT" envDefault:"1"`
	File   string `json:"ovmf_vars_file,omitempty" env:"OVMF_VARS_FILE" envDefault:"img/OVMF_VARS.fd"`
}

type NetDevConfig struct {
	ID        string `json:"netdev_id,omitempty" env:"NETDEV_ID" envDefault:"vmnic"`
	HostFwd1  string `json:"host_fwd_1,omitempty" env:"HOST_FWD_1" envDefault:"2222"`
	GuestFwd1 string `json:"guest_fwd_1,omitempty" env:"GUEST_FWD_1" envDefault:"22"`
	HostFwd2  string `json:"host_fwd_2,omitempty" env:"HOST_FWD_2" envDefault:"9301"`
	GuestFwd2 string `json:"guest_fwd_2,omitempty" env:"GUEST_FWD_2" envDefault:"9031"`
	HostFwd3  string `json:"host_fwd_3,omitempty" env:"HOST_FWD_3" envDefault:"7020"`
	GuestFwd3 string `json:"guest_fwd_3,omitempty" env:"GUEST_FWD_3" envDefault:"7002"`
}

type VirtioNetPciConfig struct {
	DisableLegacy string `json:"virtio_net_pci_disable_legacy,omitempty" env:"VIRTIO_NET_PCI_DISABLE_LEGACY" envDefault:"on"`
	IOMMUPlatform bool   `json:"virtio_net_pci_iommu_platform,omitempty" env:"VIRTIO_NET_PCI_IOMMU_PLATFORM" envDefault:"true"`
	ROMFile       string `json:"virtio_net_pci_romfile,omitempty" env:"VIRTIO_NET_PCI_ROMFILE"`
}

type DiskImgConfig struct {
	File   string `json:"disk_img_file,omitempty" env:"DISK_IMG_FILE" envDefault:"img/focal-server-cloudimg-amd64.img"`
	If     string `json:"disk_img_if,omitempty" env:"DISK_IMG_IF" envDefault:"none"`
	ID     string `json:"disk_img_id,omitempty" env:"DISK_IMG_ID" envDefault:"disk0"`
	Format string `json:"disk_img_format,omitempty" env:"DISK_IMG_FORMAT" envDefault:"qcow2"`
}

type VirtioScsiPciConfig struct {
	ID            string `json:"virtio_scsi_pci_id,omitempty" env:"VIRTIO_SCSI_PCI_ID" envDefault:"scsi"`
	DisableLegacy string `json:"virtio_scsi_pci_disable_legacy,omitempty" env:"VIRTIO_SCSI_PCI_DISABLE_LEGACY" envDefault:"on"`
	IOMMUPlatform bool   `json:"virtio_scsi_pci_iommu_platform,omitempty" env:"VIRTIO_SCSI_PCI_IOMMU_PLATFORM" envDefault:"true"`
}

type SevConfig struct {
	ID              string `json:"sev_id,omitempty" env:"SEV_ID" envDefault:"sev0"`
	CBitPos         int    `json:"sev_cbitpos,omitempty" env:"SEV_CBITPOS" envDefault:"51"`
	ReducedPhysBits int    `json:"sev_reduced_phys_bits,omitempty" env:"SEV_REDUCED_PHYS_BITS" envDefault:"1"`
}

type MemoryEncryptionConfig struct {
	SEV0 string `json:"memory_encryption_sev0,omitempty" env:"MEMORY_ENCRYPTION_SEV0" envDefault:"sev0"`
}

type Config struct {
	UseSudo   bool `json:"use_sudo,omitempty" env:"USE_SUDO" envDevault:"false"`
	EnableSEV bool `json:"enable_sev,omitempty" env:"ENABLE_SEV" envDefault:"true"`

	EnableKVM bool `json:"enable_kvm,omitempty" env:"ENABLE_KVM" envDefault:"true"`

	// machine, CPU, RAM
	Machine  string `json:"machine,omitempty" env:"MACHINE" envDefault:"q35"`
	CPU      string `json:"cpu,omitempty" env:"CPU" envDefault:"EPYC"`
	SmpCount int    `json:"smp_count,omitempty" env:"SMP_COUNT" envDefault:"4"`
	MaxCpus  int    `json:"smp_maxcpus,omitempty" env:"SMP_MAXCPUS" envDefault:"64"`
	MemoryConfig

	// OVMF
	OVMFCodeConfig
	OVMFVarsConfig

	// network
	NetDevConfig
	VirtioNetPciConfig

	// disk
	VirtioScsiPciConfig
	DiskImgConfig

	// SEV
	SevConfig
	MemoryEncryptionConfig

	// display
	NoGraphic bool   `json:"no_graphic,omitempty" env:"NO_GRAPHIC" envDefault:"true"`
	Monitor   string `json:"monitor,omitempty" env:"MONITOR" envDefault:"pty"`
}

func constructQemuArgs(config Config) []string {
	args := []string{}

	// virtualization
	if config.EnableKVM {
		args = append(args, "-enable-kvm")
	}

	// machine, CPU, RAM
	if config.Machine != "" {
		args = append(args, "-machine", config.Machine)
	}

	if config.CPU != "" {
		args = append(args, "-cpu", config.CPU)
	}

	args = append(args, "-smp", fmt.Sprintf("%d,maxcpus=%d", config.SmpCount, config.MaxCpus))

	args = append(args, "-m", fmt.Sprintf("%s,slots=%d,maxmem=%s",
		config.MemoryConfig.Size,
		config.MemoryConfig.Slots,
		config.MemoryConfig.Max))

	// OVMF
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

	// disk
	args = append(args, "-device",
		fmt.Sprintf("virtio-scsi-pci,id=%s,disable-legacy=%s,iommu_platform=%t",
			config.VirtioScsiPciConfig.ID,
			config.VirtioScsiPciConfig.DisableLegacy,
			config.VirtioScsiPciConfig.IOMMUPlatform))

	args = append(args, "-drive",
		fmt.Sprintf("file=%s,if=%s,id=%s,format=%s",
			config.DiskImgConfig.File,
			config.DiskImgConfig.If,
			config.DiskImgConfig.ID,
			config.DiskImgConfig.Format))

	args = append(args, "-device",
		fmt.Sprintf("scsi-hd,drive=%s", config.DiskImgConfig.ID))

	// network
	args = append(args, "-netdev",
		fmt.Sprintf("user,id=%s,hostfwd=tcp::%s-:%s,hostfwd=tcp::%s-:%s,hostfwd=tcp::%s-:%s",
			config.NetDevConfig.ID,
			config.NetDevConfig.HostFwd1, config.NetDevConfig.GuestFwd1,
			config.NetDevConfig.HostFwd2, config.NetDevConfig.GuestFwd2,
			config.NetDevConfig.HostFwd3, config.NetDevConfig.GuestFwd3))

	args = append(args, "-device",
		fmt.Sprintf("virtio-net-pci,disable-legacy=%s,iommu_platform=%v,netdev=%s,romfile=%s",
			config.VirtioNetPciConfig.DisableLegacy,
			config.VirtioNetPciConfig.IOMMUPlatform,
			config.NetDevConfig.ID,
			config.VirtioNetPciConfig.ROMFile))

	// SEV
	if config.EnableSEV {
		args = append(args, "-object",
			fmt.Sprintf("sev-guest,id=%s,cbitpos=%d,reduced-phys-bits=%d",
				config.SevConfig.ID,
				config.SevConfig.CBitPos,
				config.SevConfig.ReducedPhysBits))

		args = append(args, "-machine",
			fmt.Sprintf("memory-encryption=%s", config.MemoryEncryptionConfig.SEV0))
	}

	// display
	if config.NoGraphic {
		args = append(args, "-nographic")
	}

	args = append(args, "-monitor", config.Monitor)

	return args

}
