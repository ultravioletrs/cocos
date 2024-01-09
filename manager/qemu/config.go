// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"fmt"
)

type MemoryConfig struct {
	Size  string `env:"MEMORY_SIZE" envDefault:"2048M"`
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
	File   string `env:"OVMF_VARS_FILE" envDefault:"/usr/share/OVMF/OVMF_VARS.fd"`
}

type NetDevConfig struct {
	ID        string `env:"NETDEV_ID" envDefault:"vmnic"`
	HostFwd1  int    `env:"HOST_FWD_1" envDefault:"2222"`
	GuestFwd1 int    `env:"GUEST_FWD_1" envDefault:"22"`
	HostFwd2  int    `env:"HOST_FWD_2" envDefault:"9301"`
	GuestFwd2 int    `env:"GUEST_FWD_2" envDefault:"9031"`
	HostFwd3  int    `env:"HOST_FWD_3" envDefault:"7020"`
	GuestFwd3 int    `env:"GUEST_FWD_3" envDefault:"7002"`
}

type VirtioNetPciConfig struct {
	DisableLegacy string `env:"VIRTIO_NET_PCI_DISABLE_LEGACY" envDefault:"on"`
	IOMMUPlatform bool   `env:"VIRTIO_NET_PCI_IOMMU_PLATFORM" envDefault:"true"`
	ROMFile       string `env:"VIRTIO_NET_PCI_ROMFILE"`
}

type DiskImgConfig struct {
	KernelFile string `env:"DISK_IMG_KERNEL_FILE" envDefault:"img/bzImage"`
	RootFsFile string `env:"DISK_IMG_ROOTFS_FILE" envDefault:"img/rootfs.cpio.gz"`
}

type VirtioScsiPciConfig struct {
	ID            string `env:"VIRTIO_SCSI_PCI_ID" envDefault:"scsi"`
	DisableLegacy string `env:"VIRTIO_SCSI_PCI_DISABLE_LEGACY" envDefault:"on"`
	IOMMUPlatform bool   `env:"VIRTIO_SCSI_PCI_IOMMU_PLATFORM" envDefault:"true"`
}

type SevConfig struct {
	ID              string `env:"SEV_ID" envDefault:"sev0"`
	CBitPos         int    `env:"SEV_CBITPOS" envDefault:"51"`
	ReducedPhysBits int    `env:"SEV_REDUCED_PHYS_BITS" envDefault:"1"`
}

type Config struct {
	TmpFileLoc string `env:"TMP_FILE_LOC" envDefault:"tmp"`
	UseSudo    bool   `env:"USE_SUDO" envDefault:"false"`
	EnableSEV  bool   `env:"ENABLE_SEV" envDefault:"true"`

	EnableKVM bool `env:"ENABLE_KVM" envDefault:"true"`

	// machine, CPU, RAM
	Machine  string `env:"MACHINE" envDefault:"q35"`
	CPU      string `env:"CPU" envDefault:"EPYC"`
	SmpCount int    `env:"SMP_COUNT" envDefault:"4"`
	MaxCpus  int    `env:"SMP_MAXCPUS" envDefault:"64"`
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

	// display
	NoGraphic bool   `env:"NO_GRAPHIC" envDefault:"true"`
	Monitor   string `env:"MONITOR" envDefault:"pty"`
}

func constructQemuArgs(config Config, computation string) []string {
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

	args = append(args, "-kernel", config.DiskImgConfig.KernelFile)

	args = append(args, "-append", fmt.Sprintf("earlyprintk=serial console=ttyS0 computation=%s", computation))

	args = append(args, "-initrd", config.DiskImgConfig.RootFsFile)

	// network
	args = append(args, "-netdev",
		fmt.Sprintf("user,id=%s,hostfwd=tcp::%d-:%d,hostfwd=tcp::%d-:%d,hostfwd=tcp::%d-:%d",
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
			fmt.Sprintf("memory-encryption=%s", config.SevConfig.ID))
	}

	// display
	if config.NoGraphic {
		args = append(args, "-nographic")
	}

	args = append(args, "-monitor", config.Monitor)

	return args
}
