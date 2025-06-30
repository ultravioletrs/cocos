// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"fmt"
	"strconv"

	"github.com/caarlos0/env/v10"
)

const (
	BaseGuestCID      = 3
	KernelCommandLine = "quiet console=null"
	TDXObject         = "{\"qom-type\":\"tdx-guest\",\"id\":\"%s\",\"quote-generation-socket\":{\"type\": \"vsock\", \"cid\":\"2\",\"port\":\"%d\"}}"
)

type MemoryConfig struct {
	Size  string `env:"MEMORY_SIZE"  envDefault:"2048M"`
	Slots int    `env:"MEMORY_SLOTS" envDefault:"5"`
	Max   string `env:"MAX_MEMORY"   envDefault:"30G"`
}

type OVMFCodeConfig struct {
	If       string `env:"OVMF_CODE_IF"       envDefault:"pflash"`
	Format   string `env:"OVMF_CODE_FORMAT"   envDefault:"raw"`
	Unit     int    `env:"OVMF_CODE_UNIT"     envDefault:"0"`
	File     string `env:"OVMF_CODE_FILE"     envDefault:"/usr/share/OVMF/OVMF_CODE.fd"`
	ReadOnly string `env:"OVMF_CODE_READONLY" envDefault:"on"`
	Version  string `env:"OVMF_VERSION"       envDefault:""`
}

type OVMFVarsConfig struct {
	If     string `env:"OVMF_VARS_IF"     envDefault:"pflash"`
	Format string `env:"OVMF_VARS_FORMAT" envDefault:"raw"`
	Unit   int    `env:"OVMF_VARS_UNIT"   envDefault:"1"`
	File   string `env:"OVMF_VARS_FILE"   envDefault:"/usr/share/OVMF/OVMF_VARS.fd"`
}

type NetDevConfig struct {
	ID            string `env:"NETDEV_ID"       envDefault:"vmnic"`
	HostFwdAgent  int    `env:"HOST_FWD_AGENT"  envDefault:"7020"`
	GuestFwdAgent int    `env:"GUEST_FWD_AGENT" envDefault:"7002"`
}

type VirtioNetPciConfig struct {
	DisableLegacy string `env:"VIRTIO_NET_PCI_DISABLE_LEGACY" envDefault:"on"`
	IOMMUPlatform bool   `env:"VIRTIO_NET_PCI_IOMMU_PLATFORM" envDefault:"true"`
	Addr          string `env:"VIRTIO_NET_PCI_ADDR"           envDefault:"0x2"`
	ROMFile       string `env:"VIRTIO_NET_PCI_ROMFILE"`
}

type DiskImgConfig struct {
	KernelFile string `env:"DISK_IMG_KERNEL_FILE" envDefault:"img/bzImage"`
	RootFsFile string `env:"DISK_IMG_ROOTFS_FILE" envDefault:"img/rootfs.cpio.gz"`
}

type SEVSNPConfig struct {
	ID              string `env:"SEV_ID"                envDefault:"sev0"`
	CBitPos         int    `env:"SEV_CBITPOS"           envDefault:"51"`
	ReducedPhysBits int    `env:"SEV_REDUCED_PHYS_BITS" envDefault:"1"`
	EnableHostData  bool   `env:"ENABLE_HOST_DATA"      envDefault:"false"`
	HostData        string `env:"HOST_DATA"             envDefault:""`
}

type TDXConfig struct {
	ID                  string `env:"TDX_ID"                  envDefault:"tdx0"`
	QuoteGenerationPort int    `env:"QUOTE_GENERATION_PORT"   envDefault:"4050"`
	OVMF                string `env:"OVMF_FILE"               envDefault:"/usr/share/ovmf/OVMF.fd"`
}

type IGVMConfig struct {
	ID   string `env:"IGVM_ID"        envDefault:"igvm0"`
	File string `env:"IGVM_FILE"      envDefault:"/root/coconut-qemu.igvm"`
}

type VSockConfig struct {
	ID       string `env:"VSOCK_ID"        envDefault:"vhost-vsock-pci0"`
	GuestCID int    `env:"VSOCK_GUEST_CID" envDefault:"3"`
}

type Config struct {
	EnableSEVSNP bool
	EnableTDX    bool
	QemuBinPath  string `env:"BIN_PATH"       envDefault:"qemu-system-x86_64"`
	UseSudo      bool   `env:"USE_SUDO"       envDefault:"false"`

	EnableKVM bool `env:"ENABLE_KVM" envDefault:"true"`

	// machine, CPU, RAM
	Machine  string `env:"MACHINE"     envDefault:"q35"`
	CPU      string `env:"CPU"         envDefault:"EPYC"`
	SMPCount int    `env:"SMP_COUNT"   envDefault:"4"`
	MaxCPUs  int    `env:"SMP_MAXCPUS" envDefault:"64"`
	MemID    string `env:"MEM_ID"      envDefault:"ram1"`
	MemoryConfig

	// OVMF
	OVMFCodeConfig
	OVMFVarsConfig

	// network
	NetDevConfig
	VirtioNetPciConfig

	// Vsock
	VSockConfig

	// disk
	DiskImgConfig

	// SEV-SNP
	SEVSNPConfig

	// TDX
	TDXConfig

	// vTPM
	IGVMConfig

	// display
	NoGraphic bool   `env:"NO_GRAPHIC" envDefault:"true"`
	Monitor   string `env:"MONITOR"    envDefault:"pty"`

	// ports
	HostFwdRange string `env:"HOST_FWD_RANGE" envDefault:"6100-6200"`

	// mounts
	CertsMount string `env:"CERTS_MOUNT" envDefault:""`
	EnvMount   string `env:"ENV_MOUNT"   envDefault:""`
}

func (config Config) ConstructQemuArgs() []string {
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

	args = append(args, "-smp", fmt.Sprintf("%d,maxcpus=%d", config.SMPCount, config.MaxCPUs))

	args = append(args, "-m", fmt.Sprintf("%s,slots=%d,maxmem=%s",
		config.MemoryConfig.Size,
		config.MemoryConfig.Slots,
		config.MemoryConfig.Max))

	if !config.EnableSEVSNP && !config.EnableTDX {
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
	}

	// network
	args = append(args, "-netdev",
		fmt.Sprintf("user,id=%s,hostfwd=tcp::%d-:%d",
			config.NetDevConfig.ID,
			config.NetDevConfig.HostFwdAgent, config.NetDevConfig.GuestFwdAgent))

	args = append(args, "-device",
		fmt.Sprintf("virtio-net-pci,disable-legacy=%s,iommu_platform=%v,netdev=%s,addr=%s,romfile=%s",
			config.VirtioNetPciConfig.DisableLegacy,
			config.VirtioNetPciConfig.IOMMUPlatform,
			config.NetDevConfig.ID,
			config.VirtioNetPciConfig.Addr,
			config.VirtioNetPciConfig.ROMFile))

	args = append(args, "-device", fmt.Sprintf("vhost-vsock-pci,id=%s,guest-cid=%d", config.VSockConfig.ID, config.VSockConfig.GuestCID))

	// SEV-SNP
	if config.EnableSEVSNP {
		sevSnpType := "sev-snp-guest"
		hostData := ""

		args = append(args, "-machine",
			fmt.Sprintf("confidential-guest-support=%s,memory-backend=%s,igvm-cfg=%s",
				config.SEVSNPConfig.ID,
				config.MemID,
				config.IGVMConfig.ID))

		if config.SEVSNPConfig.EnableHostData {
			hostData = fmt.Sprintf(",host-data=%s", config.SEVSNPConfig.HostData)
		}

		args = append(args, "-object",
			fmt.Sprintf("memory-backend-memfd,id=%s,size=%s,share=true,prealloc=false",
				config.MemID,
				config.MemoryConfig.Size))

		args = append(args, "-object",
			fmt.Sprintf("%s,id=%s,cbitpos=%d,reduced-phys-bits=%d%s",
				sevSnpType,
				config.SEVSNPConfig.ID,
				config.SEVSNPConfig.CBitPos,
				config.SEVSNPConfig.ReducedPhysBits,
				hostData))

		args = append(args, "-object",
			fmt.Sprintf("igvm-cfg,id=%s,file=%s",
				config.IGVMConfig.ID,
				config.IGVMConfig.File))
	}

	if config.EnableTDX {
		args = append(args, "-object",
			fmt.Sprintf(TDXObject,
				config.TDXConfig.ID,
				config.TDXConfig.QuoteGenerationPort))

		args = append(args, "-machine",
			fmt.Sprintf("confidential-guest-support=%s,memory-backend=%s,hpet=off",
				config.TDXConfig.ID,
				config.MemID))

		args = append(args, "-object",
			fmt.Sprintf("memory-backend-memfd,id=%s,size=%s,share=true,prealloc=false",
				config.MemID,
				config.MemoryConfig.Size))

		args = append(args, "-bios", config.TDXConfig.OVMF)
		args = append(args, "-nodefaults")
	}

	args = append(args, "-kernel", config.DiskImgConfig.KernelFile)
	args = append(args, "-append", strconv.Quote(KernelCommandLine))
	args = append(args, "-initrd", config.DiskImgConfig.RootFsFile)

	// display
	if config.NoGraphic {
		args = append(args, "-nographic")
	}

	args = append(args, "-monitor", config.Monitor)

	if config.CertsMount != "" {
		args = append(args, "-fsdev", fmt.Sprintf("local,id=cert_fs,path=%s,security_model=mapped", config.CertsMount))
		args = append(args, "-device", "virtio-9p-pci,fsdev=cert_fs,mount_tag=certs_share")
	}

	if config.EnvMount != "" {
		args = append(args, "-fsdev", fmt.Sprintf("local,id=env_fs,path=%s,security_model=mapped", config.EnvMount))
		args = append(args, "-device", "virtio-9p-pci,fsdev=env_fs,mount_tag=env_share")
	}

	return args
}

func NewConfig() (*Config, error) {
	cfg := Config{}

	if err := env.Parse(&cfg); err != nil {
		return nil, err
	}

	cfg.EnableSEVSNP = SEVSNPEnabledOnHost()
	cfg.EnableTDX = TDXEnabledOnHost()

	return &cfg, nil
}
