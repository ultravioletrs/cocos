// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"reflect"
	"testing"
)

func TestConstructQemuArgs(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected []string
	}{
		{
			name: "Default configuration",
			config: Config{
				QemuBinPath: "qemu-system-x86_64",
				EnableKVM:   true,
				Machine:     "q35",
				CPU:         "EPYC",
				SMPCount:    4,
				MaxCPUs:     64,
				MemID:       "ram1",
				MemoryConfig: MemoryConfig{
					Size:  "2048M",
					Slots: 5,
					Max:   "30G",
				},
				OVMFCodeConfig: OVMFCodeConfig{
					If:       "pflash",
					Format:   "raw",
					Unit:     0,
					File:     "/usr/share/OVMF/OVMF_CODE.fd",
					ReadOnly: "on",
				},
				OVMFVarsConfig: OVMFVarsConfig{
					If:     "pflash",
					Format: "raw",
					Unit:   1,
					File:   "/usr/share/OVMF/OVMF_VARS.fd",
				},
				NetDevConfig: NetDevConfig{
					ID:            "vmnic",
					HostFwdAgent:  7020,
					GuestFwdAgent: 7002,
				},
				VirtioNetPciConfig: VirtioNetPciConfig{
					DisableLegacy: "on",
					IOMMUPlatform: true,
					Addr:          "0x2",
				},
				KernelConfig: KernelConfig{
					KernelFile: "img/bzImage",
					RootFsFile: "img/rootfs.cpio.gz",
				},
				NoGraphic: true,
				Monitor:   "pty",
			},
			expected: []string{
				"-enable-kvm",
				"-machine", "q35",
				"-cpu", "EPYC",
				"-smp", "4,maxcpus=64",
				"-m", "2048M,slots=5,maxmem=30G",
				"-drive", "if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on",
				"-drive", "if=pflash,format=raw,unit=1,file=/usr/share/OVMF/OVMF_VARS.fd",
				"-netdev", "user,id=vmnic,hostfwd=tcp::7020-:7002",
				"-device", "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,addr=0x2,romfile=",
				"-kernel", "img/bzImage",
				"-append", "\"quiet console=null\"",
				"-initrd", "img/rootfs.cpio.gz",
				"-nographic",
				"-monitor", "pty",
			},
		},
		{
			name: "SEV-SNP enabled configuration",
			config: Config{
				QemuBinPath:  "qemu-system-x86_64",
				EnableKVM:    true,
				EnableSEVSNP: true,
				Machine:      "q35",
				CPU:          "EPYC",
				SMPCount:     4,
				MaxCPUs:      64,
				MemID:        "ram1",
				MemoryConfig: MemoryConfig{
					Size:  "2048M",
					Slots: 5,
					Max:   "30G",
				},
				OVMFCodeConfig: OVMFCodeConfig{
					If:       "pflash",
					Format:   "raw",
					Unit:     0,
					File:     "/usr/share/OVMF/OVMF_CODE.fd",
					ReadOnly: "on",
				},
				OVMFVarsConfig: OVMFVarsConfig{
					If:     "pflash",
					Format: "raw",
					Unit:   1,
					File:   "/usr/share/OVMF/OVMF_VARS.fd",
				},
				NetDevConfig: NetDevConfig{
					ID:            "vmnic",
					HostFwdAgent:  7020,
					GuestFwdAgent: 7002,
				},
				VirtioNetPciConfig: VirtioNetPciConfig{
					DisableLegacy: "on",
					IOMMUPlatform: true,
					Addr:          "0x2",
				},
				KernelConfig: KernelConfig{
					KernelFile: "img/bzImage",
					RootFsFile: "img/rootfs.cpio.gz",
				},
				SEVSNPConfig: SEVSNPConfig{
					ID:              "sev0",
					CBitPos:         51,
					ReducedPhysBits: 1,
				},
				IGVMConfig: IGVMConfig{
					ID:   "igvm0",
					File: "/test/path/cocos-igvm.igvm",
				},
				NoGraphic: true,
				Monitor:   "pty",
			},
			expected: []string{
				"-enable-kvm",
				"-machine", "q35",
				"-cpu", "EPYC",
				"-smp", "4,maxcpus=64",
				"-m", "2048M,slots=5,maxmem=30G",
				"-netdev", "user,id=vmnic,hostfwd=tcp::7020-:7002",
				"-device", "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,addr=0x2,romfile=",
				"-machine", "confidential-guest-support=sev0,memory-backend=ram1,igvm-cfg=igvm0",
				"-object", "memory-backend-memfd,id=ram1,size=2048M,share=true,prealloc=false",
				"-object", "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1",
				"-object", "igvm-cfg,id=igvm0,file=/test/path/cocos-igvm.igvm",
				"-kernel", "img/bzImage",
				"-append", "\"quiet console=null\"",
				"-initrd", "img/rootfs.cpio.gz",
				"-nographic",
				"-monitor", "pty",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.ConstructQemuArgs()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ConstructQemuArgs() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConstructQemuArgs_HostData(t *testing.T) {
	config := Config{
		EnableSEVSNP: true,
		SEVSNPConfig: SEVSNPConfig{
			ID:              "sev0",
			CBitPos:         51,
			ReducedPhysBits: 1,
			EnableHostData:  true,
			HostData:        "test-host-data",
		},
	}

	result := config.ConstructQemuArgs()

	expected := "-object"
	expectedValue := "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,host-data=test-host-data"

	found := false
	for i, arg := range result {
		if arg == expected && i+1 < len(result) {
			if result[i+1] == expectedValue {
				found = true
				break
			}
		}
	}

	if !found {
		t.Errorf("ConstructQemuArgs() did not contain expected SEV-SNP configuration with host data")
	}
}

func TestConstructQemuArgs_EnableDisk(t *testing.T) {
	config := Config{
		EnableDisk: true,
		DiskConfig: DiskConfig{
			SrcFile: "img/enc_os.qcow2",
			DstFile: "img/enc_os_dst.qcow2",
			ID:      "disk0",
			Format:  "qcow2",
			SCSIID:  "scsi0",
		},
	}

	result := config.ConstructQemuArgs()

	expected := []string{
		"-drive", "file=img/enc_os_dst.qcow2,if=none,id=disk0,format=qcow2",
		"-device", "virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true",
		"-device", "scsi-hd,drive=disk0,bus=scsi0.0",
	}

	var found []bool = make([]bool, len(expected))
	for i, arg := range result {
		for j := 0; j < len(expected); j += 2 {
			if arg == expected[j] && i+1 < len(result) && result[i+1] == expected[j+1] {
				found[j] = true
				found[j+1] = true
				break
			}
		}
	}

	for j, f := range found {
		if !f {
			t.Errorf("ConstructQemuArgs() did not contain expected disk configuration: %s", expected[j])
		}
	}
}
