// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
)

const testComputationID = "test-computation"

func cleanupStrayQcow2(t *testing.T) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(wd, "qcow2"))
	})
}

func requireTempFile(t *testing.T, path string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create temp file %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file %s: %v", path, err)
	}
}

func TestNewVM(t *testing.T) {
	config := VMInfo{Config: Config{}}

	vm := NewVM(config, testComputationID, slog.Default())

	assert.NotNil(t, vm)
	assert.IsType(t, &qemuVM{}, vm)
}

func TestStart(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-ovmf-vars")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	config := VMInfo{Config: Config{
		OVMFVarsConfig: OVMFVarsConfig{
			File: tmpFile.Name(),
		},
		QemuBinPath: "echo",
		KernelConfig: KernelConfig{
			KernelFile: "img/bzImage",
			RootFsFile: "img/rootfs.cpio.gz",
		},
	}}

	vm := NewVM(config, testComputationID, slog.Default()).(*qemuVM)

	err = vm.Start()
	assert.NoError(t, err)
	assert.NotNil(t, vm.cmd)

	_ = vm.Stop()
}

func TestStartSudo(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-ovmf-vars")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	config := VMInfo{Config: Config{
		OVMFVarsConfig: OVMFVarsConfig{
			File: tmpFile.Name(),
		},
		QemuBinPath: "echo",
		UseSudo:     true,
		KernelConfig: KernelConfig{
			KernelFile: "img/bzImage",
			RootFsFile: "img/rootfs.cpio.gz",
		},
	}}

	vm := NewVM(config, testComputationID, slog.Default()).(*qemuVM)

	err = vm.Start()
	assert.NoError(t, err)
	assert.NotNil(t, vm.cmd)

	_ = vm.Stop()
}

func TestStart_EnableDisk(t *testing.T) {
	cleanupStrayQcow2(t)

	toolsDir := t.TempDir()
	convertLogFile := filepath.Join(toolsDir, "qemu-img-convert.log")
	resizeLogFile := filepath.Join(toolsDir, "qemu-img-resize.log")
	srcDiskFile := filepath.Join(toolsDir, "enc_os.qcow2")
	requireTempFile(t, srcDiskFile)

	writeFakeExecutable(t, toolsDir, "qemu-img", fmt.Sprintf(`#!/bin/sh
case "$1" in
info)
  printf '%%s' '{"virtual-size":2147483648}'
  ;;
convert)
  printf '%%s\n' "$@" > %q
  dst="$7"
  : > "$dst"
  ;;
resize)
  printf '%%s\n' "$@" > %q
  ;;
*)
  echo "unexpected subcommand: $1" >&2
  exit 2
  ;;
esac
`, convertLogFile, resizeLogFile))

	writeFakeExecutable(t, toolsDir, "fake-qemu", `#!/bin/sh
trap 'exit 0' TERM INT
while :; do
  sleep 1
done
`)
	prependPath(t, toolsDir)

	config := VMInfo{Config: Config{
		EnableTDX:   true,
		EnableDisk:  true,
		QemuBinPath: "fake-qemu",
		DiskConfig: DiskConfig{
			SrcFile: srcDiskFile,
			ID:      "disk0",
			Format:  "qcow2",
			SCSIID:  "scsi0",
		},
	}}

	vm := NewVM(config, testComputationID, slog.Default()).(*qemuVM)

	err := vm.Start()
	assert.NoError(t, err)
	assert.NotNil(t, vm.cmd)
	assert.Contains(t, vm.vmi.Config.DstFile, filepath.Join(tmpDir, diskDstName))
	_, err = os.Stat(vm.vmi.Config.DstFile)
	assert.NoError(t, err)

	loggedArgs, err := os.ReadFile(convertLogFile)
	assert.NoError(t, err)
	assert.Equal(t, []string{
		"convert",
		"-f",
		"qcow2",
		"-O",
		"qcow2",
		srcDiskFile,
		vm.vmi.Config.DstFile,
	}, strings.Fields(string(loggedArgs)))

	loggedArgs, err = os.ReadFile(resizeLogFile)
	assert.NoError(t, err)
	assert.Equal(t, []string{
		"resize",
		vm.vmi.Config.DstFile,
		"3G",
	}, strings.Fields(string(loggedArgs)))

	err = vm.Stop()
	assert.NoError(t, err)
	_, err = os.Stat(vm.vmi.Config.DstFile)
	assert.Error(t, err)
	assert.True(t, os.IsNotExist(err))
}

func TestStart_EnableDiskCreateError(t *testing.T) {
	cleanupStrayQcow2(t)

	toolsDir := t.TempDir()
	srcDiskFile := filepath.Join(toolsDir, "enc_os.qcow2")
	requireTempFile(t, srcDiskFile)

	writeFakeExecutable(t, toolsDir, "qemu-img", `#!/bin/sh
case "$1" in
info)
  printf '%s' '{"virtual-size":2147483648}'
  ;;
convert)
  echo 'disk create failed' >&2
  exit 1
  ;;
resize)
  exit 0
  ;;
*)
  echo "unexpected subcommand: $1" >&2
  exit 2
  ;;
esac
`)
	prependPath(t, toolsDir)

	config := VMInfo{Config: Config{
		EnableTDX:   true,
		EnableDisk:  true,
		QemuBinPath: "fake-qemu",
		DiskConfig: DiskConfig{
			SrcFile: srcDiskFile,
		},
	}}

	vm := NewVM(config, testComputationID, slog.Default()).(*qemuVM)

	err := vm.Start()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "qemu-img convert failed")
	assert.ErrorContains(t, err, "disk create failed")
	assert.Nil(t, vm.cmd)
}

func TestStop(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cmd := exec.Command("echo", "test")
		err := cmd.Start()
		assert.NoError(t, err)
		sm := new(mocks.StateMachine)
		sm.On("Transition", pkgmanager.StopComputationRun).Return(nil)

		vm := &qemuVM{
			cmd: &exec.Cmd{
				Process: cmd.Process,
			},
			StateMachine: sm,
		}

		err = vm.Stop()
		assert.NoError(t, err)
	})
	t.Run("transition error", func(t *testing.T) {
		cmd := exec.Command("echo", "test")
		err := cmd.Start()
		assert.NoError(t, err)
		sm := new(mocks.StateMachine)
		sm.On("Transition", pkgmanager.StopComputationRun).Return(assert.AnError)
		sm.On("State").Return(pkgmanager.Stopped.String())

		vm := &qemuVM{
			cmd: &exec.Cmd{
				Process: cmd.Process,
			},
			StateMachine: sm,
		}

		err = vm.Stop()
		assert.NoError(t, err)
	})
	t.Run("disk enable", func(t *testing.T) {
		dir := t.TempDir()
		dst := filepath.Join(dir, "disk.qcow2")

		f, err := os.Create(dst)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command("echo", "test")
		err = cmd.Start()
		assert.NoError(t, err)
		sm := new(mocks.StateMachine)
		sm.On("Transition", pkgmanager.StopComputationRun).Return(nil)

		vm := &qemuVM{
			vmi: VMInfo{
				Config: Config{
					EnableDisk: true,
					DiskConfig: DiskConfig{
						DstFile: dst,
					},
				},
			},
			cmd: &exec.Cmd{
				Process: cmd.Process,
			},
			StateMachine: sm,
		}

		err = vm.Stop()
		assert.NoError(t, err)
	})
}

func TestSetProcess(t *testing.T) {
	vm := &qemuVM{
		vmi: VMInfo{
			Config: Config{
				QemuBinPath: "echo", // Use 'echo' as a dummy QEMU binary
				KernelConfig: KernelConfig{
					KernelFile: "img/bzImage",
					RootFsFile: "img/rootfs.cpio.gz",
				},
			},
		},
	}

	err := vm.SetProcess(os.Getpid()) // Use current process as a dummy
	assert.NoError(t, err)
	assert.NotNil(t, vm.cmd)
	assert.NotNil(t, vm.cmd.Process)
}

func TestGetProcess(t *testing.T) {
	expectedPid := 12345
	vm := &qemuVM{
		cmd: &exec.Cmd{
			Process: &os.Process{Pid: expectedPid},
		},
	}

	pid := vm.GetProcess()
	assert.Equal(t, expectedPid, pid)
}

func TestGetConfig(t *testing.T) {
	expectedConfig := VMInfo{
		Config: Config{
			QemuBinPath: "echo",
		},
	}
	vm := &qemuVM{
		vmi: expectedConfig,
	}

	config := vm.GetConfig()
	assert.Equal(t, expectedConfig, config)
}

func TestSEVSNPEnabled(t *testing.T) {
	t.Run("cpuinfo and kvm param correct", func(t *testing.T) {
		assert.True(t, SEVSNPEnabled("flags: sev_snp abc", "Y"))
	})

	t.Run("missing sev_snp in cpuinfo", func(t *testing.T) {
		assert.False(t, SEVSNPEnabled("flags: abc", "1"))
	})

	t.Run("kernel param not enabled", func(t *testing.T) {
		assert.False(t, SEVSNPEnabled("flags: sev_snp", "0"))
	})
}

func TestTDXEnabled(t *testing.T) {
	t.Run("cpuinfo and kvm param correct", func(t *testing.T) {
		assert.True(t, TDXEnabled("flags: tdx_host_platform abc", "Y"))
	})

	t.Run("missing tdx_host_platform in cpuinfo", func(t *testing.T) {
		assert.False(t, TDXEnabled("flags: abc", "1"))
	})

	t.Run("kernel param not enabled", func(t *testing.T) {
		assert.False(t, TDXEnabled("flags: tdx_host_platform", "0"))
	})
}

func TestSEVSNPEnabledOnHost(t *testing.T) {
	cpuinfo, cpuErr := os.ReadFile("/proc/cpuinfo")
	kernelParam, kernelErr := os.ReadFile("/sys/module/kvm_amd/parameters/sev_snp")

	expected := false
	if cpuErr == nil && kernelErr == nil {
		expected = SEVSNPEnabled(string(cpuinfo), string(kernelParam))
	}

	assert.Equal(t, expected, SEVSNPEnabledOnHost())
}

func TestTDXEnabledOnHost(t *testing.T) {
	cpuinfo, cpuErr := os.ReadFile("/proc/cpuinfo")
	kernelParam, kernelErr := os.ReadFile("/sys/module/kvm_intel/parameters/tdx")

	expected := false
	if cpuErr == nil && kernelErr == nil {
		expected = TDXEnabled(string(cpuinfo), string(kernelParam))
	}

	assert.Equal(t, expected, TDXEnabledOnHost())
}

func TestGetVirtualSizeBytes_Success(t *testing.T) {
	cleanup := writeFakeQemuImg(t, `{"virtual-size":2147483648}`, 0) // 2 GiB
	defer cleanup()

	got, err := GetVirtualSizeBytes("whatever.qcow2")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != 2147483648 {
		t.Fatalf("expected 2147483648, got %d", got)
	}
}

func TestGetVirtualSizeBytes_CommandFailure(t *testing.T) {
	cleanup := writeFakeQemuImg(t, `{"virtual-size":2147483648}`, 1) // non-zero exit
	defer cleanup()

	_, err := GetVirtualSizeBytes("whatever.qcow2")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "qemu-img info failed") {
		t.Fatalf("expected wrapped error to contain %q, got %q", "qemu-img info failed", err.Error())
	}
}

func TestGetVirtualSizeBytes_InvalidJSON(t *testing.T) {
	cleanup := writeFakeQemuImg(t, `not-json`, 0)
	defer cleanup()

	_, err := GetVirtualSizeBytes("whatever.qcow2")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse qemu-img JSON") {
		t.Fatalf("expected error to contain %q, got %q", "failed to parse qemu-img JSON", err.Error())
	}
}

func TestGetVirtualSizeBytes_InvalidVirtualSize(t *testing.T) {
	cleanup := writeFakeQemuImg(t, `{"virtual-size":0}`, 0)
	defer cleanup()

	_, err := GetVirtualSizeBytes("whatever.qcow2")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid virtual size") {
		t.Fatalf("expected error to contain %q, got %q", "invalid virtual size", err.Error())
	}
}

func TestGetVirtualSizeGB_RoundsUp(t *testing.T) {
	tests := []struct {
		name      string
		virtualSz int64
		wantGB    int
	}{
		{"exact_1GiB", 1 << 30, 1},
		{"one_byte_over", (1 << 30) + 1, 2},
		{"just_under_2GiB", (2 << 30) - 1, 2},
		{"exact_2GiB", 2 << 30, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cleanup := writeFakeQemuImg(t, fmt.Sprintf(`{"virtual-size":%d}`, tc.virtualSz), 0)
			defer cleanup()

			got, err := GetVirtualSizeGB("whatever.qcow2")
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if got != tc.wantGB {
				t.Fatalf("expected %d, got %d", tc.wantGB, got)
			}
		})
	}
}

func writeFakeQemuImg(t *testing.T, stdout string, exitCode int) func() {
	dir := t.TempDir()
	fake := filepath.Join(dir, "qemu-img")

	script := fmt.Sprintf(`#!/bin/sh
# Minimal fake for: qemu-img info --output=json <path>
if [ "$1" != "info" ]; then
  echo "unexpected subcommand: $1" >&2
  exit 2
fi

# always print provided stdout, even if empty
printf '%s' %q
exit %d
`, stdout, stdout, exitCode)

	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write fake qemu-img: %v", err)
	}

	oldPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}

	return func() {
		_ = os.Setenv("PATH", oldPath)
	}
}

func writeFakeExecutable(t *testing.T, dir, name, script string) {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write fake executable %q: %v", name, err)
	}
}

func prependPath(t *testing.T, dir string) {
	t.Helper()

	oldPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
	})
}
