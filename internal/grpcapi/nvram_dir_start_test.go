package grpcapi

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// lab2-D2-proof A2: `lv update --secure-boot --tpm` then `lv start` on a host
// that never had a Secure Boot / vTPM VM failed, because only a create made
// <data_dir>/nvram and libvirt does not. Every start of such a VM makes it,
// searchable (0711 under the fixture's explicit 022 umask) as a create does;
// a BIOS VM's start does not. Production respects the operator's umask.
//
// Mutation: drop the directory from the start hook — red.
func TestPrepareHardwareForStart_MakesTheNvramDir(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	for _, tc := range []struct {
		name, spec string
		want       bool
	}{
		{"uefi_sb_tpm", `{"name":"fw","secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"u-fw"}`, true},
		{"bios_tpm", `{"name":"fw","tpm":true,"firmware":"bios","uuid":"u-fw"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, ctx := firmwareTestServer(t, "fw", "stopped")
			vm := &corrosion.VMRecord{Name: "fw", HostName: s.hostName, Spec: tc.spec, State: "stopped"}
			release, err := s.PrepareHardwareForStart(ctx, vm)
			if err != nil {
				t.Fatalf("PrepareHardwareForStart: %v", err)
			}
			release()
			fi, err := os.Stat(filepath.Join(s.dataDir, "nvram"))
			if !tc.want {
				if err == nil {
					t.Error("a BIOS VM's start made an NVRAM directory")
				}
				return
			}
			if err != nil {
				t.Fatalf("no NVRAM directory after the start hook: %v", err)
			}
			if fi.Mode().Perm() != 0o711 {
				t.Errorf("NVRAM directory mode %v, want 0711", fi.Mode().Perm())
			}
		})
	}
}

// The start hook must create a missing directory without overriding restrictive
// operator policy or widening a directory that already exists.
func TestPrepareHardwareForStart_RespectsNvramDirectoryPolicy(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	for _, existing := range []bool{false, true} {
		name := "new-under-077"
		if existing {
			name = "existing-mode-preserved"
		}
		t.Run(name, func(t *testing.T) {
			s, _, ctx := firmwareTestServer(t, "fw", "stopped")
			dir := filepath.Join(s.dataDir, "nvram")
			want := os.FileMode(0o700)
			if existing {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				want = 0o500
				if err := os.Chmod(dir, want); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			}
			vm := &corrosion.VMRecord{Name: "fw", HostName: s.hostName, Spec: `{"name":"fw","secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"u-fw"}`, State: "stopped"}
			release, err := s.PrepareHardwareForStart(ctx, vm)
			if err != nil {
				t.Fatal(err)
			}
			release()
			fi, err := os.Stat(dir)
			if err != nil || !fi.IsDir() {
				t.Fatalf("NVRAM directory unavailable: %v", err)
			}
			if got := fi.Mode().Perm(); got != want {
				t.Fatalf("NVRAM directory mode %04o, want %04o", got, want)
			}
		})
	}
}
