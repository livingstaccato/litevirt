package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// lab2-D2-proof A2: `lv update --secure-boot --tpm` then `lv start` on a host
// that never had a Secure Boot / vTPM VM failed, because only a create made
// <data_dir>/nvram and libvirt does not. Every start of such a VM makes it,
// searchable (0711) as a create does; a BIOS VM's start does not.
//
// Mutation: drop the directory from the start hook — red.
func TestPrepareHardwareForStart_MakesTheNvramDir(t *testing.T) {
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
