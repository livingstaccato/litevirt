//go:build unix

package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Turning Secure Boot on with lv update, on a host where no Secure Boot VM was
// ever created, leaves a VM that starts: its vars file's directory exists, at
// the mode a create makes it. libvirt only creates the vars FILE at start, so
// a domain pointing into a missing directory fails there ("Failed to create
// file '<data_dir>/nvram/<vm>_VARS.fd.new'").
//
// Mutation: drop the directory step from UpdateVM's regenerate — red.
func TestUpdateVM_SecureBootOnMakesTheNvramDir(t *testing.T) {
	umask022(t)
	s, fake, ctx := ioVM(t, "stopped")
	s.dataDir = t.TempDir()
	s.firmware = lv.FirmwarePaths{Code: "/c", Vars: "/v", SecbootCode: "/sc", MsVars: "/mv"}
	dir := filepath.Join(s.dataDir, "nvram")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the test needs a host with no %s yet: %v", dir, err)
	}

	on := true
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "io", SecureBoot: &on}); err != nil {
		t.Fatalf("UpdateVM --secure-boot: %v", err)
	}
	if x := fake.DefinedXML("io"); !strings.Contains(x, lv.NvramPath(s.dataDir, "io")) {
		t.Fatalf("the redefined domain does not name the vars file %s:\n%s", lv.NvramPath(s.dataDir, "io"), x)
	}
	wantMode(t, dir, 0o711)
}

// A redefine from the replicated rows (reconcileDomainDefinition) of a Secure
// Boot VM whose vars file was never made on this host (an update turned it on
// and the VM has not started since) makes the directory too, at the same mode.
//
// Mutation: drop the directory step from reconcileDomainDefinition — red.
func TestReconcile_SecureBootRedefineMakesTheNvramDir(t *testing.T) {
	umask022(t)
	s := reconfigServer(t)
	s.dataDir = t.TempDir()
	s.firmware = lv.FirmwarePaths{Code: "/c", Vars: "/v", SecbootCode: "/sc", MsVars: "/mv"}
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "sb1", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{
			Name: "sb1", Cpu: 1, MemoryMib: 512, Firmware: "uefi", SecureBoot: true,
			Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio"}},
		}))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "sb1", DiskName: "root", HostName: "test-host",
		Path: "/x/sb1-root.qcow2", DeviceKind: "disk", Bus: "virtio", TargetDev: "vda", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert root: %v", err)
	}

	if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "sb1"), nil); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if x := s.virt.(*libvirtfake.Fake).DefinedXML("sb1"); !strings.Contains(x, lv.NvramPath(s.dataDir, "sb1")) {
		t.Fatalf("the redefined domain does not name the vars file:\n%s", x)
	}
	wantMode(t, filepath.Join(s.dataDir, "nvram"), 0o711)
}
