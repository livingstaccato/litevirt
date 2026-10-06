package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// fakeBlockTools puts zfs, lvs, lvcreate, lvremove and lvextend on PATH. Each
// logs its argv to the returned file and succeeds; `zfs list` and `lvs` print
// the object asked for, as the real tools do for one that exists. Each refuses
// what the real tool refuses:
//
//   - `zfs set` (OpenZFS 2.1: no getopt) takes every argument after the
//     property as a dataset, so a "--" there is "cannot open '--'";
//   - `lvextend -L` takes a size with an LVM unit suffix.
func fakeBlockTools(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	script := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> " + log + "\n" +
		"tool=$(basename \"$0\")\n" +
		"if [ \"$tool\" = zfs ] && [ \"$1\" = set ]; then for a; do [ \"$a\" = -- ] && { echo \"cannot open '--': dataset does not exist\" >&2; exit 1; }; done; fi\n" +
		"if [ \"$tool\" = lvextend ]; then [ \"$1\" = -L ] && echo \"$2\" | grep -Eq '^[0-9]+[bBsSkKmMgGtTpPeE]?$' || { echo \"lvextend: invalid size\" >&2; exit 3; }; fi\n" +
		"for a; do last=$a; done\necho \"$last\"\n"
	for _, tool := range []string{"zfs", "lvs", "lvcreate", "lvremove", "lvextend"} {
		if err := os.WriteFile(filepath.Join(bin, tool), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func blockToolCalls(t *testing.T, log string) string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// Proxmox model: an admin creates the zfs and lvm-thin pools (storage.hostpath)
// and an operator then uses them exactly like a file pool — creates, resizes
// and deletes their own VMs' disks on them, snapshots them, and replicates to
// them — with only their project's operator role.
func TestPoolBlock_OperatorUsesAdminCreatedZfsAndLvmThinPools(t *testing.T) {
	log := fakeBlockTools(t)
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	for _, req := range []*pb.CreateStoragePoolRequest{
		{Name: "tank", Driver: "zfs", Source: "tank/acme", Project: "acme"},
		{Name: "thin", Driver: "lvm-thin", Source: "vg0", Options: map[string]string{"thinpool": "tp0"}, Project: "acme"},
	} {
		if _, err := s.CreateStoragePool(ctx, req); err != nil {
			t.Fatalf("admin creates %s pool: %v", req.Driver, err)
		}
	}
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))

	// Creating one is still the admin's.
	if _, err := s.CreateStoragePool(pat, &pb.CreateStoragePoolRequest{Name: "mine", Driver: "zfs", Source: "tank/acme/mine", Project: "acme"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator creating a zfs pool: got %v, want PermissionDenied", err)
	}

	req := disklessCreateRequest("vm1")
	req.Spec.Project = "acme"
	req.Spec.Network = nil
	req.Spec.Disks = []*pb.DiskSpec{
		{Name: "root", Size: "1G", Storage: "tank"},
		{Name: "data", Size: "1G", Storage: "thin"},
	}
	if _, err := s.CreateVM(pat, req); err != nil {
		t.Fatalf("operator creates a VM on the block pools: %v", err)
	}
	calls := blockToolCalls(t, log)
	for _, want := range []string{"zfs create -V 1073741824 -- tank/acme/vm1-root", "lvcreate --type thin", "--name vm1-data -- vg0"} {
		if !strings.Contains(calls, want) {
			t.Errorf("tool calls lack %q:\n%s", want, calls)
		}
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, d := range disks {
		paths[d.DiskName] = d.Path
	}
	if paths["root"] != "/dev/zvol/tank/acme/vm1-root" || paths["data"] != "/dev/vg0/vm1-data" {
		t.Fatalf("disk paths = %v", paths)
	}

	fake.SetState("vm1", libvirtfake.StateRunning)
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "running", ""); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"root", "data"} {
		if _, err := s.ResizeDisk(pat, &pb.ResizeDiskRequest{VmName: "vm1", DiskName: d, Size: "2G"}); err != nil {
			t.Errorf("operator resizes %s: %v", d, err)
		}
	}
	if _, err := s.CreateSnapshot(pat, &pb.CreateSnapshotRequest{VmName: "vm1", Name: "before"}); err != nil {
		t.Errorf("operator snapshots the VM: %v", err)
	}
	if _, err := s.CreateReplicationSchedule(pat, &pb.CreateReplicationScheduleRequest{
		VmName: "vm1", TargetPool: "tank", TargetHost: s.hostName, Cron: "0 0 * * *",
	}); err != nil {
		t.Errorf("operator schedules replication to the zfs pool: %v", err)
	}
	if err := s.checkPoolForWrite(pat, "tank", StoragePoolRef{Driver: "zfs", Source: "tank/acme"}); err != nil {
		t.Errorf("the zfs pool is refused for writes: %v", err)
	}

	fake.SetState("vm1", libvirtfake.StateShutdown)
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteVM(pat, &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("operator deletes the VM: %v", err)
	}
	calls = blockToolCalls(t, log)
	for _, want := range []string{"zfs destroy -r -- tank/acme/vm1-root", "lvremove -f -- vg0/vm1-data"} {
		if !strings.Contains(calls, want) {
			t.Errorf("tool calls lack %q:\n%s", want, calls)
		}
	}
}
