package grpcapi

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Review I-1: a snapshot create/rm cycle must leave the VM's chain as deep as
// it found it, whatever the snapshot's type and whether the VM runs —
// otherwise about 16 cycles later a start refuses the chain ("backing chain
// deeper than 16") and the VM never starts again. main, on libvirt >= 9,
// merged the deleted current snapshot. Here the delete of the last snapshot
// merges the VM's active layer down into the lowest layer nothing else uses.
//
// Each cycle makes the overlay a real qcow2 file over the active disk (as
// libvirt's external snapshot does), cuts the fake domain over to it, and
// deletes the snapshot through the RPC: the VM must be back on its own disk
// after every cycle, its record too.
func TestDeleteSnapshot_CreateRmCyclesKeepTheChainDepth(t *testing.T) {
	for _, tc := range []struct{ state, typ string }{
		{"running", "disk"}, {"running", "memory"}, {"stopped", "disk"},
	} {
		t.Run(tc.state+"-"+tc.typ, func(t *testing.T) {
			needQemuImg(t)
			ctx := adminCtx()
			s, fake := newDiskPathTestServer(t)
			s.dataDir = t.TempDir()
			dir := t.TempDir()
			root := filepath.Join(dir, "cyc-root.qcow2")
			runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
			if err := corrosion.InsertVM(ctx, s.db,
				corrosion.VMRecord{Name: "cyc", HostName: "host-a", State: tc.state}, nil,
				[]corrosion.DiskRecord{{VMName: "cyc", DiskName: "root", HostName: "host-a", Path: root, StorageType: "local", TargetDev: "vda"}},
			); err != nil {
				t.Fatal(err)
			}
			fake.SetDiskSource("cyc", "vda", root)
			for i := 0; i < 20; i++ {
				snap := fmt.Sprintf("c%d", i)
				active := root
				overlay := strings.TrimSuffix(active, filepath.Ext(active)) + "." + snap
				runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", active, overlay)
				if _, err := fake.CreateSnapshot("cyc", snap); err != nil {
					t.Fatal(err)
				}
				if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
					ID: "cyc-" + snap, VMName: "cyc", HostName: "host-a", Name: snap, State: "ok", Type: tc.typ,
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "cyc", SnapshotName: snap}); err != nil {
					t.Fatalf("cycle %d: DeleteSnapshot: %v", i, err)
				}
				srcs, _ := fake.DomainDiskSources("cyc")
				if srcs["vda"] != root {
					t.Fatalf("cycle %d: the domain is on %s, not merged back onto %s — the chain grew by a layer", i, srcs["vda"], root)
				}
				disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "cyc")
				if len(disks) != 1 || disks[0].Path != root {
					t.Fatalf("cycle %d: recorded disks %+v, want the root at %s", i, disks, root)
				}
			}
		})
	}
}

// A chain deeper than a start accepts is refused with its cause and the
// way out, not only the limit.
func TestStartChain_TooDeepNamesTheFix(t *testing.T) {
	needQemuImg(t)
	s, _ := newDiskPathTestServer(t)
	s.dataDir = t.TempDir()
	dir := t.TempDir()
	prev := filepath.Join(dir, "deep-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", prev, "1M")
	for i := 0; i <= maxBackingDepth+1; i++ {
		next := filepath.Join(dir, fmt.Sprintf("deep-root.c%d", i))
		runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", prev, next)
		prev = next
	}
	vm := &corrosion.VMRecord{Name: "deep", HostName: "host-a"}
	d := corrosion.DiskRecord{VMName: "deep", DiskName: "root", HostName: "host-a", Path: prev, StorageType: "local"}
	err := s.verifyDiskChainForStart(adminCtx(), vm, d, prev)
	if err == nil {
		t.Fatal("a chain deeper than the cap was accepted")
	}
	for _, want := range []string{"deeper than", "lv snapshot rm", "lv snapshot create deep"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not say %q", err, want)
		}
	}
}
