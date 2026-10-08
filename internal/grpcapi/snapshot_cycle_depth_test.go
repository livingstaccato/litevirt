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

// Round-2 concern 2: libvirt may hold a snapshot litevirt has no record of
// (left by an earlier failure). Its frozen layer — the disk its domain was
// on — must not be merged away: the merge stops above it, and the snapshot
// is named in a WARN.
func TestDeleteSnapshot_AnUnrecordedLibvirtSnapshotKeepsItsLayer(t *testing.T) {
	needQemuImg(t)
	ctx := adminCtx()
	s, fake := newDiskPathTestServer(t)
	s.dataDir = t.TempDir()
	dir := t.TempDir()
	root := filepath.Join(dir, "un-root.qcow2")
	orphan := filepath.Join(dir, "un-root.orphan")
	top := filepath.Join(dir, "un-root.s1")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", root, orphan)
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", orphan, top)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "un", HostName: "host-a", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "un", DiskName: "root", HostName: "host-a", Path: root, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	fake.SetDiskSource("un", "vda", root)
	// libvirt's own snapshot, with no litevirt record.
	if _, err := fake.CreateSnapshot("un", "orphan"); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.CreateSnapshot("un", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{ID: "un-s1", VMName: "un", HostName: "host-a", Name: "s1", State: "ok", Type: "disk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "un", SnapshotName: "s1"}); err != nil {
		t.Fatal(err)
	}
	for _, b := range fake.FlattenBases {
		if b["vda"] == root {
			t.Fatalf("merged into %s, the frozen layer of libvirt snapshot \"orphan\" that litevirt has no record of", root)
		}
	}
	srcs, _ := fake.DomainDiskSources("un")
	if srcs["vda"] != orphan {
		t.Fatalf("the domain is on %s, want merged down onto %s and no further", srcs["vda"], orphan)
	}
}
