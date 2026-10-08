package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Re-review 3, I-1. The state a failed repoint leaves: a running merge of s1
// pivoted the VM onto its root, libvirt kept the persistent definition on
// the top, and redefining it failed too. The top is kept and marked
// (.lv-merged); the guest's later writes are in the root. Here the top
// holds 0x53 ("stale") and the root, after the pivot, 0x43 ("current").
type markedVM struct {
	s          *Server
	fake       *libvirtfake.Fake
	root, top  string
	current    []byte
	definition func(file string)
}

func newMarkedVM(t *testing.T) *markedVM {
	t.Helper()
	needQemuImg(t)
	s, fake := provableCreateServer(t)
	ctx := adminCtx()
	dir := t.TempDir()
	root := filepath.Join(dir, "mk-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	spec, _ := json.Marshal(&pb.VMSpec{Name: "mk", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "mk", HostName: s.hostName, State: "running", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "mk", DiskName: "root", HostName: s.hostName, Path: root, SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda"}}); err != nil {
		t.Fatal(err)
	}
	fake.SetDiskSource("mk", "vda", root)
	top := filepath.Join(dir, "mk-root.s1")
	overlayWithData(t, top, root, "qcow2", bytes.Repeat([]byte{0x53}, 1<<20))
	if _, err := fake.CreateSnapshot("mk", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{ID: "mk-s1", VMName: "mk", HostName: s.hostName, Name: "s1", State: "ok", Type: "disk"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateVMDiskPath(ctx, s.db, "mk", "root", top); err != nil {
		t.Fatal(err)
	}
	m := &markedVM{s: s, fake: fake, root: root, top: top}
	m.definition = func(file string) {
		fake.SetInactiveXML("mk", `<domain type='kvm'><name>mk</name><devices><disk type='file' device='disk'>`+
			`<driver name='qemu' type='qcow2'/><source file='`+file+`'/><target dev='vda' bus='virtio'/></disk></devices></domain>`)
	}
	m.definition(top)
	fake.FlattenLeavesConfig = true
	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "mk", SnapshotName: "s1"}); err != nil {
		t.Fatal(err)
	}
	fake.FlattenLeavesConfig = false
	// The guest ran on the root after the pivot, then was stopped.
	if out, err := runQemuIO(root, "write -P 0x43 0 1M"); err != nil {
		t.Fatalf("guest write: %v\n%s", err, out)
	}
	m.current = bytes.Repeat([]byte{0x43}, 1<<20)
	if _, err := s.db.ExecuteRows(ctx, `UPDATE vms SET state = 'stopped' WHERE name = 'mk'`); err != nil {
		t.Fatal(err)
	}
	fake.SetDiskSource("mk", "vda", top) // stopped: libvirt works from the definition
	return m
}

// Snapshot create, then start, then snapshot rm, on the marked VM. Before
// the fix the create made an overlay over the stale top, the start check
// saw only that unmarked overlay, and the rm committed the stale top into
// the root over every later guest write. Each step now refuses, or leaves
// the root's current data alone.
func TestMarkedLayer_SnapshotCreateStartAndRmNeverReachTheStaleData(t *testing.T) {
	m := newMarkedVM(t)
	ctx := adminCtx()

	// 1. Snapshot create refuses, naming the marker.
	_, err := m.s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "mk", Name: "x"})
	if err == nil || !strings.Contains(err.Error(), ".lv-merged") {
		t.Errorf("snapshot create on a VM whose chain holds a merged layer = %v; want a refusal naming the marker", err)
	}

	// 2. Say an overlay x got made over the stale top anyway (an earlier
	// build): the start check walks the whole chain and refuses.
	x := strings.TrimSuffix(m.top, filepath.Ext(m.top)) + ".x"
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", m.top, x)
	if _, err := m.fake.CreateSnapshot("mk", "x"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSnapshot(ctx, m.s.db, corrosion.SnapshotRecord{ID: "mk-x", VMName: "mk", HostName: m.s.hostName, Name: "x", State: "ok", Type: "disk"}); err != nil {
		t.Fatal(err)
	}
	m.definition(x)
	if err := m.s.verifyImageBasesForStart(ctx, &corrosion.VMRecord{Name: "mk", HostName: m.s.hostName}); err == nil {
		t.Error("a start whose chain passes through the merged layer was accepted")
	}

	// 3. Snapshot rm never merges through the marked layer into the root.
	before := len(m.fake.FlattenBases)
	if _, err := m.s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "mk", SnapshotName: "x"}); err != nil {
		t.Fatalf("DeleteSnapshot x: %v", err)
	}
	for _, b := range m.fake.FlattenBases[before:] {
		if b["vda"] != "" && b["vda"] != x {
			t.Errorf("merged into %s, through the marked layer %s", b["vda"], m.top)
		}
	}
	if got := guestView(t, m.root); !bytes.Equal(got, m.current) {
		t.Error("the root lost the guest's current data")
	}
}

// The record names where the data is: a clone of the marked VM reads the
// current data, never the stale layer.
func TestMarkedLayer_ACloneReadsTheCurrentData(t *testing.T) {
	m := newMarkedVM(t)
	disks, _ := corrosion.GetVMDisks(context.Background(), m.s.db, "mk")
	if len(disks) != 1 || disks[0].Path != m.root {
		t.Errorf("record %+v, want it moved to %s, where the data is", disks, m.root)
	}
	if _, err := m.s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "mk", Target: "mkc", Mode: "full"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	cd, _ := corrosion.GetVMDisks(context.Background(), m.s.db, "mkc")
	if len(cd) != 1 {
		t.Fatalf("clone disks %+v", cd)
	}
	if got := guestView(t, cd[0].Path); !bytes.Equal(got, m.current) {
		t.Error("the clone holds the stale layer's data, not the VM's current data")
	}
}

// A move of the marked VM's disk reads the current data, or refuses; it
// never copies the stale layer.
func TestMarkedLayer_AMoveNeverCopiesTheStaleLayer(t *testing.T) {
	m := newMarkedVM(t)
	fast := t.TempDir()
	registerPool(t, m.s, "fast", "dir", "", fast, "")
	err := m.s.MoveVolume(&pb.MoveVolumeRequest{VmName: "mk", DiskName: "root", TargetPool: "fast"},
		&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
	disks, _ := corrosion.GetVMDisks(context.Background(), m.s.db, "mk")
	if err != nil {
		if len(disks) != 1 || disks[0].Path != m.root {
			t.Fatalf("the move refused (%v) but the record %+v is not on the current data %s", err, disks, m.root)
		}
		return
	}
	if got := guestView(t, disks[0].Path); !bytes.Equal(got, m.current) {
		t.Error("the moved disk holds the stale layer's data, not the VM's current data")
	}
}

func runQemuIO(file, cmd string) ([]byte, error) {
	return exec.Command("qemu-io", "-f", "qcow2", "-c", cmd, file).CombinedOutput()
}
