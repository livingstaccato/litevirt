package fleet

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The destructive lifecycle operations on a host in write quarantine.
//
// Each removes something on the host (a domain, disks, a root filesystem, a
// snapshot) and then records that on a replicated row, which the quarantine
// refuses. On 7a902203c `lv rebuild` deleted the VM's disks and left its row
// `running` (after the lift: `error`, "disk root is missing"); `lv ct rm`
// removed the container and left its row; `lv snapshot rm` merged the
// snapshot and answered OK with its row still listed; `lv ct snapshot rm`
// removed the file and kept the row; and a delete probing a quarantined peer
// for a VM's domain had that peer undefine it and free its disks under a row
// that stayed live. Each is now refused with FailedPrecondition, before
// anything changes, naming the quarantine and its remedy; once the
// quarantine lifts it works as before. `lv rm` itself was refused on
// 7a902203c too, but as Unavailable ("cannot take the start lease"), which
// reads as "retry", and `lv doctor repair-owner` as Internal.
//
// The file uses no symbol newer than 7a902203c, so it builds there, red.

// qlcVM creates name on n from the ubuntu image and returns its disk paths.
func qlcVM(t *testing.T, c *Cluster, n *Node, name string) []string {
	t.Helper()
	ctx := context.Background()
	if _, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name},
		Restart: &pb.RestartPolicy{Condition: "always", Delay: "1ms"}, Onboot: true}}); err != nil {
		t.Fatalf("CreateVM %s: %v", name, err)
	}
	disks, err := corrosion.GetVMDisks(ctx, n.DB, name)
	if err != nil || len(disks) == 0 {
		t.Fatalf("disks of %s: %v %v", name, disks, err)
	}
	var out []string
	for _, d := range disks {
		out = append(out, d.Path)
	}
	return out
}

// qlcRefused asserts err is the quarantine refusal: FailedPrecondition,
// naming the write quarantine, the remedy and that nothing was changed.
func qlcRefused(t *testing.T, what string, err error) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("%s under write quarantine: %v, want FailedPrecondition", what, err)
		return
	}
	msg := status.Convert(err).Message()
	for _, want := range []string{"write quarantine", qfsQuarantine, "reseed", "nothing was changed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%s refusal %q does not say %q", what, msg, want)
		}
	}
}

// qlcIntact asserts name's domain, disks and row are all still on n.
func qlcIntact(t *testing.T, n *Node, name string, disks []string, wantState string) {
	t.Helper()
	if !n.Virt.DomainExists(name) {
		t.Errorf("%s's domain is gone", name)
	}
	for _, p := range disks {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s's disk %s is gone: %v", name, p, err)
		}
	}
	vm := qfsRow(t, n, name)
	if vm == nil || vm.State != wantState {
		t.Errorf("%s's row is %+v, want %s", name, vm, wantState)
	}
}

func qlcGone(t *testing.T, n *Node, name string, disks []string) {
	t.Helper()
	if n.Virt.DomainExists(name) {
		t.Errorf("%s's domain survived its delete", name)
	}
	for _, p := range disks {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s's disk %s survived its delete", name, p)
		}
	}
	if vm := qfsRow(t, n, name); vm != nil {
		t.Errorf("%s's row survived its delete: %s", name, vm.State)
	}
}

func qlcCluster(t *testing.T) (*Cluster, *Node, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	importImageOn(t, c, n0, "ubuntu")
	importImageOn(t, c, n1, "ubuntu")
	return c, n0, n1
}

// `lv rm` of a VM on a quarantined host, whichever host it enters on, and
// with --force or --keep-disks, is refused with nothing changed; once the
// quarantine lifts it deletes.
//
// Mutation: drop the entry/owner refusal in deleteVM: the owner's cases are
// Unavailable again, and a quarantined entry forwards: red.
func TestFleet_QuarantinedDelete_RefusedWithNothingChanged(t *testing.T) {
	c, n0, n1 := qlcCluster(t)
	ctx := context.Background()
	stopped := qlcVM(t, c, n0, "stopped")
	if _, err := c.SelfClient(n0).StopVM(ctx, &pb.StopVMRequest{Name: "stopped"}); err != nil {
		t.Fatal(err)
	}
	forced := qlcVM(t, c, n0, "forced")
	kept := qlcVM(t, c, n0, "kept")
	fwd := qlcVM(t, c, n0, "fwd")
	other := qlcVM(t, c, n1, "other")
	eventually(t, 15*time.Second, "both nodes to see every VM", func() bool {
		a, _ := corrosion.GetVM(ctx, n1.DB, "fwd")
		b, _ := corrosion.GetVM(ctx, n0.DB, "other")
		return a != nil && b != nil
	})

	n0.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	for _, tc := range []struct {
		name  string
		entry *Node
		req   *pb.DeleteVMRequest
	}{
		{"stopped", n0, &pb.DeleteVMRequest{Name: "stopped"}},
		{"forced", n0, &pb.DeleteVMRequest{Name: "forced", Force: true}},
		{"kept", n0, &pb.DeleteVMRequest{Name: "kept", KeepDisks: true}},
		{"fwd", n1, &pb.DeleteVMRequest{Name: "fwd"}},
		// The quarantined host is the entry, the owner can write: the
		// entry records part of the delete (firewall tags, schedules).
		{"other", n0, &pb.DeleteVMRequest{Name: "other"}},
	} {
		_, err := c.SelfClient(tc.entry).DeleteVM(ctx, tc.req)
		qlcRefused(t, "delete "+tc.name, err)
		if tc.name == "other" && !strings.Contains(status.Convert(err).Message(), "run it from a host that is not in write quarantine") {
			t.Errorf("a quarantined entry's refusal %q does not say another host can take it", status.Convert(err).Message())
		}
	}
	qlcIntact(t, n0, "stopped", stopped, "stopped")
	qlcIntact(t, n0, "forced", forced, "running")
	qlcIntact(t, n0, "kept", kept, "running")
	qlcIntact(t, n0, "fwd", fwd, "running")
	qlcIntact(t, n1, "other", other, "running")

	n0.DB.SetWriteQuarantine(nil)
	for _, name := range []string{"stopped", "forced", "fwd"} {
		if _, err := c.SelfClient(n0).DeleteVM(ctx, &pb.DeleteVMRequest{Name: name, Force: true}); err != nil {
			t.Fatalf("delete %s after the lift: %v", name, err)
		}
	}
	qlcGone(t, n0, "stopped", stopped)
	qlcGone(t, n0, "forced", forced)
	qlcGone(t, n0, "fwd", fwd)
}

// A delete whose VM's row names a host without its domain probes its peers;
// a quarantined peer that has the domain refuses the probe before it acts,
// so the probing host keeps the record and the peer the domain and disks.
//
// Red on 7a902203c: the peer undefines the domain and frees the disks, then
// fails to tombstone its row.
//
// Mutation: drop the probe's refusal in deleteVM: the disks are freed: red.
func TestFleet_QuarantinedDelete_ProbedPeerKeepsTheVM(t *testing.T) {
	c, n0, n1 := qlcCluster(t)
	ctx := context.Background()
	disks := qlcVM(t, c, n1, "web")
	eventually(t, 15*time.Second, n0.Name+" to see web", func() bool {
		vm, err := corrosion.GetVM(ctx, n0.DB, "web")
		return err == nil && vm != nil
	})
	// n0's copy of the row says web is n0's; its domain is on n1.
	if err := localExec(ctx, n0.DB, `UPDATE vms SET host_name = ? WHERE name = 'web'`, n0.Name); err != nil {
		t.Fatal(err)
	}
	n1.DB.SetWriteQuarantine(func() string { return qfsQuarantine })

	_, err := c.SelfClient(n0).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web"})
	qlcRefused(t, "a delete probing the quarantined peer", err)
	qlcIntact(t, n1, "web", disks, "running")
	if vm := qfsRow(t, n0, "web"); vm == nil {
		t.Error("the probing host removed the record as stale")
	}
}

// `lv rebuild` on a quarantined host is refused before its teardown.
//
// Red on 7a902203c: the domain and disks are gone, the row still reads
// running, and after the lift the VM is in error with its disk missing.
//
// Mutation: drop RebuildVM's refusal: red.
func TestFleet_QuarantinedRebuild_RefusedWithNothingChanged(t *testing.T) {
	c, n0, n1 := qlcCluster(t)
	ctx := context.Background()
	disks := qlcVM(t, c, n0, "web")
	eventually(t, 15*time.Second, n1.Name+" to see web", func() bool {
		vm, _ := corrosion.GetVM(ctx, n1.DB, "web")
		return vm != nil
	})
	n0.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	for _, entry := range []*Node{n0, n1} {
		_, err := c.SelfClient(entry).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"})
		qlcRefused(t, "rebuild entering on "+entry.Name, err)
	}
	qlcIntact(t, n0, "web", disks, "running")

	n0.DB.SetWriteQuarantine(nil)
	if _, err := c.SelfClient(n0).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("rebuild after the lift: %v", err)
	}
	if vm := qfsRow(t, n0, "web"); vm == nil || vm.State != "running" {
		t.Errorf("after the rebuild the row is %+v, want running", vm)
	}
}

// `lv ct rm` on a quarantined host is refused before the container goes.
//
// Red on 7a902203c: the container is removed, its row stays live.
//
// Mutation: drop deleteContainer's refusal: red.
func TestFleet_QuarantinedContainerDelete_RefusedWithNothingChanged(t *testing.T) {
	c, n0, n1 := qlcCluster(t)
	ctx := context.Background()
	createContainer(t, c, n0, "ct1")
	createContainer(t, c, n1, "ct2")
	eventually(t, 15*time.Second, "both nodes to see both containers", func() bool {
		a, _ := corrosion.GetContainer(ctx, n1.DB, n0.Name, "ct1")
		b, _ := corrosion.GetContainer(ctx, n0.DB, n1.Name, "ct2")
		return a != nil && b != nil
	})
	n0.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	for _, tc := range []struct {
		entry *Node
		name  string
	}{{n0, "ct1"}, {n1, "ct1"}, {n0, "ct2"}} {
		_, err := c.SelfClient(tc.entry).DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: tc.name, Force: true})
		qlcRefused(t, "ct rm "+tc.name+" entering on "+tc.entry.Name, err)
		if tc.name == "ct2" && !strings.Contains(status.Convert(err).Message(), "run it from a host that is not in write quarantine") {
			t.Errorf("a quarantined entry's refusal %q does not say another host can take it", status.Convert(err).Message())
		}
	}
	if !n0.CT.Exists("ct1") || !n1.CT.Exists("ct2") {
		t.Errorf("a container was removed under the quarantine: ct1 %v, ct2 %v", n0.CT.Exists("ct1"), n1.CT.Exists("ct2"))
	}
	if r, _ := corrosion.GetContainer(ctx, n0.DB, n0.Name, "ct1"); r == nil {
		t.Error("ct1's row is gone")
	}

	n0.DB.SetWriteQuarantine(nil)
	if _, err := c.SelfClient(n0).DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: "ct1", Force: true}); err != nil {
		t.Fatalf("ct rm after the lift: %v", err)
	}
	if n0.CT.Exists("ct1") {
		t.Error("ct1 survived its delete after the lift")
	}
}

// `lv snapshot rm` and `lv ct snapshot rm` on a quarantined host are refused
// before the snapshot is merged or its file removed.
//
// Red on 7a902203c: the VM snapshot is merged in libvirt and the delete
// answers OK with its row still listed; the container snapshot's file is
// removed and its row kept.
//
// Mutation: drop either refusal: red.
func TestFleet_QuarantinedSnapshotDelete_RefusedWithNothingChanged(t *testing.T) {
	c, n0, _ := qlcCluster(t)
	ctx := context.Background()
	cl := c.SelfClient(n0)
	qlcVM(t, c, n0, "web")
	for _, s := range []string{"s1", "s2"} {
		if _, err := cl.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "web", Name: s}); err != nil {
			t.Fatalf("snapshot %s: %v", s, err)
		}
	}
	createContainer(t, c, n0, "ct1")
	if _, err := cl.SnapshotContainer(ctx, &pb.SnapshotContainerRequest{Name: "ct1", Snapshot: "cs1"}); err != nil {
		t.Fatalf("ct snapshot: %v", err)
	}
	cs, err := corrosion.GetContainerSnapshot(ctx, n0.DB, n0.Name, "ct1", "cs1")
	if err != nil || cs == nil || cs.Path == "" {
		t.Fatalf("ct1's snapshot row: %+v %v", cs, err)
	}
	if _, err := os.Stat(cs.Path); err != nil {
		t.Fatalf("ct1's snapshot file: %v", err)
	}

	n0.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	before := len(n0.Virt.EventLog())
	_, err = cl.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "web", SnapshotName: "s2"})
	qlcRefused(t, "snapshot rm", err)
	if ops := qfsOps(n0, "web", before); len(ops) != 0 {
		t.Errorf("libvirt ops on web under the quarantine: %v, want none", ops)
	}
	if snaps, _ := corrosion.ListSnapshots(ctx, n0.DB, "web"); len(snaps) != 2 {
		t.Errorf("web's snapshot rows: %d, want 2", len(snaps))
	}
	_, err = cl.DeleteContainerSnapshot(ctx, &pb.DeleteContainerSnapshotRequest{Name: "ct1", Snapshot: "cs1"})
	qlcRefused(t, "ct snapshot rm", err)
	if _, serr := os.Stat(cs.Path); serr != nil {
		t.Errorf("ct1's snapshot file is gone: %v", serr)
	}

	n0.DB.SetWriteQuarantine(nil)
	if _, err := cl.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "web", SnapshotName: "s2"}); err != nil {
		t.Fatalf("snapshot rm after the lift: %v", err)
	}
	if snaps, _ := corrosion.ListSnapshots(ctx, n0.DB, "web"); len(snaps) != 1 {
		t.Errorf("web's snapshot rows after the lift: %d, want 1", len(snaps))
	}
	if _, err := cl.DeleteContainerSnapshot(ctx, &pb.DeleteContainerSnapshotRequest{Name: "ct1", Snapshot: "cs1"}); err != nil {
		t.Fatalf("ct snapshot rm after the lift: %v", err)
	}
}

// `lv doctor repair-owner` on a quarantined host, and `lv restart` of a
// stopped VM there, are refused with FailedPrecondition naming the
// quarantine (on 7a902203c: Internal, "update owner: write refused" and
// "reserve capacity: write refused"). `lv restart` of a running VM still
// restarts it: its row says running before and after.
//
// Mutation: drop either refusal: the code is Internal again: red.
func TestFleet_QuarantinedRepairOwnerAndRestart(t *testing.T) {
	c, n0, n1 := qlcCluster(t)
	ctx := context.Background()
	qlcVM(t, c, n0, "web")
	stopped := qlcVM(t, c, n0, "stopped")
	if _, err := c.SelfClient(n0).StopVM(ctx, &pb.StopVMRequest{Name: "stopped"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, n1.Name+" to see web", func() bool {
		vm, _ := corrosion.GetVM(ctx, n1.DB, "web")
		return vm != nil
	})
	n0.DB.SetWriteQuarantine(func() string { return qfsQuarantine })

	for _, entry := range []*Node{n0, n1} {
		_, err := c.SelfClient(entry).RepairVMOwner(ctx, &pb.RepairVMOwnerRequest{Name: "web", Host: n0.Name})
		qlcRefused(t, "repair-owner entering on "+entry.Name, err)
	}

	_, err := c.SelfClient(n0).RestartVM(ctx, &pb.RestartVMRequest{Name: "stopped"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "write quarantine") {
		t.Errorf("restart of a stopped VM under write quarantine: %v, want FailedPrecondition naming it", err)
	}
	qlcIntact(t, n0, "stopped", stopped, "stopped")
	if st, _ := n0.Virt.DomainState("stopped"); st == "running" {
		t.Error("restart started a stopped VM under write quarantine")
	}

	before := len(n0.Virt.EventLog())
	if _, err := c.SelfClient(n0).RestartVM(ctx, &pb.RestartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("restart of a running VM under write quarantine: %v, want it restarted", err)
	}
	if ops := qfsOps(n0, "web", before); ops["destroy"] != 1 || ops["start"] != 1 {
		t.Errorf("libvirt ops of the restart: %v, want one destroy and one start", ops)
	}
}

// `lv resize-disk` on a quarantined host is refused before the disk grows.
// The recorded size is what refuses a later shrink, and a grow it did not
// record would let that shrink through.
//
// Red on 352316c2b: OK, with libvirt's block-resize on the running VM and
// the stopped VM's qcow2 grown, and both rows at the old size.
//
// Mutation: drop ResizeDisk's refusal: red.
func TestFleet_QuarantinedResizeDisk_RefusedWithNothingChanged(t *testing.T) {
	c, n0, n1 := qlcCluster(t)
	ctx := context.Background()
	qlcVM(t, c, n0, "run")
	qlcVM(t, c, n0, "stp")
	if _, err := c.SelfClient(n0).StopVM(ctx, &pb.StopVMRequest{Name: "stp"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, n1.Name+" to see run", func() bool {
		vm, _ := corrosion.GetVM(ctx, n1.DB, "run")
		return vm != nil
	})
	n0.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	for _, tc := range []struct {
		name  string
		entry *Node
	}{{"run", n0}, {"stp", n0}, {"run", n1}} {
		ds, err := corrosion.GetVMDisks(ctx, n0.DB, tc.name)
		if err != nil || len(ds) == 0 {
			t.Fatalf("disks of %s: %v %v", tc.name, ds, err)
		}
		fi0, err := os.Stat(ds[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		before := len(n0.Virt.EventLog())
		_, err = c.SelfClient(tc.entry).ResizeDisk(ctx, &pb.ResizeDiskRequest{VmName: tc.name, DiskName: ds[0].DiskName, Size: "50G"})
		qlcRefused(t, "resize-disk "+tc.name+" entering on "+tc.entry.Name, err)
		if ops := qfsOps(n0, tc.name, before); len(ops) != 0 {
			t.Errorf("libvirt ops on %s under the quarantine: %v, want none", tc.name, ops)
		}
		if fi1, _ := os.Stat(ds[0].Path); fi1 == nil || fi1.Size() != fi0.Size() {
			t.Errorf("%s's disk file changed size under the quarantine", tc.name)
		}
	}

	n0.DB.SetWriteQuarantine(nil)
	ds, _ := corrosion.GetVMDisks(ctx, n0.DB, "stp")
	if _, err := c.SelfClient(n0).ResizeDisk(ctx, &pb.ResizeDiskRequest{VmName: "stp", DiskName: ds[0].DiskName, Size: "50G"}); err != nil {
		t.Fatalf("resize-disk after the lift: %v", err)
	}
	if after, _ := corrosion.GetVMDisks(ctx, n0.DB, "stp"); len(after) == 0 || after[0].SizeBytes <= ds[0].SizeBytes {
		t.Errorf("the resize after the lift did not record the new size: %+v", after)
	}
}
