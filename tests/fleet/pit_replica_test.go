// Fleet scenario: a replica that is not point-in-time is marked as such on the
// host that RECEIVES it, and automatic promotion there holds the VM.
//
// The VM runs on node-0 and replicates to node-1's pool over the real
// PushReplica RPC. node-0 can make no point-in-time copy (its snapshot layer
// fails, and the fleet has no backup sessions), so it falls back to main's
// -U copy. The mark travels in the pushed record; the coordinator's
// promotion lists node-1's replicas over a real peer call, finds only a
// not-point-in-time one and holds the VM rather than relaying a promotion;
// an operator's promotion with the accept flag relays and runs on node-1.
// Only two real nodes prove the mark survives the wire and is read back on
// the other side.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Mutation "mark dropped on the receiver": PushReplica records the replica
// without NotPointInTime — red.
func TestFleet_NotPointInTimeReplicaIsMarkedAcrossHostsAndHeld(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	vmHost, replicaHost := c.Node("node-0"), c.Node("node-1")
	vmHost.Virt.SetPITFailures(errors.New("snapshot refused"), nil)
	vmHost.Virt.SetState("web", libvirtfake.StateRunning)
	dr := filepath.Join(c.tmpRoot, replicaHost.Name, "data", "dr")
	if err := os.MkdirAll(dr, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, replicaHost.DB, corrosion.StoragePoolRecord{
		HostName: replicaHost.Name, Name: "dr", Driver: "local", Target: dr, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(c.tmpRoot, vmHost.Name, "web-root.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, vmHost.DB, corrosion.VMRecord{
		Name: "web", HostName: vmHost.Name, State: "running", Spec: string(spec),
	}, nil, []corrosion.DiskRecord{{
		VMName: "web", DiskName: "root", HostName: vmHost.Name, Path: src, SizeBytes: 1 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatal(err)
	}
	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: replicaHost.Name, KeepReplicas: 2, AutoPromote: true,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, vmHost.DB, sched); err != nil {
		t.Fatal(err)
	}
	if err := vmHost.Server.RunReplication(ctx, sched, time.Now().Add(-5*time.Minute)); err != nil {
		t.Fatalf("replicate web to %s: %v", replicaHost.Name, err)
	}

	// The record on node-1 carries the mark.
	var marked []string
	_ = filepath.WalkDir(filepath.Join(dr, ".replicas"), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && strings.HasSuffix(p, ".json") {
			data, _ := os.ReadFile(p)
			var rec struct {
				File           string `json:"file"`
				NotPointInTime bool   `json:"not_point_in_time"`
			}
			if json.Unmarshal(data, &rec) == nil && rec.NotPointInTime {
				marked = append(marked, rec.File)
			}
		}
		return nil
	})
	if len(marked) != 1 {
		t.Fatalf("not-point-in-time records on %s = %v, want the one replica", replicaHost.Name, marked)
	}

	// Automatic promotion, seen from node-0, holds.
	err := vmHost.Server.AutoPromoteReplica(ctx, "web", "", 0)
	if err == nil || !strings.Contains(err.Error(), "--accept-not-point-in-time") {
		t.Fatalf("automatic promotion = %v, want it held with the manual command", err)
	}
	if replicaHost.Virt.DomainExists("web") {
		t.Fatal("web was promoted from a not-point-in-time replica")
	}

	// The operator's promotion with the flag relays and runs.
	st, err := c.SelfClient(vmHost).PromoteReplica(ctx, &pb.PromoteReplicaRequest{VmName: "web", Force: true, AcceptNotPointInTime: true})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
		if err == io.EOF {
			err = nil
		}
	}
	if err != nil {
		t.Fatalf("manual promotion with --accept-not-point-in-time: %v", err)
	}
	if !replicaHost.Virt.DomainExists("web") {
		t.Errorf("web was not promoted on %s", replicaHost.Name)
	}
}

// windowOverlay leaves, beside disk, the overlay of a layer-2 copy whose host
// died mid-window: a real qcow2 backed by the disk, holding a write (0x5a over
// 64 KiB at 64 KiB) the disk lacks.
func windowOverlay(t *testing.T, disk string, owner pitoverlay.Owner) {
	t.Helper()
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not on PATH")
	}
	if err := qcow2.CreateWithBackingFormat(pitoverlay.Path(disk), disk, "qcow2", 0, nil); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x5a 65536 65536", pitoverlay.Path(disk)).CombinedOutput(); err != nil {
		t.Fatalf("write into the overlay: %v %s", err, out)
	}
	if err := pitoverlay.Bind(disk, owner); err != nil {
		t.Fatal(err)
	}
}

func diskHoldsTheWindow(t *testing.T, disk string) bool {
	t.Helper()
	out := filepath.Join(t.TempDir(), "o.raw")
	if b, err := exec.Command("qemu-img", "convert", "-f", "qcow2", "-O", "raw", disk, out).CombinedOutput(); err != nil {
		t.Fatalf("convert %s: %v %s", disk, err, b)
	}
	got, _ := os.ReadFile(out)
	return len(got) >= 131072 && bytes.Equal(got[65536:131072], bytes.Repeat([]byte{0x5a}, 65536))
}

// C1 of the #256 review: a VM on a shared pool whose host died while a
// layer-2 copy had its writes on the overlay is restarted elsewhere WITH those
// writes. Nothing replicated names the overlay; its fixed name beside the
// disk is found by the target's define, which commits it into the disk before
// defining the domain on it — and never deletes it uncommitted.
//
// Mutation "define ignores the overlay": domainXMLFor's settle loop is
// removed — red (the target boots the disk without the window's writes).
func TestFleet_FailoverMidWindowKeepsTheWindowsWrites(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	latchPITOverlay(t, c)
	ctx := context.Background()
	target, victim, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	shared := filepath.Join(c.tmpRoot, "nfs")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(shared, "pw1-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	windowOverlay(t, disk, pitoverlay.Owner{VM: "pw1", Disk: "root"})
	if err := corrosion.InsertVM(ctx, coord.DB, corrosion.VMRecord{
		Name: "pw1", HostName: victim.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"pw1","cpu":1,"memory_mib":256,"on_host_failure":"restart-any","placement":{"host":"` + target.Name + `"}}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "pw1", DiskName: "root", HostName: victim.Name, Path: disk,
		SizeBytes: 1 << 20, StorageType: "nfs", StorageVolume: "nfs", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if got := fenceVictim(t, c, coord, victim, target, coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	if vm, _ := corrosion.GetVM(ctx, target.DB, "pw1"); vm == nil || vm.HostName != target.Name {
		t.Fatalf("pw1 after the failover = %+v, want it on %s", vm, target.Name)
	}
	rec := health.NewReconciler(target.Name, filepath.Join(c.tmpRoot, target.Name, "data"), target.DB, target.Virt)
	// As the daemon wires it: the target's own pit_overlay gate, open once
	// the release token has latched on every host.
	rec.SetPITOverlayFeature(target.Server.PITOverlayFeature)
	rec.ReconcileOnce(ctx)

	if !strings.Contains(target.Virt.DefinedXML("pw1"), disk) {
		t.Fatalf("pw1 was not defined on %s on its disk", target.Name)
	}
	if !diskHoldsTheWindow(t, disk) {
		t.Fatal("pw1 was started on its disk WITHOUT the writes the overlay held: they are lost")
	}
	if pitoverlay.Present(disk) {
		t.Error("the committed overlay is still beside the disk")
	}
}

// I7 of the #256 review: a VM whose only replica is not point-in-time and
// whose disk is host-local is HELD by failover — not rescheduled onto a host
// that cannot start it — the hold is visible, and the manual steps the hold
// prints work as printed, in order.
//
// A same-name promote needs its owner proven powered off (the split-brain
// guard). Fenced by a method that proves nothing, the hold names
// `lv host fence-confirm` first, and the promote alone is refused until it
// has run; fenced proof-grade, it names the promote alone, which works.
//
// Mutations: "held VMs are rescheduled" (the coordinator's holdsDown returns
// false) — red; the fence-confirm step dropped from the hold — the printed
// promote is refused, red.
func TestFleet_AHeldPromotionStaysDownAndItsCommandWorks(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		confirm      bool // the hold must name lv host fence-confirm first
	}{
		{"fence that proves nothing", "fleet-test", true},
		{"proof-grade fence", "ipmi", false},
	} {
		t.Run(tc.name, func(t *testing.T) { heldPromotionCommandsWork(t, tc.method, tc.confirm) })
	}
}

func heldPromotionCommandsWork(t *testing.T, fenceMethod string, wantConfirm bool) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	victim, replicaHost, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	victim.Virt.SetPITFailures(errors.New("snapshot refused"), nil)
	dr := filepath.Join(c.tmpRoot, replicaHost.Name, "data", "dr")
	if err := os.MkdirAll(dr, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, replicaHost.DB, corrosion.StoragePoolRecord{
		HostName: replicaHost.Name, Name: "dr", Driver: "local", Target: dr, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(c.tmpRoot, victim.Name, "hw-root.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "hw", Cpu: 1, MemoryMib: 256, OnHostFailure: "restart-any"})
	if err := corrosion.InsertVM(ctx, victim.DB, corrosion.VMRecord{
		Name: "hw", HostName: victim.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{
		VMName: "hw", DiskName: "root", HostName: victim.Name, Path: src, SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatal(err)
	}
	victim.Virt.SetState("hw", libvirtfake.StateRunning)
	sched := corrosion.BackupScheduleRecord{
		VMName: "hw", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: replicaHost.Name, KeepReplicas: 2, AutoPromote: true,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, victim.DB, sched); err != nil {
		t.Fatal(err)
	}
	if err := victim.Server.RunReplication(ctx, sched, time.Now().Add(-5*time.Minute)); err != nil {
		t.Fatalf("replicate hw: %v", err)
	}

	// The victim dies; the coordinator fences it and tries to promote.
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, o := range []*Node{replicaHost, coord} {
		if err := localExec(ctx, coord.DB, `INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', 5, NULL, ?)`, o.Name, victim.Name, nowRFC); err != nil {
			t.Fatal(err)
		}
	}
	c.Kill(victim) // it does not answer: it is down, and powered off
	fc := failover.NewCoordinator(coord.Name, coord.DB)
	fc.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: fenceMethod, Success: true}
	})
	fc.Promoter = coord.Server
	fc.RunOnce(ctx)

	vm, _ := corrosion.GetVM(ctx, coord.DB, "hw")
	if vm == nil || vm.HostName != victim.Name {
		t.Fatalf("hw after the failover = %+v, want it held on %s, not rescheduled", vm, victim.Name)
	}
	if replicaHost.Virt.DomainExists("hw") {
		t.Fatal("hw was promoted from a not-point-in-time replica")
	}
	evs, _ := corrosion.ListVMEvents(ctx, coord.DB, "hw", 50, "")
	var held string
	for _, e := range evs {
		if e.Type == "vm.failover.held" {
			held = e.Detail
			break
		}
	}
	if held == "" {
		t.Fatal("no vm.failover.held event")
	}
	inspected, err := c.SelfClient(coord).InspectVM(ctx, &pb.InspectVMRequest{Name: "hw"})
	if err != nil || !strings.Contains(inspected.GetFailoverHeld(), "not point-in-time") {
		t.Errorf("inspect failover_held = %q (%v), want the hold", inspected.GetFailoverHeld(), err)
	}
	if inspected.GetFailoverHeld() != held {
		t.Errorf("inspect failover_held = %q, want the hold's own text %q", inspected.GetFailoverHeld(), held)
	}

	// The commands the hold printed, run as printed, in order.
	i := strings.Index(held, "lv replication promote ")
	if i < 0 {
		t.Fatalf("the hold names no command: %s", held)
	}
	args := strings.Fields(strings.SplitN(held[i:], ". ", 2)[0])[3:]
	req := &pb.PromoteReplicaRequest{VmName: args[0]}
	for j := 1; j < len(args); j++ {
		switch args[j] {
		case "--pool":
			j++
			req.TargetPool = args[j]
		case "--host":
			j++
			req.TargetHost = args[j]
		case "--replica":
			j++
			req.Replica = args[j]
		case "--accept-not-point-in-time":
			req.AcceptNotPointInTime = true
		default:
			t.Fatalf("the printed command has a flag this test does not map: %s", args[j])
		}
	}
	promote := func() error {
		st, err := c.SelfClient(coord).PromoteReplica(ctx, req)
		if err == nil {
			for {
				if _, err = st.Recv(); err != nil {
					break
				}
			}
			if err == io.EOF {
				err = nil
			}
		}
		return err
	}
	k := strings.Index(held, "lv host fence-confirm ")
	if wantConfirm != (k >= 0 && k < i) {
		t.Fatalf("hold names fence-confirm before the promote = %v, want %v: %s", k >= 0 && k < i, wantConfirm, held)
	}
	if wantConfirm {
		// Run out of order, the promote is refused: the step is needed.
		if err := promote(); err == nil || !strings.Contains(err.Error(), "not proven powered off") {
			t.Fatalf("the printed promote before the printed fence-confirm = %v; want it refused, not proven off", err)
		}
		host := strings.TrimRight(strings.Fields(held[k:])[3], ",")
		// fencing_log is stamped to the second, and a fence and a
		// confirmation in the same second count as the weaker of the two
		// (corrosion.FenceRecordProvesOff): the operator confirms later.
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
		if _, err := c.SelfClient(coord).FenceHost(ctx,
			&pb.FenceHostRequest{Name: host, Confirmed: true, ConfirmManualOnly: true}); err != nil {
			t.Fatalf("the printed lv host fence-confirm %s failed: %v", host, err)
		}
	}
	if err := promote(); err != nil {
		t.Fatalf("the printed command %q failed: %v", held[i:], err)
	}
	if !replicaHost.Virt.DomainExists("hw") {
		t.Errorf("hw was not promoted on %s by the printed command", replicaHost.Name)
	}
}

// N1(c) of the #256 review, multi-node: the overlay a dead host left is NOT
// committed when the base has been written since — as when a host that knows
// nothing of overlays restarted the VM on the base mid-roll — and the VM is
// not started on the bare disk either: the target's define holds it.
//
// Mutations: "binding ignored" (CommitOffline's verdict check accepts any
// sidecar) and "define ignores a hold" (the reconciler defines past a Held
// settle) — red.
func TestFleet_AnOverlayIsNeverCommittedOverABaseWrittenSince(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	latchPITOverlay(t, c)
	ctx := context.Background()
	target, victim, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	shared := filepath.Join(c.tmpRoot, "nfs")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(shared, "pw2-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	windowOverlay(t, disk, pitoverlay.Owner{VM: "pw2", Disk: "root"})
	time.Sleep(10 * time.Millisecond)
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write -P 0x33 65536 65536", disk).CombinedOutput(); err != nil {
		t.Fatalf("write the base: %v %s", err, out)
	}
	if err := corrosion.InsertVM(ctx, coord.DB, corrosion.VMRecord{
		Name: "pw2", HostName: victim.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"pw2","cpu":1,"memory_mib":256,"on_host_failure":"restart-any","placement":{"host":"` + target.Name + `"}}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "pw2", DiskName: "root", HostName: victim.Name, Path: disk,
		SizeBytes: 1 << 20, StorageType: "nfs", StorageVolume: "nfs", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if got := fenceVictim(t, c, coord, victim, target, coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	rec := health.NewReconciler(target.Name, filepath.Join(c.tmpRoot, target.Name, "data"), target.DB, target.Virt)
	// As the daemon wires it: a hold is a durable, per-disk condition, and
	// the target's own pit_overlay gate (open: the verdict decides).
	rec.SetPITOverlayReporter(target.Server.ReportPITOverlayHeld, target.Server.ClearPITOverlayHold)
	rec.SetPITOverlayFeature(target.Server.PITOverlayFeature)
	rec.ReconcileOnce(ctx)

	if diskHoldsTheWindow(t, disk) {
		t.Fatal("the stale overlay was committed over the base written since")
	}
	if !pitoverlay.Present(disk) {
		t.Fatal("the held overlay was moved or removed")
	}
	if target.Virt.DomainExists("pw2") {
		t.Fatal("pw2 was defined on its bare disk while an overlay it cannot verify may hold its writes")
	}
	evs, _ := corrosion.ListVMEvents(ctx, target.DB, "pw2", 50, "")
	held := false
	for _, e := range evs {
		held = held || (e.Type == "disk.pit_overlay_held" && strings.Contains(e.Detail, "lv resolve-pit-overlay pw2 root"))
	}
	if !held {
		t.Error("the hold was not reported with the admin command")
	}

	// N4 of round 4: the hold is a degraded condition, per disk, that every
	// node reads — here the coordinator — and lv inspect shows from it.
	row, found, err := corrosion.GetHealthCondition(ctx, coord.DB, "pit_overlay", "pit_overlay.held", "disk", "pw2/root")
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved || row.Severity != corrosion.SeverityWarning {
		t.Fatalf("held condition seen from %s = %+v (found %v, %v), want an open warning", coord.Name, row, found, err)
	}
	insp, err := c.SelfClient(coord).InspectVM(ctx, &pb.InspectVMRequest{Name: "pw2"})
	if err != nil || !strings.Contains(insp.GetPitOverlayHeld(), "lv resolve-pit-overlay pw2 root") {
		t.Fatalf("inspect from %s: %q, %v; want the hold", coord.Name, insp.GetPitOverlayHeld(), err)
	}

	// The hold clears when the overlay is gone (here an operator removed it
	// by hand): the reconciler's next define of the VM (its start re-armed)
	// settles nothing and resolves it.
	if err := pitoverlay.Remove(disk); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateVMState(ctx, target.DB, "pw2", "pending", "re-armed"); err != nil {
		t.Fatal(err)
	}
	rec.ReconcileOnce(ctx)
	if row, _, _ := corrosion.GetHealthCondition(ctx, coord.DB, "pit_overlay", "pit_overlay.held", "disk", "pw2/root"); row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the held condition did not resolve once the overlay was gone: %+v", row)
	}
}
