// Fleet scenario (colonelpanik/litevirt#258): failover's automatic promotion
// recovers every disk of a VM that has a replica, not only its root.
//
// The VM runs on the victim with a root disk and three data disks, each
// holding its own bytes, and replicates to the replica host's pool over the
// real PushReplica RPC. The coordinator, a third node, fences the victim and
// promotes: it lists the replica host's replicas over a real peer call and
// relays the promotion there, where every disk with a replica is built into a
// live disk and attached. Only real nodes prove the other disks' replicas
// reach the replica host and that the relayed promotion finds them there.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// setDiskPatterns are the bytes each disk of the set holds at offset 0.
var setDiskPatterns = map[string]byte{"root": 0x11, "data1": 0x22, "data2": 0x33, "data3": 0x44}

// replicaSetVM puts VM vm on victim with a root disk and data1..data3, each a
// qcow2 holding its own pattern, and an auto-promote replication schedule
// into a "dr" pool on replicaHost. It returns the schedule.
func replicaSetVM(t *testing.T, c *Cluster, victim, replicaHost *Node, vm string) corrosion.BackupScheduleRecord {
	t.Helper()
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io not on PATH")
	}
	ctx := context.Background()
	dr := filepath.Join(c.tmpRoot, replicaHost.Name, "data", "dr")
	if err := os.MkdirAll(dr, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, replicaHost.DB, corrosion.StoragePoolRecord{
		HostName: replicaHost.Name, Name: "dr", Driver: "local", Target: dr, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	var disks []corrosion.DiskRecord
	for i, d := range []string{"root", "data1", "data2", "data3"} {
		p := filepath.Join(c.tmpRoot, victim.Name, vm+"-"+d+".qcow2")
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		cmd := fmt.Sprintf("write -P 0x%02x 0 65536", setDiskPatterns[d])
		if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", cmd, p).CombinedOutput(); err != nil {
			t.Fatalf("write %s: %v %s", d, err, out)
		}
		disks = append(disks, corrosion.DiskRecord{
			VMName: vm, DiskName: d, HostName: victim.Name, Path: p, SizeBytes: 1 << 20,
			StorageType: "local", TargetDev: fmt.Sprintf("vd%c", 'a'+i), Bus: "virtio",
		})
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: vm, Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, victim.DB, corrosion.VMRecord{
		Name: vm, HostName: victim.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, disks); err != nil {
		t.Fatal(err)
	}
	victim.Virt.SetState(vm, libvirtfake.StateRunning) // running: each copy is point-in-time (layer 2)
	sched := corrosion.BackupScheduleRecord{
		VMName: vm, Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: replicaHost.Name, KeepReplicas: 2, AutoPromote: true,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, victim.DB, sched); err != nil {
		t.Fatal(err)
	}
	return sched
}

// failVictim fences victim from coord, whose coordinator auto-promotes.
func failVictim(t *testing.T, coord, victim *Node, observers ...*Node) {
	t.Helper()
	ctx := context.Background()
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, o := range observers {
		if err := coord.DB.Execute(ctx, `INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', 5, NULL, ?)`, o.Name, victim.Name, nowRFC); err != nil {
			t.Fatal(err)
		}
	}
	fc := failover.NewCoordinator(coord.Name, coord.DB)
	fc.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "fleet-test", Success: true}
	})
	fc.Promoter = coord.Server
	fc.RunOnce(ctx)
}

// diskPattern reads the first 64 KiB of a qcow2 and reports whether it is
// pattern p throughout.
func diskPattern(t *testing.T, path string, p byte) bool {
	t.Helper()
	out := filepath.Join(t.TempDir(), "o.raw")
	if b, err := exec.Command("qemu-img", "convert", "-O", "raw", path, out).CombinedOutput(); err != nil {
		t.Fatalf("convert %s: %v %s", path, err, b)
	}
	got, _ := os.ReadFile(out)
	return len(got) >= 65536 && bytes.Equal(got[:65536], bytes.Repeat([]byte{p}, 65536))
}

// promotedDisks checks the promoted VM on host: every disk in want is attached
// at its own device, re-homed onto a live disk there that holds its own bytes;
// every disk in missing still names its real disk on victim and is not
// attached.
func promotedDisks(t *testing.T, c *Cluster, host, victim *Node, vm string, want, missing []string) {
	t.Helper()
	ctx := context.Background()
	xml := host.Virt.DefinedXML(vm)
	if xml == "" {
		t.Fatalf("%s was not promoted on %s", vm, host.Name)
	}
	rows, err := corrosion.GetVMDisks(ctx, host.DB, vm)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]corrosion.DiskRecord{}
	for _, r := range rows {
		byName[r.DiskName] = r
	}
	for _, d := range want {
		r := byName[d]
		if r.HostName != host.Name || !strings.Contains(xml, r.Path) || !strings.Contains(xml, `dev="`+r.TargetDev+`"`) {
			t.Errorf("disk %s not recovered on %s: row %+v", d, host.Name, r)
			continue
		}
		if !diskPattern(t, r.Path, setDiskPatterns[d]) {
			t.Errorf("disk %s on %s (%s) does not hold its own data", d, host.Name, r.Path)
		}
	}
	for _, d := range missing {
		r := byName[d]
		if r.HostName != victim.Name || r.Path != filepath.Join(c.tmpRoot, victim.Name, vm+"-"+d+".qcow2") {
			t.Errorf("missing disk %s row = %+v, want it still naming its real disk on %s", d, r, victim.Name)
		}
		if strings.Contains(xml, `dev="`+r.TargetDev+`"`) {
			t.Errorf("missing disk %s's device %s is attached", d, r.TargetDev)
		}
	}
}

// A complete set: failover recovers all four disks, each with its own data,
// and nothing is partial.
//
// Mutation "root-only promotion": doPromoteLocal recovers no other disk — red.
// Mutation "root-only replication": runVMReplication skips the other disks — red.
func TestFleet_AutoPromote_RecoversEveryDiskOfTheSet(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	victim, replicaHost, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	sched := replicaSetVM(t, c, victim, replicaHost, "set1")
	if err := victim.Server.RunReplication(ctx, sched, time.Now().Add(-5*time.Minute)); err != nil {
		t.Fatalf("replicate set1: %v", err)
	}

	failVictim(t, coord, victim, replicaHost, coord)

	promotedDisks(t, c, replicaHost, victim, "set1", []string{"root", "data1", "data2", "data3"}, nil)
	insp, err := c.SelfClient(coord).InspectVM(ctx, &pb.InspectVMRequest{Name: "set1"})
	if err != nil || insp.GetPromotedPartial() != "" {
		t.Errorf("inspect promoted_partial = %q (%v), want empty for a complete set", insp.GetPromotedPartial(), err)
	}
}

// An incomplete set — the run's copy of data3 failed — is still promoted, as
// main promoted the root: with every disk that has a replica, each with its
// own data, and data3 named, with where its real data is, in an event and lv
// inspect (the notification carries the event's text; the unit test
// TestPromote_AnIncompleteSetPromotesWhatItHasAndMarksThePartial sees it).
//
// Mutations: "refuse an incomplete set" (doPromoteLocal fails on a missing
// disk) — red, the VM is not promoted; "partial not reported" — red.
func TestFleet_AutoPromote_IncompleteSetRecoversWhatHasAReplicaAndNamesTheRest(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	victim, replicaHost, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	sched := replicaSetVM(t, c, victim, replicaHost, "set2")
	data3 := filepath.Join(c.tmpRoot, victim.Name, "set2-data3.qcow2")
	aside := data3 + ".aside"
	if err := os.Rename(data3, aside); err != nil {
		t.Fatal(err)
	}
	err := victim.Server.RunReplication(ctx, sched, time.Now().Add(-5*time.Minute))
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("a run whose data3 copy failed = %v, want it reported incomplete", err)
	}
	if err := os.Rename(aside, data3); err != nil { // the real disk is still there on the victim
		t.Fatal(err)
	}

	failVictim(t, coord, victim, replicaHost, coord)

	promotedDisks(t, c, replicaHost, victim, "set2", []string{"root", "data1", "data2"}, []string{"data3"})
	evs, _ := corrosion.ListVMEvents(ctx, coord.DB, "set2", 100, "")
	partial := ""
	for _, e := range evs {
		if e.Type == "vm.promoted_partial" {
			partial = e.Detail
			break
		}
	}
	if !strings.Contains(partial, "data3") || !strings.Contains(partial, victim.Name+" at "+data3) {
		t.Errorf("vm.promoted_partial = %q, want data3 named with its real disk on %s", partial, victim.Name)
	}
	for _, d := range []string{"data1", "data2"} {
		if strings.Contains(partial, d) {
			t.Errorf("vm.promoted_partial names %s, which was recovered: %s", d, partial)
		}
	}
	insp, err := c.SelfClient(coord).InspectVM(ctx, &pb.InspectVMRequest{Name: "set2"})
	if err != nil || !strings.Contains(insp.GetPromotedPartial(), "data3") {
		t.Errorf("inspect promoted_partial = %q (%v), want data3 named", insp.GetPromotedPartial(), err)
	}
}
