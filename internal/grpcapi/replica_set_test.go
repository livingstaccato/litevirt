package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// setPromoteVM gives vm, on a dead host, a root disk and the data disks
// named, each at its own target device, and a "dr" pool on this host. It
// returns the pool's directory.
func setPromoteVM(t *testing.T, s *Server, vm string, data map[string]string) string {
	t.Helper()
	ctx := context.Background()
	s.virt = libvirtfake.New()
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"dr": {Driver: "local", Target: poolDir}})
	spec, _ := json.Marshal(&pb.VMSpec{Name: vm, Cpu: 1, MemoryMib: 256})
	disks := []corrosion.DiskRecord{{
		VMName: vm, DiskName: "root", HostName: "dead-host", Path: "/dead/" + vm + "-root.qcow2",
		SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda", Bus: "virtio",
	}}
	devs := []string{"vdb", "vdc", "vdd", "vde"}
	names := make([]string, 0, len(data))
	for n := range data {
		names = append(names, n)
	}
	slices.Sort(names)
	for i, n := range names {
		disks = append(disks, corrosion.DiskRecord{
			VMName: vm, DiskName: n, HostName: "dead-host", Path: "/dead/" + vm + "-" + n + ".qcow2",
			SizeBytes: 1 << 20, StorageType: data[n], TargetDev: devs[i], Bus: "virtio",
		})
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: vm, HostName: "dead-host", State: "running", Spec: string(spec),
	}, nil, disks); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	return poolDir
}

func promoteSet(t *testing.T, s *Server, req *pb.PromoteReplicaRequest) {
	t.Helper()
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}
	if err := s.PromoteReplica(req, stream); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}
}

func diskRowsOf(t *testing.T, s *Server, vm string) map[string]corrosion.DiskRecord {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), s.db, vm)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]corrosion.DiskRecord{}
	for _, d := range disks {
		out[d.DiskName] = d
	}
	return out
}

func eventDetail(t *testing.T, s *Server, vm, typ string) string {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, vm, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Type == typ {
			return e.Detail
		}
	}
	return ""
}

// A promotion recovers every disk that has a replica, not only the root:
// each on its own target device, each disk row re-homed onto its live disk.
// The set is complete, so nothing is partial.
//
// Mutation "root-only promotion": doPromoteLocal recovers no other disk — red.
func TestPromote_RecoversEveryDiskOfACompleteSet(t *testing.T) {
	s := testServer(t)
	seen := seenNotifications(s)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local", "data2": "local"})
	run := "20260101-000000"
	for _, d := range []string{"root", "data1", "data2"} {
		seedReplica(t, poolDir, "", "db", d, run, "raw", 1<<20)
	}

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})

	xml := s.virt.(*libvirtfake.Fake).DefinedXML("db")
	rows := diskRowsOf(t, s, "db")
	for _, d := range []string{"root", "data1", "data2"} {
		r := rows[d]
		if r.HostName != s.hostName || !strings.HasPrefix(r.Path, poolDir) {
			t.Errorf("disk %s row = %+v, want it re-homed onto a live disk in the pool here", d, r)
		}
		if !strings.Contains(xml, r.Path) {
			t.Errorf("the promoted domain has no disk %s (%s)", d, r.Path)
		}
	}
	for _, dev := range []string{"vda", "vdb", "vdc"} {
		if !strings.Contains(xml, `dev="`+dev+`"`) {
			t.Errorf("the promoted domain has no %s", dev)
		}
	}
	manifest := eventDetail(t, s, "db", "vm.promoted")
	for _, want := range []string{"root ← root-" + run, "data1 ← data1-" + run, "data2 ← data2-" + run} {
		if !strings.Contains(manifest, want) {
			t.Errorf("manifest %q lacks %q", manifest, want)
		}
	}
	if d := eventDetail(t, s, "db", vmEventPromotedPartial); d != "" {
		t.Errorf("a complete set was reported partial: %s", d)
	}
	if hasNotification(seen, "replication.promoted_partial") {
		t.Error("a complete set notified partial")
	}
	pbVM, err := s.vmToProto(context.Background(), "db")
	if err != nil || pbVM.PromotedPartial != "" {
		t.Errorf("inspect promoted_partial = %q (%v), want empty", pbVM.GetPromotedPartial(), err)
	}
}

// An incomplete set still promotes — main's automatic recovery is never
// refused — with every disk that has a replica: a disk the root's run did not
// copy comes from its newest earlier replica, and one with none is named,
// with where its real data is. The VM is marked partial: an event, a
// notification, and lv inspect.
//
// Mutations: "partial not reported" (reportPromotedPartial skipped) — red;
// "inspect blind" (vmToProto does not set PromotedPartial) — red;
// "earlier run refused" (chooseSetReplicas takes only the root's run) — red.
func TestPromote_AnIncompleteSetPromotesWhatItHasAndMarksThePartial(t *testing.T) {
	s := testServer(t)
	seen := seenNotifications(s)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local", "data2": "local", "data3": "local", "data4": "ceph"})
	run, earlier := "20260101-000000", "20251231-000000"
	seedReplica(t, poolDir, "", "db", "root", run, "raw", 1<<20)
	seedReplica(t, poolDir, "", "db", "data1", run, "raw", 1<<20)
	seedReplica(t, poolDir, "", "db", "data2", earlier, "raw", 1<<20)

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})

	xml := s.virt.(*libvirtfake.Fake).DefinedXML("db")
	rows := diskRowsOf(t, s, "db")
	for _, d := range []string{"root", "data1", "data2"} {
		if rows[d].HostName != s.hostName || !strings.Contains(xml, rows[d].Path) {
			t.Errorf("disk %s was not recovered: row %+v", d, rows[d])
		}
	}
	for _, d := range []string{"data3", "data4"} {
		if rows[d].HostName != "dead-host" || rows[d].Path != "/dead/db-"+d+".qcow2" {
			t.Errorf("missing disk %s row = %+v, want it still naming its real disk on dead-host", d, rows[d])
		}
		if strings.Contains(xml, `dev="`+rows[d].TargetDev+`"`) {
			t.Errorf("the domain has a device at missing disk %s's target %s", d, rows[d].TargetDev)
		}
	}
	partial := eventDetail(t, s, "db", vmEventPromotedPartial)
	for _, want := range []string{"data3 (it has no replica", "dead-host at /dead/db-data3.qcow2", "data4 (shared (ceph) at /dead/db-data4.qcow2, not attached", "data2 (from the run of " + earlier} {
		if !strings.Contains(partial, want) {
			t.Errorf("partial event %q lacks %q", partial, want)
		}
	}
	if strings.Contains(partial, "data1") {
		t.Errorf("partial event names data1, which the root's run recovered: %s", partial)
	}
	if !hasNotification(seen, "replication.promoted_partial") {
		t.Error("no replication.promoted_partial notification")
	}
	pbVM, err := s.vmToProto(context.Background(), "db")
	if err != nil || !strings.Contains(pbVM.GetPromotedPartial(), "data3") {
		t.Errorf("inspect promoted_partial = %q (%v), want the missing disks", pbVM.GetPromotedPartial(), err)
	}
}

// A disk replica newer than the root's run is never taken: an operator who
// named an older root replica chose that point in time.
//
// Mutation "newest anywhere": chooseSetReplicas drops the rootTaken bound — red.
func TestPromote_NeverTakesADiskReplicaNewerThanTheRoots(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	old, newer := "20260101-000000", "20260102-000000"
	rootOld := seedReplica(t, poolDir, "", "db", "root", old, "raw", 1<<20)
	seedReplica(t, poolDir, "", "db", "root", newer, "raw", 1<<20)
	seedReplica(t, poolDir, "", "db", "data1", newer, "raw", 1<<20)

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Replica: rootOld})

	if r := diskRowsOf(t, s, "db")["data1"]; r.HostName != "dead-host" {
		t.Errorf("data1 = %+v: recovered from a replica newer than the root's", r)
	}
	if p := eventDetail(t, s, "db", vmEventPromotedPartial); !strings.Contains(p, "data1") {
		t.Errorf("partial = %q, want data1 named", p)
	}
}

// A disk whose live disk cannot be built — here its replica is not a qcow2 it
// claims to be — does not stop the promotion: the VM comes up with the rest
// and the disk is named.
//
// Mutation "a build failure refuses": doPromoteLocal returns the data disk's
// build error — red.
func TestPromote_ADiskThatCannotBeBuiltIsNamedNotFatal(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	run := "20260101-000000"
	seedReplica(t, poolDir, "", "db", "root", run, "raw", 1<<20)
	seedReplica(t, poolDir, "", "db", "data1", run, "qcow2", 4096) // zeros: no qcow2 header

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true})

	if rows := diskRowsOf(t, s, "db"); rows["root"].HostName != s.hostName || rows["data1"].HostName != "dead-host" {
		t.Errorf("rows = %+v, want root recovered and data1 left naming its real disk", rows)
	}
	if p := eventDetail(t, s, "db", vmEventPromotedPartial); !strings.Contains(p, "data1 (its replica data1-"+run+".qcow2 could not be built") {
		t.Errorf("partial = %q, want data1 named with the build failure", p)
	}
}

// M7: a file already where a disk's live disk would go — a crashed earlier
// attempt's, or anyone's — is neither removed nor reused nor fatal: the live
// disk is built beside it and the disk is recovered.
//
// Mutation "debris refuses": the fresh-name fallback is removed — red (data1
// is not recovered).
func TestPromote_DebrisWhereALiveDiskGoesIsLeftAndBuiltBeside(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	run := "20260101-000000"
	for _, d := range []string{"root", "data1"} {
		seedReplica(t, poolDir, "", "db", d, run, "raw", 1<<20)
	}
	inTheWay := filepath.Join(poolDir, "db-promoted-data1-"+run+".qcow2")
	if err := os.WriteFile(inTheWay, []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})

	r := diskRowsOf(t, s, "db")["data1"]
	if r.HostName != s.hostName || r.Path == inTheWay || !strings.HasPrefix(r.Path, poolDir) {
		t.Errorf("data1 = %+v, want it recovered beside the file in the way", r)
	}
	if p := eventDetail(t, s, "db", vmEventPromotedPartial); p != "" {
		t.Errorf("partial = %q, want a complete promotion", p)
	}
	if b, err := os.ReadFile(inTheWay); err != nil || string(b) != "someone else's" {
		t.Errorf("the file in the way was touched: %q, %v", b, err)
	}
}

// A renamed promotion writes every recovered disk into the new VM's rows.
//
// Mutation "renamed root-only": the other disks are not appended to
// diskRecords — red.
func TestPromote_RenamedCarriesEveryRecoveredDisk(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	for _, d := range []string{"root", "data1"} {
		seedReplica(t, poolDir, "", "db", d, "20260101-000000", "raw", 1<<20)
	}
	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", NewName: "db2", TargetPool: "dr", NoLocalize: true})
	rows := diskRowsOf(t, s, "db2")
	if len(rows) != 2 || rows["data1"].TargetDev != "vdb" || rows["data1"].HostName != s.hostName {
		t.Fatalf("db2 disks = %+v, want root and data1 at vdb", rows)
	}
}

// One run replicates every disk of the VM with one run time, and a disk
// replication cannot copy is reported, not silently absent. Nothing is
// written at the pool's top level: every replica is in the replica area.
//
// Mutation: "root only" (runVMReplication skips replicateOtherDisks) — red.
func TestReplication_OneRunReplicatesTheWholeSet(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	dir := replicaPoolDir(t, s, "dr")
	srcDir := t.TempDir()
	var disks []corrosion.DiskRecord
	for i, d := range []string{"root", "data1", "data2"} {
		p := filepath.Join(srcDir, d+".qcow2")
		if err := qcow2.Create(p, uint64(i+1)<<20, nil); err != nil {
			t.Fatal(err)
		}
		st := "dir"
		if d == "data2" {
			st = "ceph"
		}
		disks = append(disks, corrosion.DiskRecord{VMName: "set1", HostName: s.hostName, DiskName: d, Path: p, StorageType: st})
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "set1", HostName: s.hostName, State: "stopped", Spec: `{}`}, nil, disks); err != nil {
		t.Fatal(err)
	}
	sched := corrosion.BackupScheduleRecord{VMName: "set1", Repo: "dr", Type: "replication", TargetPool: "dr", TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 3}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.RunReplication(ctx, sched, at); err != nil {
		t.Fatalf("RunReplication: %v", err)
	}
	recs, err := listReplicaRecords(dir, "", "set1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range recs {
		got[r.Disk] = r.Taken
	}
	want := at.Format("20060102-150405")
	if got["root"] != want || got["data1"] != want {
		t.Fatalf("replicas = %v, want root and data1 at %s", got, want)
	}
	if _, ok := got["data2"]; ok {
		t.Fatalf("data2, on ceph, was replicated: %v", got)
	}
	if info, err := qcow2.Info(filepath.Join(replicaOwnerDir(dir, "", "set1"), "data1-"+want+".qcow2")); err != nil || info.VirtualSize != 2<<20 {
		t.Errorf("data1's replica = %+v, %v; want data1's 2 MiB", info, err)
	}
	skipped := false
	evs, _ := corrosion.ListVMEvents(ctx, s.db, "set1", 100, "")
	for _, e := range evs {
		skipped = skipped || (e.Type == "disk.replicated" && e.Result == "skipped" && strings.Contains(e.Detail, "data2"))
	}
	if !skipped {
		t.Error("data2 was skipped silently")
	}
	top, _ := os.ReadDir(dir)
	for _, e := range top {
		if strings.HasPrefix(e.Name(), "set1-") {
			t.Errorf("a replica was written at the pool's top level: %s", e.Name())
		}
	}
}
