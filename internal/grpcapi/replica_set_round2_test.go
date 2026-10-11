package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// N1/N6/R2-I1: every branch of the shared-disk reattach verdict. Each case
// removed from sharedReattachVerdict turns a row here red.
func TestSharedReattachVerdict_EveryBranch(t *testing.T) {
	host := func(state string) *corrosion.HostRecord { return &corrosion.HostRecord{Name: "old", State: state} }
	for _, c := range []struct {
		name                  string
		renamed, auto, proven bool
		owner                 string
		h                     *corrosion.HostRecord
		herr                  error
		want                  bool
	}{
		{"renamed, owner fenced", true, false, false, "old", host("fenced"), nil, false},
		{"renamed, fence proven", true, true, true, "old", host("fenced"), nil, false},
		{"fence proven, owner maintenance", false, true, true, "old", host("maintenance"), nil, true},
		{"fence proven, owner active", false, false, true, "old", host("active"), nil, true},
		{"automated, no fence proven, owner fenced", false, true, false, "old", host("fenced"), nil, false},
		{"automated, no fence proven, owner maintenance", false, true, false, "old", host("maintenance"), nil, false},
		{"unproven, owner is this host", false, false, false, "self", nil, nil, true},
		{"unproven, no owner", false, false, false, "", nil, nil, true},
		{"unproven, owner unreadable", false, false, false, "old", nil, errors.New("db down"), false},
		{"unproven, owner no longer a member", false, false, false, "old", nil, nil, true},
		{"unproven, owner removed", false, false, false, "old", host("removed"), nil, true},
		{"unproven, owner fenced", false, false, false, "old", host("fenced"), nil, true},
		{"unproven, owner maintenance", false, false, false, "old", host("maintenance"), nil, false},
		{"unproven, owner offline", false, false, false, "old", host("offline"), nil, false},
		{"unproven, owner active", false, false, false, "old", host("active"), nil, false},
	} {
		got, why := sharedReattachVerdict(c.renamed, c.auto, c.proven, c.owner, "self", c.h, c.herr)
		if got != c.want {
			t.Errorf("%s: reattach = %v (%s), want %v", c.name, got, why, c.want)
		}
		if !got && why == "" {
			t.Errorf("%s: refused with no reason", c.name)
		}
	}
}

// nfsPromoteVM is a VM on a dead host with a root and an NFS data1 that is
// reachable here, with a replica of the root. It returns the NFS file.
func nfsPromoteVM(t *testing.T, s *Server, ownerState string) string {
	t.Helper()
	nfsDisk := filepath.Join(t.TempDir(), "db-data1.qcow2")
	if err := os.WriteFile(nfsDisk, []byte("current data"), 0o600); err != nil {
		t.Fatal(err)
	}
	poolDir := setPromoteVMRows(t, s, "db", []corrosion.DiskRecord{
		{DiskName: "data1", HostName: "dead-host", Path: nfsDisk, SizeBytes: 1 << 20, StorageType: "nfs", StorageVolume: "nfs1", TargetDev: "vdb", Bus: "virtio"},
	})
	if ownerState != "" {
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "dead-host", Address: "10.0.0.9", State: ownerState}); err != nil {
			t.Fatal(err)
		}
	}
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	return nfsDisk
}

func assertSharedUnattached(t *testing.T, s *Server, nfsDisk, reason string) {
	t.Helper()
	if r := diskRowsOf(t, s, "db")["data1"]; r.Path != nfsDisk || r.HostName != "dead-host" {
		t.Errorf("data1 row = %+v, want it untouched", r)
	}
	if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); xml == "" || strings.Contains(xml, nfsDisk) {
		t.Errorf("want the VM promoted without the shared disk; domain: %q", xml)
	}
	if p := eventDetail(t, s, "db", vmEventPromotedPartial); !strings.Contains(p, reason) {
		t.Errorf("partial = %q, want %q", p, reason)
	}
}

// N1: a manual promotion whose owner is in maintenance — not fenced — leaves
// the shared disk unattached and says why; one whose owner is fenced
// reattaches it.
func TestPromote_ManualSharedReattachNeedsAFencedOwner(t *testing.T) {
	s := testServer(t)
	nfsDisk := nfsPromoteVM(t, s, "maintenance")
	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})
	assertSharedUnattached(t, s, nfsDisk, "its owner dead-host is maintenance, not fenced")

	s2 := testServer(t)
	nfs2 := nfsPromoteVM(t, s2, "fenced")
	promoteSet(t, s2, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})
	if xml := s2.virt.(*libvirtfake.Fake).DefinedXML("db"); !strings.Contains(xml, nfs2) {
		t.Errorf("a fenced owner's shared disk was not reattached: %s", xml)
	}
}

// N1: an automatic promotion with enforcement.shared_storage_fence off (no
// proof-grade fence) leaves the shared disk unattached, even with the owner
// fenced: main's outcome.
func TestAutoPromote_SharedDiskNeedsTheSharedStorageFence(t *testing.T) {
	s := testServer(t)
	nfsDisk := nfsPromoteVM(t, s, "fenced")
	if err := corrosion.UpsertBackupSchedule(context.Background(), s.db, corrosion.BackupScheduleRecord{
		VMName: "db", Repo: "dr", Type: "replication", TargetPool: "dr",
		TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 3, AutoPromote: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AutoPromoteReplica(context.Background(), "db", "", 0); err != nil {
		t.Fatalf("AutoPromoteReplica: %v", err)
	}
	assertSharedUnattached(t, s, nfsDisk, "no proof-grade fence of dead-host")
}

// N6/N8: a renamed promotion never attaches the original's shared disk, and
// says it belongs to the original and must not be attached to the copy.
func TestPromote_RenamedNeverTakesTheOriginalsSharedDisk(t *testing.T) {
	s := testServer(t)
	nfsDisk := nfsPromoteVM(t, s, "fenced")
	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", NewName: "db2", TargetPool: "dr", NoLocalize: true})
	if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db2"); xml == "" || strings.Contains(xml, nfsDisk) {
		t.Errorf("db2 took db's shared disk: %q", xml)
	}
	if p := eventDetail(t, s, "db2", vmEventPromotedPartial); !strings.Contains(p, "it belongs to the original VM db and must not be attached to db2") {
		t.Errorf("partial = %q, want the renamed wording", p)
	}
}

// N2: a shared disk whose path does not answer (a hung NFS mount) is given up
// on after a deadline; the promotion completes without it.
//
// Mutation "unbounded stat": statWithin waits for the stat — red (the test's
// guard fires).
func TestPromote_AHungSharedPathTimesOut(t *testing.T) {
	s := testServer(t)
	nfsDisk := nfsPromoteVM(t, s, "fenced")
	release := make(chan struct{})
	defer close(release)
	prevStat, prevTimeout := statShared, sharedDiskStatTimeout
	statShared = func(string) (os.FileInfo, error) { <-release; return nil, errors.New("released") }
	sharedDiskStatTimeout = 50 * time.Millisecond
	t.Cleanup(func() { statShared, sharedDiskStatTimeout = prevStat, prevTimeout })

	done := make(chan struct{})
	go func() {
		defer close(done)
		promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the promotion hung on a shared disk's path")
	}
	assertSharedUnattached(t, s, nfsDisk, "not reachable (timed out")
}

// N3: an admin-named root replica with no run time in its name takes no
// other disk's replica — not one estimated from the file's mtime.
//
// Mutation "mtime estimate": the root's run time falls back to the file's
// mtime — red.
func TestPromote_AnUnstampedRootTakesNoOtherReplica(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	named := filepath.Join(poolDir, "root-copy.raw")
	if err := os.WriteFile(named, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	seedReplica(t, poolDir, "", "db", "data1", "20200101-000000", "raw", 1<<20) // older than the file's mtime
	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Replica: "root-copy.raw"})
	if r := diskRowsOf(t, s, "db")["data1"]; r.HostName != "dead-host" {
		t.Errorf("data1 = %+v: matched to a root replica with no run time", r)
	}
	if p := eventDetail(t, s, "db", vmEventPromotedPartial); !strings.Contains(p, "run time is unknown") {
		t.Errorf("partial = %q, want data1 named for the unknown run time", p)
	}
}

// N4/R2-m2: the build step names the file the proof built and the replica
// it was built from; a retry reuses that file only for that replica.
//
// Mutations: "path unchecked" (builtStepPath accepts a path) — red; "source
// ignored" (builtStepPath drops the replica) — red.
func TestBuiltStepPath(t *testing.T) {
	steps := "disk_built started " + builtStep("data1", "db-promoted-data1-x-abc.qcow2", "data1-x.qcow2")
	if file, from, ok := builtStepPath(steps, "data1"); !ok || file != "db-promoted-data1-x-abc.qcow2" || from != "data1-x.qcow2" {
		t.Errorf("builtStepPath = %q, %q, %v", file, from, ok)
	}
	for _, bad := range []string{"disk_built:data1", "disk_built:data1=", "disk_built:data1=f", "disk_built:data1=../x,r",
		"disk_built:data1=f,../r", "disk_built:data10=y,r"} {
		if file, from, ok := builtStepPath(bad, "data1"); ok {
			t.Errorf("builtStepPath(%q) = %q, %q, want none", bad, file, from)
		}
	}
}

// N5: the partial marker goes with a deleted VM, and a VM re-created under
// the name never inherits an earlier one's.
//
// Mutations: "delete keeps it" (DeleteVM does not clear) — red; "inherited"
// (promotedPartialReason ignores created_at) — red.
func TestPromote_ThePartialMarkerGoesWithItsVM(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "pm", HostName: s.hostName, State: "stopped", Spec: `{}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	s.reportPromotedPartial(ctx, "pm", s.hostName, "partial recovery: not recovered: data1")
	if s.promotedPartialReason(ctx, "pm") == "" {
		t.Fatal("no marker raised")
	}
	if err := s.db.Execute(ctx, `UPDATE vms SET created_at = '2099-01-01T00:00:00Z' WHERE name = 'pm'`); err != nil {
		t.Fatal(err)
	}
	if r := s.promotedPartialReason(ctx, "pm"); r != "" {
		t.Errorf("a re-created VM inherited the marker: %q", r)
	}

	s2 := testServer(t)
	s2.virt = libvirtfake.New()
	if err := corrosion.InsertVM(ctx, s2.db, corrosion.VMRecord{Name: "pm", HostName: s2.hostName, State: "stopped", Spec: `{}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	s2.reportPromotedPartial(ctx, "pm", s2.hostName, "partial recovery: not recovered: data1")
	if _, err := s2.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "pm"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s2.db, promotedPartialEvaluator, promotedPartialCode, promotedPartialKind, "pm")
	if err != nil || !found || row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("marker after delete = %+v (found %v, %v), want resolved", row, found, err)
	}
}

// N7: a VM that left this host while the lock was dropped (here, between the
// root's run and data1's copy) is not copied any further: no -U copy of a
// source this host no longer runs, and the run's remaining disks are not
// tried.
//
// Mutations: "no recheck on taking the lock" (acquireHere does not call
// vmStillHere) — red; "keep going" (the break on errVMNoLongerHere removed)
// — red.
func TestOtherDiskCopy_AVMThatLeftIsNotCopiedFurther(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	f := libvirtfake.New()
	s.virt = f
	replicaPoolDir(t, s, "dr")
	src := t.TempDir()
	var disks []corrosion.DiskRecord
	for _, d := range []string{"data1", "data2"} {
		p := filepath.Join(src, d+".qcow2")
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		disks = append(disks, corrosion.DiskRecord{VMName: "mv1", HostName: s.hostName, DiskName: d, Path: p, StorageType: "dir"})
	}
	vm := corrosion.VMRecord{Name: "mv1", HostName: s.hostName, State: "running", Spec: `{}`}
	if err := corrosion.InsertVM(ctx, s.db, vm, nil, disks); err != nil {
		t.Fatal(err)
	}
	f.SetState("mv1", libvirtfake.StateRunning)
	s.backupSource = failingBackupSource{} // the session fails: layer 2, then -U, would follow
	takes := 0
	relock := func() func() {
		takes++
		if takes == 1 { // the VM migrated away after the root's run released the lock
			if err := s.db.Execute(ctx, `UPDATE vms SET host_name = 'elsewhere' WHERE name = 'mv1'`); err != nil {
				t.Fatal(err)
			}
		}
		return func() {}
	}
	sched := corrosion.BackupScheduleRecord{VMName: "mv1", Repo: "dr", Type: "replication", TargetPool: "dr", TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 3}
	err := s.replicateOtherDisks(ctx, sched, &vm, disks, s.hostName, "20260101-000000", true, relock)
	if !errors.Is(err, errVMNoLongerHere) {
		t.Fatalf("replicateOtherDisks = %v, want errVMNoLongerHere", err)
	}
	if recs, _ := listReplicaRecords(replicaPoolDirOf(t, s), "", "mv1"); len(recs) != 0 {
		t.Errorf("replicas of a VM that left: %+v", recs)
	}
	if takes != 1 {
		t.Errorf("the lock was taken %d times, want 1: data2 was tried for a VM that left", takes)
	}
}

func replicaPoolDirOf(t *testing.T, s *Server) string {
	t.Helper()
	d, err := s.replicaPoolDir(context.Background(), "dr")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// N9: a disk on a pool defined only on its own host is judged shared by that
// host's pool row, not only by this host's.
//
// Mutation "this host's pools only": diskOnSharedStorage skips the owner's
// pool row — red.
func TestDiskOnSharedStorage_ReadsTheOwnersPoolRow(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: "dead-host", Name: "remote-nfs", Driver: "nfs", Source: "nas:/vm", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	d := corrosion.DiskRecord{DiskName: "data1", HostName: "dead-host", StorageType: "local", StorageVolume: "remote-nfs"}
	if !s.diskOnSharedStorage(ctx, d) {
		t.Error("a disk on the owner's nfs pool was judged host-local")
	}
	d.StorageVolume = "nowhere"
	if s.diskOnSharedStorage(ctx, d) {
		t.Error("a disk on an unknown pool was judged shared")
	}
}
