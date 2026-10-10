package health

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// strandedFixture is VM "web", running on node-b after a failover off node-a,
// with one host-local disk at path and one disk on shared storage. node-a,
// the host it failed over from, still holds the real local disk at path. The
// returned reconciler is node-a's.
func strandedFixture(t *testing.T) (*corrosion.Client, *libvirtfake.Fake, *Reconciler, string, string) {
	t.Helper()
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "disks", "web-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("the real disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "web", HostName: "node-b", State: "running", Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, []corrosion.DiskRecord{
		{VMName: "web", DiskName: "root", HostName: "node-b", Path: path, BackingImage: "base", StorageType: "local"},
		{VMName: "web", DiskName: "data", HostName: "node-b", Path: "/mnt/nfs/web-data.qcow2", StorageType: "nfs"},
	}); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", dataDir, db, fake)
	return db, fake, r, dataDir, path
}

func strandedRow(t *testing.T, db *corrosion.Client, vm, host string) (corrosion.HealthCondition, StrandedDisks, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), db, DiskMissingEvaluator, CondVMDiskStranded, "vm", vm+"@"+host)
	if err != nil {
		t.Fatal(err)
	}
	var ev StrandedDisks
	if ok {
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
			t.Fatalf("evidence %q: %v", row.Evidence, err)
		}
	}
	return row, ev, ok
}

// recordWeb records what the coordinator records when it reschedules web off
// node-a to node-b.
func recordWeb(t *testing.T, db *corrosion.Client, now time.Time) string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), db, "web")
	if err != nil {
		t.Fatal(err)
	}
	detail, err := RecordStrandedDisks(context.Background(), db, "coord", "web", "node-a", "node-b", disks, now)
	if err != nil {
		t.Fatalf("RecordStrandedDisks: %v", err)
	}
	return detail
}

// A failover that restarts a VM elsewhere records, for the host it left, the
// host-local disks it left there: the VM's real data, which the restart did
// not take. A disk on shared storage moved with the VM and is not listed.
// Recording it again (a second coordinator, a re-materialised claim) does not
// list a disk twice.
//
// Mutations: record nothing — the test is red on the missing row; list
// shared disks too — the test is red on the entry count.
func TestRecordStrandedDisks_NamesTheHostLocalDisksLeftBehind(t *testing.T) {
	db, _, _, _, path := strandedFixture(t)
	now := time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC)
	detail := recordWeb(t, db, now)
	recordWeb(t, db, now.Add(time.Minute))

	row, ev, ok := strandedRow(t, db, "web", "node-a")
	if !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("no open vm_disk_stranded for web@node-a: %+v", row)
	}
	if row.Severity != corrosion.SeverityWarning || len(row.Hosts) != 1 || row.Hosts[0] != "node-a" {
		t.Fatalf("condition %+v, want a warning naming node-a", row)
	}
	if len(ev.Disks) != 1 || ev.Disks[0].Path != path || ev.Disks[0].Disk != "root" || ev.Disks[0].Copy != "" {
		t.Fatalf("stranded disks = %+v, want only root at %s", ev.Disks, path)
	}
	if ev.MovedTo != "node-b" || !strings.Contains(detail, "node-a") || !strings.Contains(detail, path) || ev.Fix == "" {
		t.Fatalf("detail %q / evidence %+v do not say where the real disk is and what to do", detail, ev)
	}
	if got, err := StrandedDisksOf(context.Background(), db, "web"); err != nil || len(got) != 1 || got[0].Host != "node-a" {
		t.Fatalf("StrandedDisksOf(web) = %+v, %v", got, err)
	}
}

// When the host comes back it sets the VM's real disk aside under a name no
// later move or restart onto the host can take (<path>.superseded-<time>),
// records where it put it, and the copy is retained whatever its age while
// the VM exists: the sweep never removes it.
//
// Mutations: skip the set-aside in tendStrandedDisks — the file stays at its
// path and the test is red; drop the retention of a recorded copy whose VM
// exists — the sweep removes it and the test is red.
func TestTendStrandedDisks_SetsTheRealDiskAsideWhenItsHostReturns(t *testing.T) {
	db, _, r, dataDir, path := strandedFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC)
	recordWeb(t, db, now)
	var notified []string
	r.SetDiskStrandedObserver(func(vm, host, detail string) { notified = append(notified, vm+"@"+host+": "+detail) })

	r.tendStrandedDisks(ctx)

	if exists(path) {
		t.Fatalf("the real disk is still at %s, where a move back onto this host would collide with it", path)
	}
	_, ev, ok := strandedRow(t, db, "web", "node-a")
	if !ok || len(ev.Disks) != 1 || ev.Disks[0].Copy == "" {
		t.Fatalf("the set-aside copy is not recorded: %+v", ev)
	}
	got, err := os.ReadFile(ev.Disks[0].Copy)
	if err != nil || !bytes.Equal(got, []byte("the real disk")) {
		t.Fatalf("the copy at %s does not hold the real disk (err %v)", ev.Disks[0].Copy, err)
	}
	if len(notified) != 1 || !strings.Contains(notified[0], ev.Disks[0].Copy) {
		t.Fatalf("notifications = %q, want one naming the copy", notified)
	}
	// A month later the VM still exists: the sweep keeps the copy.
	if _, err := PurgeSupersededDisks(ctx, db, dataDir, 7*24*time.Hour, time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !exists(ev.Disks[0].Copy) {
		t.Fatal("the sweep removed the only copy of the VM's data from before the failover")
	}
	// Even when the VM's disk has since moved to another path, the copy is
	// still known to be the VM's.
	if err := db.Execute(ctx, `UPDATE vm_disks SET path = '/elsewhere/web-root.qcow2', updated_at = ? WHERE vm_name = 'web' AND disk_name = 'root'`, db.NowTS()); err != nil {
		t.Fatal(err)
	}
	if _, err := PurgeSupersededDisks(ctx, db, dataDir, 7*24*time.Hour, time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !exists(ev.Disks[0].Copy) {
		t.Fatal("the sweep removed a recorded copy once the VM's disk path changed")
	}
}

// A host that comes back still RUNNING the VM — not a dead leftover — has
// its disk open; the tend pass leaves it for the ownership repair and does
// not touch the file.
//
// Mutation: drop the running-domain check — the file is renamed and the test
// is red.
func TestTendStrandedDisks_LeavesTheDiskOfADomainStillRunningHere(t *testing.T) {
	db, fake, r, _, path := strandedFixture(t)
	recordWeb(t, db, time.Now())
	if err := fake.DefineDomain(`<domain><name>web</name></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain("web"); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(context.Background())
	if !exists(path) {
		t.Fatal("the disk of a domain still running on this host was moved")
	}
	if _, ev, _ := strandedRow(t, db, "web", "node-a"); len(ev.Disks) != 1 || ev.Disks[0].Copy != "" {
		t.Fatalf("evidence %+v, want the disk still recorded at its path", ev)
	}
}

// The record clears once nothing is left to keep: the VM was deleted, or the
// operator removed or restored the copy.
//
// Mutation: never resolve — the test is red.
func TestTendStrandedDisks_ClearsWhenNothingIsLeftToKeep(t *testing.T) {
	db, _, r, _, _ := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	r.tendStrandedDisks(ctx)
	_, ev, _ := strandedRow(t, db, "web", "node-a")
	if len(ev.Disks) != 1 || ev.Disks[0].Copy == "" {
		t.Fatalf("setup: %+v", ev)
	}
	if err := os.Remove(ev.Disks[0].Copy); err != nil { // the operator's --remove
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if row, _, ok := strandedRow(t, db, "web", "node-a"); !ok || row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %+v, want resolved once the copy is gone", row)
	}

	// Recorded again, then the VM is deleted.
	recordWeb(t, db, time.Now())
	if row, _, _ := strandedRow(t, db, "web", "node-a"); row.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("a new stranding did not reopen the condition")
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if row, _, ok := strandedRow(t, db, "web", "node-a"); !ok || row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %+v, want resolved once the VM is gone", row)
	}
}

// A failover start that sets an old copy aside on its target records it, so
// the copy is surfaced, with its path, like a disk left on a failed host.
//
// Mutation: drop the record in setAsideSupersededDisk — the test is red.
func TestStartPendingVM_RecordsTheCopyItSetsAside(t *testing.T) {
	db, fake, r, path := supersededFixture(t, "running")
	ctx := context.Background()
	if err := corrosion.WriteVMRescheduleProof(ctx, db, corrosion.ActionProof{
		ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a",
	}, "vm1", "node-a"); err != nil {
		t.Fatal(err)
	}
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	var notified []string
	r.SetDiskStrandedObserver(func(vm, host, detail string) { notified = append(notified, detail) })
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)
	if !startedOrDefined(fake, "vm1") {
		t.Fatal("vm1 was not started")
	}
	aside, _ := filepath.Glob(path + ".superseded-*")
	if len(aside) != 1 {
		t.Fatalf("set-aside copies = %v", aside)
	}
	_, ev, ok := strandedRow(t, db, "vm1", "node-a")
	if !ok || len(ev.Disks) != 1 || ev.Disks[0].Copy != aside[0] || ev.Disks[0].Path != path {
		t.Fatalf("the set-aside copy is not recorded: ok=%v %+v", ok, ev)
	}
	if len(notified) != 1 {
		t.Fatalf("notifications = %q, want one", notified)
	}
}

// Restoring a copy puts it back at the disk's path and sets the file there
// aside in its place, so nothing is deleted: the disk the VM ran on since the
// failover becomes a retained copy itself. Only for a stopped VM on this
// host, never one running.
//
// Mutations: drop the set-aside of the current file — the restore fails on
// the occupied path (it never overwrites) and the test is red; drop the
// running check — the running VM's disk is swapped and the test is red.
func TestRestoreSupersededDisk_SwapsWithoutDeletingAnything(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "disks", "web-root.qcow2")
	copyPath := supersededAt(t, path, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err := os.WriteFile(copyPath, []byte("the real disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("rebuilt blank"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", HostName: "node-a", State: "running", Spec: "{}"},
		nil, []corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: "node-a", Path: path, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	running := func(string) bool { return true }
	if _, err := RestoreSupersededDisk(ctx, db, dataDir, "node-a", copyPath, running, time.Now()); err == nil {
		t.Fatal("restored a disk under a running VM")
	}
	if b, _ := os.ReadFile(path); string(b) != "rebuilt blank" {
		t.Fatalf("a refused restore changed the disk: %q", b)
	}

	if err := db.Execute(ctx, `UPDATE vms SET state = 'stopped', state_detail = 'operator-stop', updated_at = ? WHERE name = 'web'`, db.NowTS()); err != nil {
		t.Fatal(err)
	}
	got, err := RestoreSupersededDisk(ctx, db, dataDir, "node-a", copyPath, func(string) bool { return false }, time.Now())
	if err != nil {
		t.Fatalf("RestoreSupersededDisk: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "the real disk" {
		t.Fatalf("the disk is %q after the restore, want the restored copy", b)
	}
	if exists(copyPath) {
		t.Fatalf("the restored copy %s is still beside the disk", copyPath)
	}
	if b, err := os.ReadFile(got.SetAside); err != nil || string(b) != "rebuilt blank" {
		t.Fatalf("the disk the VM ran on since the failover was not kept at %q (err %v, %q)", got.SetAside, err, b)
	}
	copies, err := ListSupersededDisks(ctx, db, dataDir)
	if err != nil || len(copies) != 1 || copies[0].Path != got.SetAside || copies[0].Retained == "" {
		t.Fatalf("copies after the restore = %+v (err %v), want the swapped-out disk retained", copies, err)
	}
}

// A record for a host removed from the cluster is cleared by any host once
// the VM is deleted: the removed host will never tend it.
//
// Mutation: drop resolveStrandedOnRemovedHost — the test is red.
func TestTendStrandedDisks_ClearsARemovedHostsRecordOnceTheVMIsGone(t *testing.T) {
	db, _, _, dataDir, _ := strandedFixture(t)
	ctx := context.Background()
	disks, err := corrosion.GetVMDisks(ctx, db, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordStrandedDisks(ctx, db, "coord", "web", "gone-host", "node-b", disks, time.Now()); err != nil {
		t.Fatal(err)
	}
	other := NewReconciler("node-c", dataDir, db, libvirtfake.New())
	other.tendStrandedDisks(ctx)
	if row, _, _ := strandedRow(t, db, "web", "gone-host"); row.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("cleared while the VM still exists")
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	other.tendStrandedDisks(ctx)
	if row, _, ok := strandedRow(t, db, "web", "gone-host"); !ok || row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition %+v, want resolved: the host is gone and so is the VM", row)
	}
}

// Rolling upgrade: an older host decides whether to keep a copy from the VM's
// row alone (its state), so nothing this record does may change that row —
// the record and the set-aside live in health_conditions and on disk only.
// An older host therefore holds copies exactly as it did before, and no row
// written here gives it a reason to delete one.
//
// Mutation: have the record or the set-aside write the VM's state or detail
// (e.g. a "disk-stranded" state_detail) — the row changes and the test is red.
func TestStrandedRecord_LeavesTheVMRowAsItWas(t *testing.T) {
	db, _, r, _, _ := strandedFixture(t)
	ctx := context.Background()
	row := func() string {
		t.Helper()
		rows, err := db.Query(ctx, `SELECT host_name, state, state_detail, vm_owner_epoch, updated_at FROM vms WHERE name = 'web'`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read web: %v", err)
		}
		return rows[0].String("host_name") + "|" + rows[0].String("state") + "|" + rows[0].String("state_detail") + "|" +
			rows[0].String("vm_owner_epoch") + "|" + rows[0].String("updated_at")
	}
	before := row()
	recordWeb(t, db, time.Now())
	r.tendStrandedDisks(ctx)
	if _, ev, _ := strandedRow(t, db, "web", "node-a"); len(ev.Disks) != 1 || ev.Disks[0].Copy == "" {
		t.Fatalf("setup: the disk was not set aside: %+v", ev)
	}
	if after := row(); after != before {
		t.Fatalf("the VM row changed from %q to %q", before, after)
	}
}
