// Fleet scenarios for `lv host drain` of a host holding a RUNNING VM with a
// host-local disk. Drain cannot live-migrate it (drain copies no storage), and
// it used to shut it down and move its row alone, leaving the disk behind. It
// is now cold-moved: every check of the move runs while the VM still runs, it
// is shut down only then, moved with its disks, and started on the target. A
// move that fails after the shutdown starts it again where it was.
//
// The nodes share one database here, so the target's copy of the VM row never
// lags the source's stopped write. That case is pinned by
// internal/grpcapi/migrate_cold_disk_drain_test.go.

package fleet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// makeRunning turns the scenario's stopped VM into a running one on the source.
func (sc *coldStoppedScenario) makeRunning(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := sc.src.Virt.StartDomain("os1"); err != nil {
		t.Fatalf("start os1's domain: %v", err)
	}
	if err := sc.src.DB.Execute(ctx, `UPDATE vms SET state = 'running', state_detail = '', updated_at = ? WHERE name = 'os1'`, sc.src.DB.NowTS()); err != nil {
		t.Fatalf("record os1 running: %v", err)
	}
}

func (sc *coldStoppedScenario) srcOps(op string) int {
	n := 0
	for _, e := range sc.src.Virt.EventLog() {
		if e.Op == op && e.Domain == "os1" {
			n++
		}
	}
	return n
}

// assertRunningOnSource: os1 runs where it was, its rows and its disk there.
func (sc *coldStoppedScenario) assertRunningOnSource(t *testing.T) {
	t.Helper()
	vm := sc.vm(t)
	if vm.HostName != sc.src.Name || vm.State != "running" {
		t.Errorf("os1 row = host %s state %s, want host %s state running", vm.HostName, vm.State, sc.src.Name)
	}
	if active, _ := sc.src.Virt.DomainIsActive("os1"); !active {
		t.Errorf("os1's domain is not running on %s", sc.src.Name)
	}
	for name, host := range sc.diskHosts(t) {
		if host != sc.src.Name {
			t.Errorf("disk %s row names %s, want %s", name, host, sc.src.Name)
		}
	}
	if got, err := os.ReadFile(sc.file(sc.src, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("os1's disk is not intact on %s (err %v, %d bytes)", sc.src.Name, err, len(got))
	}
	if sc.dst.Virt.DomainExists("os1") {
		t.Errorf("os1's domain is defined on %s", sc.dst.Name)
	}
	if _, err := os.Stat(sc.file(sc.dst, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("a disk copy was left on %s (stat: %v)", sc.dst.Name, err)
	}
}

func assertIncomplete(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "drain incomplete: 1 VM(s) remain") {
		t.Fatalf("drain = %v, want FailedPrecondition drain incomplete: 1 VM(s) remain", err)
	}
}

// A running VM with a local disk arrives on the target with its disk's bytes,
// and runs there, as it did before the drain. The source keeps neither the
// disk nor the domain, and libvirt was never asked to migrate it live.
//
// Mutations: move the row alone after the shutdown (the old path) — the disk
// never arrives and goes red. Skip the start on the target — os1 is stopped
// there and goes red.
func TestFleet_DrainMovesARunningVMWithItsLocalDiskAndStartsIt(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain of a host holding one running local-disk VM: %v", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for os1 = %+v, want done with no error", p)
	}
	got, err := os.ReadFile(sc.file(sc.dst, sc.disk))
	if err != nil || string(got) != string(sc.payload) {
		t.Fatalf("os1's disk did not arrive intact on %s (err %v, %d bytes)", sc.dst.Name, err, len(got))
	}
	if _, err := os.Stat(sc.file(sc.src, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("the drained host still holds the moved disk (stat: %v)", err)
	}
	vm := sc.vm(t)
	if vm.HostName != sc.dst.Name || vm.State != "running" {
		t.Fatalf("os1 row = host %s state %s, want host %s state running", vm.HostName, vm.State, sc.dst.Name)
	}
	if active, _ := sc.dst.Virt.DomainIsActive("os1"); !active {
		t.Errorf("os1's domain is not running on %s", sc.dst.Name)
	}
	for name, host := range sc.diskHosts(t) {
		if host != sc.dst.Name {
			t.Errorf("disk %s row names %s, want %s", name, host, sc.dst.Name)
		}
	}
	if sc.src.Virt.DomainExists("os1") {
		t.Errorf("os1's domain is still defined on the drained host")
	}
	if n := sc.srcOps("migrate"); n != 0 {
		t.Errorf("libvirt was asked to live-migrate a VM with a local disk %d time(s)", n)
	}
}

// A move the target would refuse is refused while the VM still runs: here the
// target already holds a file at the disk's path, which the copy must never
// overwrite. The VM is never shut down, and stays running with its disk.
//
// Mutation: skip the preflight — the VM is shut down before the copy is
// refused and started again, and the frame ("started again", not "left
// running") goes red.
func TestFleet_DrainRefusesARunningVMBeforeShuttingItDown(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	dp := sc.file(sc.dst, sc.disk)
	if err := os.MkdirAll(filepath.Dir(dp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dp, []byte("an earlier stay's disk"), 0o600); err != nil {
		t.Fatal(err)
	}

	progress, err := sc.drain(t)
	assertIncomplete(t, err)
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "left running on "+sc.src.Name) ||
		!strings.Contains(p.Error, "already exists") {
		t.Fatalf("drain progress for os1 = %+v, want failed: left running, the target's refusal", p)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Errorf("os1 was shut down %d time(s) for a move its preflight should have refused", n)
	}
	vm := sc.vm(t)
	if vm.HostName != sc.src.Name || vm.State != "running" {
		t.Errorf("os1 row = host %s state %s, want host %s state running", vm.HostName, vm.State, sc.src.Name)
	}
	if active, _ := sc.src.Virt.DomainIsActive("os1"); !active {
		t.Errorf("os1's domain is not running on %s", sc.src.Name)
	}
	if got, _ := os.ReadFile(sc.file(sc.src, sc.disk)); string(got) != string(sc.payload) {
		t.Errorf("os1's disk is not intact on the drained host")
	}
	if got, _ := os.ReadFile(dp); string(got) != "an earlier stay's disk" {
		t.Errorf("the target's existing file was changed: %q", got)
	}
}

// A move that fails after the shutdown — the target's define, the last step
// before the handoff — leaves os1 on the drained host with its disk, and starts
// it there again. The copy that reached the target is taken back.
//
// Mutation: skip the restart — os1 is stopped on the source and goes red.
func TestFleet_DrainStartsARunningVMAgainWhenItsMoveFails(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.dst.Virt.FailDefineDomain = func(string) error { return errors.New("injected define failure") }

	progress, err := sc.drain(t)
	assertIncomplete(t, err)
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "started again on "+sc.src.Name) ||
		!strings.Contains(p.Error, "injected define failure") {
		t.Fatalf("drain progress for os1 = %+v, want failed: started again, with the define failure", p)
	}
	if n := sc.srcOps("shutdown"); n != 1 {
		t.Errorf("os1 was shut down %d time(s), want 1", n)
	}
	sc.assertRunningOnSource(t)
}

// A guest that never completes the shutdown it was asked for is not moved,
// and the drain says what is true: its shutdown was requested and its domain
// is still active, so it still runs here and will power off if the guest ever
// completes the shutdown. It does not claim the VM was "started again", and
// the row says running, which is what the VM is.
//
// Mutation: do not check that the domain shut off — the move goes on under a
// running guest, is refused only by the cold path's own active-domain check,
// and the frame's reason goes red. Report it as started again (drop the
// still-active branch) — the frame goes red.
func TestFleet_DrainReportsAGuestThatNeverShutsDown(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.src.Virt.IgnoreShutdown = func(string) bool { return true }

	progress, err := sc.drain(t)
	assertIncomplete(t, err)
	p := progress["os1"]
	if p == nil || p.Status != "error" || !strings.Contains(p.Error, "did not shut down within its stop timeout") ||
		!strings.Contains(p.Error, "shutdown was requested and its domain on "+sc.src.Name+" is still active") ||
		strings.Contains(p.Error, "started again") {
		t.Fatalf("drain progress for os1 = %+v, want error: shutdown requested, domain still active, never \"started again\"", p)
	}
	sc.assertRunningOnSource(t)
}

// A guest slower than its stop timeout finishes its shutdown after the move
// has given up. The drain waits for that (its separate, bounded budget past
// the stop timeout), and only then starts the VM again, which ends running
// where it was. Starting it while it was still going down would have been
// undone moments later by the guest's own power-off, and stuck: a clean guest
// shutdown is never restarted by the restart policy.
//
// Mutations: do not wait past the stop timeout — the guest is still going
// down, the drain reports it still active instead of starting it, and the
// frame goes red. Start it without checking that it shut off — libvirt refuses
// a domain still running, the guest then powers off, and the VM ends stopped.
func TestFleet_DrainStartsAGuestThatShutsDownLateAgain(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.src.Virt.ShutdownLate = func(string) bool { return true }

	progress, err := sc.drain(t)
	assertIncomplete(t, err)
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "started again on "+sc.src.Name) {
		t.Fatalf("drain progress for os1 = %+v, want failed: started again", p)
	}
	late, started := -1, -1
	for i, e := range sc.src.Virt.EventLog() {
		if e.Domain != "os1" {
			continue
		}
		switch e.Op {
		case "shutoff-late":
			late = i
		case "start":
			started = i
		}
	}
	if late < 0 || started < late {
		t.Fatalf("os1 was started again (event %d) before its late shutdown completed (event %d)", started, late)
	}
	sc.assertRunningOnSource(t)
}

// The row says stopped, with the drain's own stop detail (an operator stop to
// every health decision), before the guest is asked to shut down. A guest that went down under a row saying running would read as a
// crash to the domain-event handler and the restart policy, which could start
// it again while its disk is being copied.
//
// Mutation: request the shutdown before recording the row — the row seen at
// the shutdown says running and goes red.
func TestFleet_DrainRecordsTheVMStoppedBeforeShuttingItDown(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	var atShutdown *corrosion.VMRecord
	sc.src.Virt.FailShutdownDomain = func(name string) error {
		if name == "os1" && atShutdown == nil {
			atShutdown, _ = corrosion.GetVM(context.Background(), sc.src.DB, "os1")
		}
		return nil
	}

	if _, err := sc.drain(t); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if atShutdown == nil {
		t.Fatal("os1 was never shut down")
	}
	if atShutdown.State != "stopped" || !health.IsOperatorStop(atShutdown.StateDetail) ||
		!strings.HasPrefix(atShutdown.StateDetail, health.DrainStopDetailPrefix) {
		t.Fatalf("os1's row when its shutdown was requested = %s/%q, want stopped with the drain's own operator-stop detail", atShutdown.State, atShutdown.StateDetail)
	}
}

// If the VM cannot be started again after a failed move, the drain says so
// loudly, naming the VM, and the VM stays on the drained host, stopped, with
// its disk and rows — never moved by its row alone.
//
// Mutation: report it as an ordinary failure (drop the restart-failed branch)
// — the frame's status and wording go red.
func TestFleet_DrainReportsAVMItCouldNotStartAgain(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.dst.Virt.FailDefineDomain = func(string) error { return errors.New("injected define failure") }
	sc.src.Virt.FailStartDomain = func(string) error { return errors.New("injected start failure") }

	progress, err := sc.drain(t)
	assertIncomplete(t, err)
	p := progress["os1"]
	if p == nil || p.Status != "error" || !strings.Contains(p.Error, "VM os1 was shut down") ||
		!strings.Contains(p.Error, "could NOT be started again") || !strings.Contains(p.Error, "injected start failure") {
		t.Fatalf("drain progress for os1 = %+v, want error naming os1: could NOT be started again", p)
	}
	vm := sc.vm(t)
	if vm.HostName != sc.src.Name || vm.State != "stopped" {
		t.Errorf("os1 row = host %s state %s, want host %s stopped", vm.HostName, vm.State, sc.src.Name)
	}
	for name, host := range sc.diskHosts(t) {
		if host != sc.src.Name {
			t.Errorf("disk %s row names %s, want %s", name, host, sc.src.Name)
		}
	}
	if got, _ := os.ReadFile(sc.file(sc.src, sc.disk)); string(got) != string(sc.payload) {
		t.Errorf("os1's disk is not intact on the drained host")
	}
}

// A running VM whose disk is in a dir pool — a host-local file, like local —
// is cold-moved too. Drain used to count only `local` as host-local, so it
// live-migrated such a VM without its disk.
//
// Mutation: count only `local` storage as host-local — os1 is live-migrated,
// its disk never arrives, and the test goes red.
func TestFleet_DrainMovesARunningDirPoolVMWithItsDisk(t *testing.T) {
	sc := newColdStoppedScenario(t)
	if err := sc.src.DB.Execute(context.Background(), `UPDATE vm_disks SET storage_type = 'dir', updated_at = ? WHERE vm_name = 'os1' AND disk_name = 'root'`, sc.src.DB.NowTS()); err != nil {
		t.Fatalf("make os1's root disk a dir-pool disk: %v", err)
	}
	sc.makeRunning(t)

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain of a host holding a running dir-pool VM: %v", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for os1 = %+v, want done with no error", p)
	}
	if got, err := os.ReadFile(sc.file(sc.dst, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Fatalf("os1's disk did not arrive intact on %s (err %v)", sc.dst.Name, err)
	}
	if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != "running" {
		t.Fatalf("os1 row = host %s state %s, want host %s state running", vm.HostName, vm.State, sc.dst.Name)
	}
}

// A running VM on shared storage whose live migration fails is cold-moved
// instead: shut down, its domain defined on the target, handed over and
// started there. Drain used to shut it down and move its row alone, leaving no
// domain on the target and, as the shutdown request returns at once, possibly
// a guest still running on the source.
//
// Mutation: fall back to the old shutdown-and-move-the-row — os3 has no domain
// on the target and goes red.
func TestFleet_DrainFallsBackToAColdMoveWhenLiveMigrationFails(t *testing.T) {
	sc := newColdStoppedScenario(t)
	ctx := context.Background()
	// os1 (stopped) drains too; this test is about os3.
	if err := corrosion.InsertVM(ctx, sc.src.DB, corrosion.VMRecord{
		Name: "os3", HostName: sc.src.Name, State: "running", Spec: `{"name":"os3","cpu":1,"memory_mib":256}`, CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "os3", DiskName: "root", HostName: sc.src.Name, Path: sc.shared + ".os3", SizeBytes: 1 << 30, StorageType: "nfs", TargetDev: "vda"},
	}); err != nil {
		t.Fatalf("InsertVM os3: %v", err)
	}
	if err := sc.src.Virt.DefineDomain(`<domain type='kvm'><name>os3</name><uuid>33333333-4444-4555-8666-777777777777</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='` + sc.shared + `.os3'/><target dev='vda'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := sc.src.Virt.StartDomain("os3"); err != nil {
		t.Fatal(err)
	}
	sc.src.Virt.FailMigrateToTarget = func(string, string) error { return errors.New("injected live migration failure") }

	progress, _ := sc.drain(t)
	if p := progress["os3"]; p == nil || p.Status != "done" || p.Error != "" || p.Strategy.String() != "MIGRATE_COLD" {
		t.Fatalf("drain progress for os3 = %+v, want done by a cold move", p)
	}
	vm, err := corrosion.GetVM(ctx, sc.dst.DB, "os3")
	if err != nil || vm == nil || vm.HostName != sc.dst.Name || vm.State != "running" {
		t.Fatalf("os3 row = %+v (%v), want host %s running", vm, err, sc.dst.Name)
	}
	if active, _ := sc.dst.Virt.DomainIsActive("os3"); !active {
		t.Errorf("os3's domain is not running on %s", sc.dst.Name)
	}
	if sc.src.Virt.DomainExists("os3") {
		t.Errorf("os3's domain is still defined on the drained host")
	}
}

// A VM that moved but did not start on its target left the host, but the
// drain did not do what it was asked for it: the drain ends incomplete,
// naming the VM, and a VM event on it says why. The frame says where it is.
//
// Mutations: count a done frame with an error as success — the drain returns
// nil and goes red. Drop the VM event — the event check goes red.
func TestFleet_DrainCountsAVMThatDidNotStartOnItsTarget(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.dst.Virt.FailStartDomain = func(string) error { return errors.New("injected start failure") }

	progress, err := sc.drain(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "did not start on its target (os1)") {
		t.Fatalf("drain = %v, want FailedPrecondition naming os1 as not started on its target", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || !strings.Contains(p.Error, "stopped on "+sc.dst.Name) {
		t.Fatalf("drain progress for os1 = %+v, want done with the not-started error", p)
	}
	if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != "stopped" {
		t.Errorf("os1 row = host %s state %s, want stopped on %s", vm.HostName, vm.State, sc.dst.Name)
	}
	evs, err := corrosion.ListVMEvents(context.Background(), sc.src.DB, "os1", 50, "")
	if err != nil {
		t.Fatalf("ListVMEvents: %v", err)
	}
	found := false
	for _, e := range evs {
		if e.Type == "vm.drain" && e.Result == "error" && strings.Contains(e.Detail, "not started there") {
			found = true
		}
	}
	if !found {
		t.Errorf("no vm.drain error event says os1 was not started on %s: %+v", sc.dst.Name, evs)
	}
}
