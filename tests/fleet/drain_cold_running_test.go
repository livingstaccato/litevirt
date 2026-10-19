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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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

// auditEntries is the audit log's host.drain entries on n: "result detail".
func auditEntries(t *testing.T, n *Node, action string) []string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT result, detail FROM audit_log WHERE action = ?`, action)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("result")+" "+r.String("detail"))
	}
	return out
}

// The client of `lv host drain` goes away (Ctrl-C) while a running VM's cold
// move is shutting it down. The move does not die with the request: it
// completes, and the VM runs on the target only. The drain does not end
// silently: the host's audit log records that its client left and how each
// VM it had started ended.
//
// Mutations: run the cold move on the request's context — the move fails
// (context canceled), the VM is started again on the source, and goes red.
// Record nothing when the client leaves — the audit check goes red.
func TestFleet_DrainColdMoveCompletesWhenTheClientLeaves(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	startsBefore := sc.srcOps("start")
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	sc.src.Virt.FailShutdownDomain = func(name string) error {
		if name == "os1" {
			once.Do(func() { close(started) })
			<-release
		}
		return nil
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := sc.c.SelfClient(sc.src).DrainHost(ctx, &pb.DrainHostRequest{Name: sc.src.Name})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			if _, err := st.Recv(); err != nil {
				return
			}
		}
	}()
	select {
	case <-started:
	case <-time.After(15 * time.Second):
		t.Fatal("the cold move never reached the shutdown")
	}
	cancel()
	time.Sleep(150 * time.Millisecond) // the server sees the stream end
	close(release)

	eventually(t, 15*time.Second, "os1 to run on the target only", func() bool {
		vm, _ := corrosion.GetVM(context.Background(), sc.src.DB, "os1")
		dstActive, _ := sc.dst.Virt.DomainIsActive("os1")
		srcActive, _ := sc.src.Virt.DomainIsActive("os1")
		return vm != nil && vm.HostName == sc.dst.Name && vm.State == "running" && dstActive && !srcActive
	})
	if n := sc.srcOps("start") - startsBefore; n != 0 {
		t.Errorf("os1 was started again on the source %d time(s)", n)
	}
	eventually(t, 15*time.Second, "the drain's end after its client left to be audited", func() bool {
		for _, e := range auditEntries(t, sc.src, "host.drain") {
			if strings.HasPrefix(e, "cancelled ") && strings.Contains(e, "os1") && strings.Contains(e, "moved") {
				return true
			}
		}
		return false
	})
}

// stallReceive makes dst's ReceiveMigrationDisk take the stream and never
// read it, as a target wedged in a hung write does, until release. With
// afterCheck, the move's check of the disk (check_only) is answered first, so
// the stall is in the copy itself, after the guest's shutdown.
func stallReceive(dst *Node, afterCheck bool, entered chan<- struct{}, release <-chan struct{}) {
	var once sync.Once
	if afterCheck {
		dst.HookStream("ReceiveMigrationDisk", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
			return h(srv, ss)
		})
	}
	dst.HookStream("ReceiveMigrationDisk", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
		once.Do(func() { close(entered) })
		<-release
		return status.Error(codes.Unavailable, "test: the target was wedged")
	})
}

func drainWithin(t *testing.T, sc *coldStoppedScenario, d time.Duration) (map[string]*pb.DrainProgress, error) {
	t.Helper()
	type res struct {
		p   map[string]*pb.DrainProgress
		err error
	}
	out := make(chan res, 1)
	go func() { p, err := sc.drain(t); out <- res{p, err} }()
	select {
	case r := <-out:
		return r.p, r.err
	case <-time.After(d):
		t.Fatalf("the drain did not end within %v", d)
		return nil, nil
	}
}

// A cold move whose target stops taking the disk mid-copy (alive, but wedged)
// is not waited on forever with the guest shut down: a copy that makes no
// progress for its bound is aborted, and the move rolls back — the VM is
// started again on the source, where its row still names it.
//
// Mutation: no progress watchdog — the drain waits on the stalled copy, red.
func TestFleet_DrainColdMoveToAStalledTargetIsRolledBack(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.src.Server.SetColdDiskStallForTest(500 * time.Millisecond)
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release) })
	stallReceive(sc.dst, true, entered, release)

	progress, err := drainWithin(t, sc, 30*time.Second)
	assertIncomplete(t, err)
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "no progress") ||
		!strings.Contains(p.Error, "started again") {
		t.Fatalf("drain progress for os1 = %+v, want failed, the copy aborted for making no progress, started again", p)
	}
	sc.assertRunningOnSource(t)
}

// The move's check of the disk on the target (before the guest is shut
// down) is bounded too: a target that never answers leaves the VM running
// here, not moved, instead of holding the drain.
//
// Mutation: no bound on the check — the drain waits, red.
func TestFleet_DrainColdMoveCheckOfAStalledTargetIsBounded(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.src.Server.SetColdDiskStallForTest(500 * time.Millisecond)
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release) })
	stallReceive(sc.dst, false, entered, release)

	progress, err := drainWithin(t, sc, 30*time.Second)
	assertIncomplete(t, err)
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "did not answer") ||
		!strings.Contains(p.Error, "left running") {
		t.Fatalf("drain progress for os1 = %+v, want failed, the target did not answer, left running", p)
	}
	sc.assertRunningOnSource(t)
}

// An operator gets a stuck drain move out without restarting the daemon:
// `lv operation abort <vm> --force` cancels it, and it rolls back.
//
// Mutation: abort only the VM's recorded operation — no drain move is
// cancelled, the drain waits on the stalled copy, red.
func TestFleet_AStuckDrainMoveIsCancelledByOperationAbort(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.src.Server.SetColdDiskStallForTest(time.Hour)
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release) })
	stallReceive(sc.dst, true, entered, release)

	type res struct {
		p   map[string]*pb.DrainProgress
		err error
	}
	out := make(chan res, 1)
	go func() { p, err := sc.drain(t); out <- res{p, err} }()
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the copy never reached the target")
	}
	resp, err := sc.c.SelfClient(sc.src).AbortVMOperation(context.Background(),
		&pb.AbortVMOperationRequest{VmName: "os1", Force: true})
	if err != nil || !resp.GetAborted() {
		t.Fatalf("operation abort = %+v, %v; want the drain's move of os1 aborted", resp, err)
	}
	var r res
	select {
	case r = <-out:
	case <-time.After(30 * time.Second):
		t.Fatal("the drain did not end after its move was aborted")
	}
	assertIncomplete(t, r.err)
	sc.assertRunningOnSource(t)
}

// The client leaves before any move has started (during the placement of the
// VMs): the drain still ends visibly, audited as cancelled.
//
// Mutation: return on the failed send without recording — red.
func TestFleet_DrainCancelledBeforeAnyMoveIsAudited(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	// os1 has no eligible target, so its frame is sent from the placement loop.
	setHostCapacity(t, sc.c, sc.dst.Name, 0, 0)
	sc.src.HookStream("DrainHost", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
		return h(srv, failingSendStream{ss})
	})
	_, _ = sc.drain(t)
	eventually(t, 15*time.Second, "the drain's end before any move to be audited", func() bool {
		for _, e := range auditEntries(t, sc.src, "host.drain") {
			if strings.HasPrefix(e, "cancelled ") {
				return true
			}
		}
		return false
	})
}

// failingSendStream is a server stream whose client has gone away.
type failingSendStream struct{ grpc.ServerStream }

func (failingSendStream) SendMsg(any) error {
	return status.Error(codes.Canceled, "test: the client went away")
}

// An abort sent to another host than the VM's reaches the VM's host, where
// its drain move runs, and cancels it there.
//
// Mutation: do not forward — the other host has no move to cancel, the drain
// waits on the stalled copy, red.
func TestFleet_OperationAbortSentToAnotherHostCancelsTheDrainMove(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.src.Server.SetColdDiskStallForTest(time.Hour)
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release) })
	stallReceive(sc.dst, true, entered, release)

	out := make(chan error, 1)
	go func() { _, err := sc.drain(t); out <- err }()
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the copy never reached the target")
	}
	resp, err := sc.c.SelfClient(sc.dst).AbortVMOperation(context.Background(),
		&pb.AbortVMOperationRequest{VmName: "os1", Force: true})
	if err != nil || !resp.GetAborted() {
		t.Fatalf("operation abort via %s = %+v, %v; want the drain's move of os1 aborted on %s", sc.dst.Name, resp, err, sc.src.Name)
	}
	select {
	case err := <-out:
		assertIncomplete(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("the drain did not end after its move was aborted from another host")
	}
	sc.assertRunningOnSource(t)
}

// The VM's host cannot be reached: the abort is answered where it was sent,
// as before (the recorded operation is aborted there), not failed.
//
// Mutations: return the forward's Unavailable — red. Do not forward at all —
// the VM's host is never tried, red.
func TestFleet_OperationAbortFallsBackWhenTheVMsHostIsUnreachable(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	var tried atomic.Bool
	sc.src.HookUnary("AbortVMOperation", func(context.Context, any, grpc.UnaryHandler) (any, error) {
		tried.Store(true)
		return nil, status.Error(codes.Unavailable, "test: the VM's host cannot be reached")
	})
	resp, err := sc.c.SelfClient(sc.dst).AbortVMOperation(context.Background(),
		&pb.AbortVMOperationRequest{VmName: "os1", Force: true})
	if !tried.Load() {
		t.Fatal("the abort was not forwarded to the VM's host before falling back")
	}
	if err != nil {
		t.Fatalf("operation abort with the VM's host unreachable = %v; want it answered locally", err)
	}
	if resp.GetAborted() || resp.GetDetail() != "no active operation" {
		t.Fatalf("operation abort = %+v; want the local answer (no active operation)", resp)
	}
}

// A scoped abort (--operation) is never forwarded: it cancels no drain move,
// its compare-and-swap works on any host, and a VM host on an older build
// drops operation_id and would abort whatever operation is active.
//
// Mutation: forward scoped aborts too — the VM's host is called, red.
func TestFleet_ScopedOperationAbortIsNotForwarded(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	var called atomic.Bool
	sc.src.HookUnary("AbortVMOperation", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		called.Store(true)
		return h(ctx, req)
	})
	_, err := sc.c.SelfClient(sc.dst).AbortVMOperation(context.Background(),
		&pb.AbortVMOperationRequest{VmName: "os1", Force: true, OperationId: "op-x"})
	if called.Load() {
		t.Fatal("a scoped abort was forwarded to the VM's host")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("scoped abort of an operation that is not active = %v; want FailedPrecondition", err)
	}
}

// The target's final sync is slow but inside the stall bound: the copy is not
// aborted for it. After the last frame the wait for the target's answer is
// the stall bound, as for any frame.
//
// Mutation: cap the wait after the last frame below the sync's time — the
// copy is aborted after it fully arrived, red.
func TestFleet_DrainColdMoveWaitsForASlowFinalSync(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.src.Server.SetColdDiskStallForTest(3 * time.Second)
	sc.dst.Server.SetColdDiskSyncHookForTest(func(final bool) {
		if final {
			time.Sleep(1500 * time.Millisecond)
		}
	})
	progress, err := drainWithin(t, sc, 30*time.Second)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for os1 = %+v, want done", p)
	}
}

// A target that wedges after the last frame (its final sync never returns)
// holds the guest down for the stall bound, not for a time that grows with
// the disk's size: the copy is aborted and the move rolls back.
//
// Mutations: bound the wait after the last frame by the disk's size at
// 16 MiB/s (at least the stall bound) — it is 1s for this disk, and the
// abort names 1s, red. Wait at least 3s after the last frame — the source
// gives up too late, red.
func TestFleet_DrainColdMoveToATargetWedgedAfterTheLastFrameIsRolledBack(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	const stall = 300 * time.Millisecond
	sc.src.Server.SetColdDiskStallForTest(stall)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	finalAt := make(chan time.Time, 1)
	sc.dst.Server.SetColdDiskSyncHookForTest(func(final bool) {
		if final {
			finalAt <- time.Now()
			<-release
		}
	})
	// The move's check of the disk, then the copy: when the source gave up on
	// the copy is when the target's stream ends.
	abandonedAt := make(chan time.Time, 1)
	sc.dst.HookStream("ReceiveMigrationDisk", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
		return h(srv, ss)
	})
	sc.dst.HookStream("ReceiveMigrationDisk", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
		go func() { <-ss.Context().Done(); abandonedAt <- time.Now() }()
		return h(srv, ss)
	})
	progress, err := drainWithin(t, sc, 30*time.Second)
	assertIncomplete(t, err)
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "made no progress for 300ms") ||
		!strings.Contains(p.Error, "started again") {
		t.Fatalf("drain progress for os1 = %+v, want failed, the copy aborted after the 300ms stall bound, started again", p)
	}
	sc.assertRunningOnSource(t)
	var from, to time.Time
	select {
	case from = <-finalAt:
	default:
		t.Fatal("the target never reached its final sync")
	}
	select {
	case to = <-abandonedAt:
	case <-time.After(5 * time.Second):
		t.Fatal("the target's stream never ended")
	}
	if waited := to.Sub(from); waited >= 1500*time.Millisecond {
		t.Fatalf("the source waited %v for the target's answer after the last frame; want about the %v stall bound", waited, stall)
	}
}

// The target syncs a received disk as it writes, so its final sync is small
// and the sender's progress reflects what the target's storage takes.
//
// Mutation: sync only at the end — no periodic sync, red.
func TestFleet_ColdDiskReceiveSyncsAsItWrites(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.dst.Server.SetColdDiskSyncEveryForTest(1 << 20)
	var mu sync.Mutex
	periodic := 0
	sc.dst.Server.SetColdDiskSyncHookForTest(func(final bool) {
		if !final {
			mu.Lock()
			periodic++
			mu.Unlock()
		}
	})
	if _, err := drainWithin(t, sc, 30*time.Second); err != nil {
		t.Fatalf("drain: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if periodic < 2 {
		t.Fatalf("the target synced %d time(s) while it wrote ~2 MiB in 1 MiB steps; want at least 2", periodic)
	}
}

// A target whose final sync returns after the source gave up on the copy
// (its stall bound) does not place the disk: the source has rolled the move
// back and runs the VM, and a placed copy would be a stray full copy of its
// disk on the target. The scratch file goes too.
//
// Mutation: place without checking the stream — the disk appears on the
// target, red.
func TestFleet_ColdDiskCopyTheSourceGaveUpOnIsNotPlaced(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.src.Server.SetColdDiskStallForTest(300 * time.Millisecond)
	release := make(chan struct{})
	var once sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseNow)
	sc.dst.Server.SetColdDiskSyncHookForTest(func(final bool) {
		if final {
			<-release
		}
	})
	progress, err := drainWithin(t, sc, 30*time.Second)
	assertIncomplete(t, err)
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "no progress") {
		t.Fatalf("drain progress for os1 = %+v, want failed, the copy aborted", p)
	}
	dst := sc.file(sc.dst, sc.disk)
	scratch := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".receiving-*")
	if m, _ := filepath.Glob(scratch); len(m) == 0 {
		t.Fatal("the target holds no scratch file while its final sync is wedged")
	}
	releaseNow()
	eventually(t, 15*time.Second, "the target to finish its receive", func() bool {
		m, _ := filepath.Glob(scratch)
		return len(m) == 0
	})
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		t.Fatalf("the target placed the disk at %s after the source gave up on the copy (stat: %v)", dst, err)
	}
	sc.assertRunningOnSource(t)
}

// A disk file already on the target that no migration of this attempt made
// (one a rolled-back move placed in the instant after its source gave up, or
// an earlier stay's) refuses the move before the guest is shut down, and the
// refusal names the exact way out: the rename that sets the file aside, and
// the command that then lists and keeps it. The file is left as it was.
//
// Mutation: the old wording (<path>.superseded-<time>) — red.
func TestFleet_DrainColdMoveNamesTheWayOutOfAStrayTargetDisk(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	dst := sc.file(sc.dst, sc.disk)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("a stray copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	progress, err := drainWithin(t, sc, 30*time.Second)
	assertIncomplete(t, err)
	p := progress["os1"]
	if p == nil || p.Status == "done" {
		t.Fatalf("drain progress for os1 = %+v, want the move refused", p)
	}
	if want := "`mv " + dst + " " + dst + ".superseded-"; !strings.Contains(p.Error, want) ||
		!strings.Contains(p.Error, "`lv host superseded-disks "+sc.dst.Name+"`") {
		t.Fatalf("refusal = %q; want the rename (%s<time>`) and `lv host superseded-disks %s`", p.Error, want, sc.dst.Name)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Fatalf("os1 was shut down %d time(s); the refusal must come before the shutdown", n)
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != "a stray copy" {
		t.Fatalf("the stray file changed (err %v, %q)", err, got)
	}
	if active, _ := sc.src.Virt.DomainIsActive("os1"); !active {
		t.Fatal("os1 is not running on the source")
	}
}
