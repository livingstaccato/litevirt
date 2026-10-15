package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// destroyedClaims counts web's vm.stopped/ok events that say its domain was
// destroyed.
func (st *stuckStart) destroyedClaims(t *testing.T) int {
	t.Helper()
	n := 0
	for _, e := range st.events(t, "vm.stopped", "ok") {
		if strings.Contains(e.Detail, "was destroyed") {
			n++
		}
	}
	return n
}

// cancelledLateWithLibvirtDown cancels st's held start, then makes libvirt
// answer the start (successfully) while it answers neither a destroy nor a
// state read, and waits for the late answer to be handled.
func cancelledLateWithLibvirtDown(t *testing.T, st *stuckStart) *libvirtfake.Fake {
	t.Helper()
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	fake := st.s.virt.(*libvirtfake.Fake)
	down := errors.New("libvirt: connection reset")
	fake.FailDestroyDomain = func(string) error { return down }
	fake.FailDomainState = func(string) error { return down }
	close(st.release)
	st.waitLockFree(t, "after libvirt answered the cancelled start")
	return fake
}

// CR8 c-0002: the late answer to a cancelled start took a state read that
// failed for "not running": a destroy that failed while libvirt was down was
// then recorded as done (vm.stopped/ok, "destroyed"), and the durable record
// was dropped, so nothing tried again while the domain ran on. An unknown
// outcome now keeps the record, says nothing was destroyed, and the sweep
// destroys the domain once libvirt answers.
//
// Mutations: the unconditional drop back — no record after the late answer:
// red. An unreadable state taken for not running — a destroyed claim: red.
func TestCancelledStart_AnUnknownLateOutcomeKeepsTheRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		mk   func(*testing.T) *stuckStart
	}{
		{"stopped row", heldStart},
		{"error row", erroredHeldStart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.mk(t)
			st.s.liveStateWait = 150 * time.Millisecond
			fake := cancelledLateWithLibvirtDown(t, st)
			if n := st.destroyedClaims(t); n != 0 {
				t.Fatalf("%d events claim the domain was destroyed, though neither the destroy nor a state read answered", n)
			}
			if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
				t.Fatalf("the record after an unknown outcome: %+v, want it kept", recs)
			}
			// libvirt answers again: the sweep destroys the domain.
			fake.FailDestroyDomain, fake.FailDomainState = nil, nil
			st.sweep(t)
			if st.domainActive(t) {
				t.Fatal("the cancelled start's domain runs after the sweep")
			}
			if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
				t.Fatalf("the record outlived the destroy: %+v", recs)
			}
		})
	}
}

// A late failure whose domain state cannot be read keeps the record too: the
// start has answered (nothing is pending), so a later pass that finds the
// domain shut off ends it.
func TestCancelledStart_ALateFailureWithAnUnknownStateKeepsTheRecord(t *testing.T) {
	st := heldStart(t)
	st.s.liveStateWait = 150 * time.Millisecond
	if _, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	fake := st.s.virt.(*libvirtfake.Fake)
	st.answer.Store(errors.New("qemu: cannot open disk"))
	fake.FailDomainState = func(string) error { return errors.New("libvirt: connection reset") }
	close(st.release)
	st.waitLockFree(t, "after libvirt's late failure")
	recs := st.cancelledStartsOnDisk(t)
	if len(recs) != 1 || !recs[0].Ran {
		t.Fatalf("the record after a late failure with an unknown state: %+v, want it kept, its start answered", recs)
	}
	fake.FailDomainState = nil
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("a record whose start answered outlived a shut-off domain: %+v", recs)
	}
}

// CR8 c-0001: each stop of a VM whose start libvirt has not answered left a
// goroutine blocked on the VM's mutex for as long as the start held it, so
// repeated stops grew the daemon without bound. Stops asked while the start
// is held, and while it is still within its wait, now leave O(1) waiters.
//
// Mutation: the per-request goroutine on lockVM back — the goroutine count
// grows with the number of stops: red.
func TestStopVM_RepeatedStopsOfAHeldStartLeaveNoWaiters(t *testing.T) {
	st := newStuckStart(t)
	st.s.startDomainWait = 400 * time.Millisecond
	started := make(chan error, 1)
	go func() {
		_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
		started <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := st.s.startFlightOf("web"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the start never began")
		}
		time.Sleep(5 * time.Millisecond)
	}
	base := runtime.NumGoroutine()
	const n = 60
	stop := func() {
		_, err := st.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "web"})
		if status.Code(err) != codes.Unavailable {
			t.Errorf("a stop of a held start = %v, want Unavailable", err)
		}
	}
	// Half are asked while the start is still within its wait (they queue
	// for the lock, then see it held), half once it is held.
	var wg sync.WaitGroup
	for i := 0; i < n/2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); stop() }()
	}
	wantStartInFlight(t, "start", <-started)
	for i := 0; i < n/2; i++ {
		stop()
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	if grew := runtime.NumGoroutine() - base; grew > 5 {
		t.Fatalf("%d stops of a held start left %d more goroutines, want O(1)", n, grew)
	}
	close(st.release)
	st.waitLockFree(t, "after libvirt answered the start")
}

// unreadableRecord writes a cancelled-starts.json that does not parse.
func unreadableRecord(t *testing.T, s *Server) {
	t.Helper()
	if err := os.WriteFile(s.cancelledStartsPath(), []byte("[{trunc"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// CR8 c-0004/c-0008: an unreadable cancelled-starts.json made the probe answer
// yes for every VM on the host, switching restart policy and the desync heal
// off host-wide. The last good read is now kept and answers for the VMs it
// names; with no good read, only a row that says what a cancel writes is held.
// The file is read again once per sweep, not by every probe, and a host
// condition says it cannot be read.
//
// Mutations: every VM held on a load error — db's crashed row is held: red.
// The last good read thrown away — web is not held: red. No condition: red.
func TestCancelledStart_AnUnreadableFileHoldsOnlyWhatItMayName(t *testing.T) {
	st := newStuckStart(t)
	st.restarted(t, "error", "failover start failed")
	recs := st.cancelledStartsOnDisk(t)
	recs[0].Row = "error"
	raw, _ := json.Marshal(recs)
	if err := os.WriteFile(st.s.cancelledStartsPath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	// A good read, then the file breaks: the read in memory answers.
	if !st.s.HasCancelledStart("web", "error", "failover start failed") {
		t.Fatal("web's record is not reported")
	}
	unreadableRecord(t, st.s)
	st.sweep(t)
	if !st.s.HasCancelledStart("web", "error", "failover start failed") {
		t.Fatal("web, named by the good read, is not held")
	}
	if st.s.HasCancelledStart("db", "error", "failover start failed") {
		t.Fatal("db, named by no read, is held")
	}

	// A daemon that never read it: only a row a cancel could have written,
	// and a host condition says the file cannot be read.
	st2 := newStuckStart(t)
	st2.s.db, st2.s.dataDir = st.s.db, st.s.dataDir
	unreadableRecord(t, st2.s)
	st2.sweep(t)
	if !st2.conditionActive(t, condCancelledStartsUnreadable) {
		t.Fatal("no host condition says the record of cancelled starts cannot be read")
	}
	if st2.s.HasCancelledStart("db", "stopped", "crashed") {
		t.Fatal("a crashed VM is held because the file cannot be read")
	}
	if !st2.s.HasCancelledStart("db", "error", "failover start failed") {
		t.Fatal("an error row is not held although the unreadable file may name it")
	}
	// The probe does not read the file: a fix takes effect at the next sweep.
	if err := os.Remove(st2.s.cancelledStartsPath()); err != nil {
		t.Fatal(err)
	}
	if !st2.s.HasCancelledStart("db", "error", "failover start failed") {
		t.Fatal("the probe read the file itself; it is read once per sweep")
	}
	st2.sweep(t)
	if st2.s.HasCancelledStart("db", "error", "failover start failed") {
		t.Fatal("db is still held after the sweep read the removed file")
	}
	if st2.conditionActive(t, condCancelledStartsUnreadable) {
		t.Fatal("the condition outlived the file's fix")
	}
}

// conditionActive reports whether this host's held_start condition code is
// raised and not resolved.
func (st *stuckStart) conditionActive(t *testing.T, code string) bool {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), st.s.db, heldStartEvaluator, code, "host", st.s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	return found && row.Lifecycle != corrosion.ConditionResolved
}

// CR8 c-0005: the observation that the cancelled start's domain ran was kept
// only in memory, so a daemon restart between the pass that saw it running
// and the next left the record (and an error row's suppression) for good. It
// is now kept in the record.
//
// Mutation: ran kept only in memory — the new daemon keeps the record: red.
func TestCancelledStart_ARanObservationSurvivesARestart(t *testing.T) {
	st := newStuckStart(t)
	st.s.liveStateWait = 150 * time.Millisecond
	st.restarted(t, "stopped", "operator-stop")
	unlock := st.s.lockVM("web") // a lifecycle call holds the VM: no destroy this pass
	st.sweep(t)
	unlock()
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 || !recs[0].Ran {
		t.Fatalf("the record after its domain was seen running: %+v, want ran", recs)
	}
	// The domain stops; a new daemon reads the record.
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	st.s.cancelledStarts = cancelledStarts{}
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("a record whose domain ran outlived a restart and the domain's stop: %+v", recs)
	}
}

// CR8 c-0005: a libvirt daemon (libvirtd or virtqemud) that restarted since
// the record was made took every start it had queued with it, so a domain
// that does not run then has no start pending: the record ends. The same
// daemon, or one that cannot be identified, ends nothing.
//
// Mutation: the daemon not compared — the record is kept: red.
func TestCancelledStart_ALibvirtRestartEndsTheRecord(t *testing.T) {
	st := newStuckStart(t)
	st.restartedAt(t, "stopped", "operator-stop", time.Now().Add(-time.Hour))
	setLibvirtd := func(id string) {
		recs := st.cancelledStartsOnDisk(t)
		recs[0].Libvirtd = id
		raw, _ := json.Marshal(recs)
		if err := os.WriteFile(st.s.cancelledStartsPath(), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		st.s.cancelledStarts = cancelledStarts{}
	}
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	setLibvirtd("1234:5000")

	st.s.libvirtdID = func() string { return "1234:5000" }
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
		t.Fatalf("the same libvirt daemon ended the record: %+v", recs)
	}
	st.s.libvirtdID = func() string { return "" }
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 1 {
		t.Fatalf("a daemon that cannot be identified ended the record: %+v", recs)
	}
	st.s.libvirtdID = func() string { return "4321:9000" }
	st.sweep(t)
	if recs := st.cancelledStartsOnDisk(t); len(recs) != 0 {
		t.Fatalf("a restarted libvirt daemon left the record: %+v", recs)
	}
}

// CR8 c-0005: a record kept past an hour is named in a host condition, which
// says what it suppresses and that `lv start` ends it; the condition resolves
// once no such record is left.
func TestCancelledStart_ALongKeptRecordRaisesACondition(t *testing.T) {
	st := newStuckStart(t)
	st.restartedAt(t, "stopped", "operator-stop", time.Now().Add(-2*time.Hour))
	st.s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateShutdown)
	st.sweep(t)
	row, found, err := corrosion.GetHealthCondition(context.Background(), st.s.db, heldStartEvaluator, condCancelledStartKept, "host", st.s.hostName)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("no condition for a record kept 2h: %+v %v %v", row, found, err)
	}
	if !strings.Contains(row.Evidence, `"web"`) || !strings.Contains(row.Evidence, "lv start") {
		t.Fatalf("the condition's evidence %s, want web named and lv start", row.Evidence)
	}
	if err := corrosion.UpdateVMState(context.Background(), st.s.db, "web", "running", ""); err != nil {
		t.Fatal(err)
	}
	st.sweep(t)
	if st.conditionActive(t, condCancelledStartKept) {
		t.Fatal("the condition outlived the record")
	}
}

// Reads of the live daemon's identity: a process named libvirtd or
// virtqemud, its pid and start time.
func TestLibvirtdIdentity_ParsesStat(t *testing.T) {
	id, ok := libvirtdIdentityFromStat("4242 (virtqemud) S 1 4242 4242 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 18 0 77123 1 2 3")
	if !ok || id != "4242:77123" {
		t.Fatalf("identity = %q %v, want 4242:77123", id, ok)
	}
	if _, ok := libvirtdIdentityFromStat("garbage"); ok {
		t.Fatal("garbage parsed")
	}
}
