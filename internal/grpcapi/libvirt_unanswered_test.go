package grpcapi

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A libvirt call whose goroutine ends without returning gives what waits on
// it an answer: errLibvirtCallUnanswered. These are the two places a
// goroutine of the daemon makes a libvirt call for another to wait on.

// The migration's libvirt call ends without an answer while the source runs:
// the move ends as a migration that failed with the guest still on the
// source (the row running there, the marker gone), instead of the request
// waiting for good.
//
// Mutation: the result sent after the call instead of from a defer —
// MigrateVM never returns, red.
func TestMigrateVM_AMigrationCallThatEndsUnansweredFailsTheMove(t *testing.T) {
	r := newFwlRig(t, fwlOpts{})
	r.srcFake.OnMigrateToTarget = func(string, string, lv.MigrateParams) error {
		runtime.Goexit()
		return nil
	}
	err := within(t, time.Minute, "a migration whose libvirt call never answers", r.migrate)
	if err == nil || !strings.Contains(err.Error(), errLibvirtCallUnanswered.Error()) {
		t.Fatalf("the move returned %v, want it failed with %q", err, errLibvirtCallUnanswered)
	}
	if vm := r.row(); vm.HostName != "src-host" || vm.State != "running" {
		t.Errorf("row %s on %s, want running on src-host", vm.State, vm.HostName)
	}
	if m, ok := r.marker(); ok {
		t.Errorf("marker left %+v", m)
	}
}

// The bounded start's libvirt call ends without an answer after the start
// was held: the held start is settled as a start that failed with that
// answer (the row as before the start, the lock let go), instead of holding
// the VM for good.
//
// Mutation: the result sent after the call instead of from a defer — web's
// lock is never let go, red.
func TestStartVM_AHeldStartWhoseCallEndsUnansweredSettles(t *testing.T) {
	st := newStuckStart(t)
	st.s.virt.(*libvirtfake.Fake).FailStartDomain = func(string) error {
		st.calls.Add(1)
		<-st.release
		runtime.Goexit()
		return nil
	}
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	wantStartInFlight(t, "start", err)
	close(st.release)
	st.waitLockFree(t, "after the start's libvirt call ended unanswered")
	if vm := st.row(t); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Fatalf("web after the start ended unanswered: %s/%s, want stopped/operator-stop, as before the start", vm.State, vm.StateDetail)
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), st.s.db, "web", 50, "")
	found := false
	for _, e := range evs {
		if e.Type == "vm.started" && e.Result == "error" && strings.Contains(e.Detail, errLibvirtCallUnanswered.Error()) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no failed-start event naming the unanswered call: %+v", evs)
	}
}

// A panic in the libvirt call answers nothing: it crashes the daemon, and the
// waiter is not told anything first, so it takes no step against a crash
// already under way. Each case runs a child process that panics in the call
// and prints a line whenever the waiter asks libvirt anything after the
// panic; the line must never show. The interleaving is a race, so the child
// runs several times.
//
// Mutation: the deferred send without the recover and re-panic — the waiter
// asks libvirt about the source after the panic, red.
const unansweredPanicChild = "LV_UNANSWERED_PANIC_CHILD"

func unansweredPanicRuns(t *testing.T, test, mode string) {
	t.Helper()
	for i := 0; i < 20; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.count=1")
		cmd.Env = append(os.Environ(), unansweredPanicChild+"="+mode)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("run %d: the child did not crash:\n%s", i, out)
		}
		if !bytes.Contains(out, []byte("unanswered-probe panic")) {
			t.Fatalf("run %d: the child did not panic in the libvirt call:\n%s", i, out)
		}
		if bytes.Contains(out, []byte("WAITER-ACTED")) {
			t.Fatalf("run %d: the waiter acted after the panic:\n%s", i, out)
		}
	}
}

// unansweredPanicWatch prints WAITER-ACTED when f is asked a domain's state
// once panicked is set.
func unansweredPanicWatch(f *libvirtfake.Fake, panicked *atomic.Bool) {
	acted := func(string) error {
		if panicked.Load() {
			fmt.Fprintln(os.Stderr, "WAITER-ACTED")
		}
		return nil
	}
	f.FailDomainState = acted
	f.FailDomainStateReason = acted
}

func TestMigrateVM_APanicInTheMigrationCallAnswersNothing(t *testing.T) {
	if os.Getenv(unansweredPanicChild) != "migrate" {
		unansweredPanicRuns(t, "TestMigrateVM_APanicInTheMigrationCallAnswersNothing", "migrate")
		return
	}
	r := newFwlRig(t, fwlOpts{})
	var panicked atomic.Bool
	unansweredPanicWatch(r.srcFake, &panicked)
	r.srcFake.OnMigrateToTarget = func(string, string, lv.MigrateParams) error {
		panicked.Store(true)
		panic("unanswered-probe panic")
	}
	_ = r.migrate()
}

func TestStartVM_APanicInTheHeldStartsCallAnswersNothing(t *testing.T) {
	if os.Getenv(unansweredPanicChild) != "start" {
		unansweredPanicRuns(t, "TestStartVM_APanicInTheHeldStartsCallAnswersNothing", "start")
		return
	}
	st := newStuckStart(t)
	f := st.s.virt.(*libvirtfake.Fake)
	var panicked atomic.Bool
	unansweredPanicWatch(f, &panicked)
	f.FailStartDomain = func(string) error {
		<-st.release
		panicked.Store(true)
		panic("unanswered-probe panic")
	}
	_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
	wantStartInFlight(t, "start", err)
	close(st.release)
	time.Sleep(10 * time.Second) // the panic ends the process first
}
