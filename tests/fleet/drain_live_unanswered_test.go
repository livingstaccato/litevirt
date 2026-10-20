// Fleet scenarios for a drain's live move whose libvirt call ends without an
// answer: its goroutine ended inside MigrateToTarget (runtime.Goexit below
// it, as the fake's dead daemon ends one) without returning. The drain, or
// the background owner of a move whose abort libvirt did not answer, is
// given an answer anyway, and the guest stays on the source.
package fleet

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
)

// unansweredMove is the text of grpcapi's errLibvirtCallUnanswered.
const unansweredMove = "the libvirt call ended without an answer"

// unansweredChild names the scenario a child process runs. A drain that
// never ends would hold the cluster's teardown, and with it the package, so
// each scenario that drains runs in a child of its own, which exits when the
// drain does not end.
const unansweredChild = "LV_DRAIN_UNANSWERED_CHILD"

// inUnansweredChild runs test in a child process and reports false, failing
// t when the child fails; in that child it reports true, and the caller runs
// the scenario.
func inUnansweredChild(t *testing.T, test string) bool {
	t.Helper()
	if os.Getenv(unansweredChild) == test {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+test+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), unansweredChild+"="+test)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s failed in its child process (%v):\n%s", test, err, out)
	}
	return false
}

// liveDrainWithin drains sc's source. When the drain has not ended within d,
// it says so and ends the (child) process.
func liveDrainWithin(t *testing.T, sc *stuckLiveDrain, d time.Duration) (*pb.DrainProgress, error) {
	t.Helper()
	type res struct {
		p   *pb.DrainProgress
		err error
	}
	out := make(chan res, 1)
	go func() { p, err := sc.drain(t); out <- res{p, err} }()
	select {
	case r := <-out:
		return r.p, r.err
	case <-time.After(d):
		fmt.Fprintf(os.Stderr, "DRAIN-HUNG: the drain did not end within %s: it still waits on a live move whose libvirt call ended without an answer\n", d)
		os.Exit(3)
		return nil, nil
	}
}

// The drain's live move ends without libvirt's answer: the drain is told so,
// reports slow's move failed, and leaves the guest running on the source.
// No cold move follows, as libvirt's call said nothing of what it did.
//
// Mutations: the drain's result sent after the call instead of from a defer
// — the drain never ends, red. The unanswered call taken as an ordinary
// failure — a cold move shuts slow down, red.
func TestFleet_DrainLiveMoveWhoseCallEndsUnansweredStaysOnTheSource(t *testing.T) {
	if !inUnansweredChild(t, "TestFleet_DrainLiveMoveWhoseCallEndsUnansweredStaysOnTheSource") {
		return
	}
	sc := newStuckLiveDrainTimeout(t, false, 0)
	ctx := context.Background()
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name == "slow" {
			runtime.Goexit()
		}
		return nil
	}
	p, err := liveDrainWithin(t, sc, 15*time.Second)
	if err == nil || !strings.Contains(err.Error(), "slow") {
		t.Fatalf("drain = %v; want it incomplete, naming slow", err)
	}
	if p == nil || p.Status != "failed" || p.Strategy != pb.MigrateStrategy_MIGRATE_LIVE ||
		!strings.Contains(p.Error, unansweredMove) || !strings.Contains(p.Error, sc.src.Name) {
		t.Fatalf("frame for slow = %+v; want a failed LIVE move naming the unanswered call and %s", p, sc.src.Name)
	}
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Fatalf("slow was shut down %d time(s) on the source", n)
	}
	if st, _ := sc.src.Virt.DomainState("slow"); st != "running" {
		t.Fatalf("source domain state = %q, want running", st)
	}
	if sc.dst.Virt.DomainExists("slow") {
		t.Fatal("slow is defined on the target")
	}
	row, err := corrosion.GetVM(ctx, sc.src.DB, "slow")
	if err != nil || row == nil || row.HostName != sc.src.Name || row.State != "running" {
		t.Fatalf("VM row = %+v (err %v); want running on %s", row, err, sc.src.Name)
	}
}

// The live move reaches its migration policy timeout, libvirt does not
// answer the abort, and the move goes to a background owner. Its libvirt
// call then ends without an answer: the owner is told so, and the row goes
// back to running on the source instead of staying migrating for the
// owner's one-hour ceiling.
//
// Mutation: the drain's result sent after the call instead of from a defer
// — the row stays migrating, red.
func TestFleet_BackgroundDrainMoveWhoseCallEndsUnansweredSettlesOnTheSource(t *testing.T) {
	if !inUnansweredChild(t, "TestFleet_BackgroundDrainMoveWhoseCallEndsUnansweredSettlesOnTheSource") {
		return
	}
	sc := newStuckLiveDrain(t, false)
	release := releaseOnCleanup(t)
	sc.src.Server.SetDrainAbortGraceForTest(300 * time.Millisecond)
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name != "slow" {
			return nil
		}
		<-release // the abort is not answered
		runtime.Goexit()
		return nil
	}
	p, _ := liveDrainWithin(t, sc, 15*time.Second)
	if p == nil || p.Status != "failed" || !strings.Contains(p.Error, "background") {
		t.Fatalf("frame for slow = %+v; want failed, left to the background", p)
	}
	close(release)
	waitRow(t, sc.src, sc.src.Name, "running")
	if n := sc.srcOps("shutdown"); n != 0 {
		t.Fatalf("slow was shut down %d time(s) on the source", n)
	}
	if sc.dst.Virt.DomainExists("slow") {
		t.Fatal("slow is defined on the target")
	}
}

// A panic in the drain's libvirt call answers nothing: it crashes the
// daemon, and the drain is not told anything first, so it takes no step
// against a crash already under way. A child process panics in the call and
// prints a line whenever the drain asks libvirt anything after the panic;
// the line must never show. The interleaving is a race, so the child runs
// several times.
//
// Mutation: the deferred send without the recover and re-panic — the drain
// asks libvirt about slow after the panic, red.
const drainPanicChild = "LV_DRAIN_UNANSWERED_PANIC_CHILD"

func TestFleet_APanicInTheDrainsMigrationCallAnswersNothing(t *testing.T) {
	if os.Getenv(drainPanicChild) == "" {
		const name = "TestFleet_APanicInTheDrainsMigrationCallAnswersNothing"
		for i := 0; i < 20; i++ {
			cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.count=1")
			cmd.Env = append(os.Environ(), drainPanicChild+"=1")
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("run %d: the child did not crash:\n%s", i, out)
			}
			if !bytes.Contains(out, []byte("drain-unanswered-probe panic")) {
				t.Fatalf("run %d: the child did not panic in the libvirt call:\n%s", i, out)
			}
			if bytes.Contains(out, []byte("DRAIN-ACTED")) {
				t.Fatalf("run %d: the drain acted after the panic:\n%s", i, out)
			}
		}
		return
	}
	sc := newStuckLiveDrainTimeout(t, false, 0)
	var panicked atomic.Bool
	// Only the drain's own calls count: the node's other loops may ask
	// libvirt about slow at any moment.
	sc.src.Virt.FailDomainState = func(name string) error {
		if name == "slow" && panicked.Load() {
			buf := make([]byte, 64<<10)
			if strings.Contains(string(buf[:runtime.Stack(buf, false)]), "(*Server).drainOneVM") {
				fmt.Fprintln(os.Stderr, "DRAIN-ACTED")
			}
		}
		return nil
	}
	sc.src.Virt.FailMigrateToTarget = func(name, _ string) error {
		if name == "slow" {
			panicked.Store(true)
			panic("drain-unanswered-probe panic")
		}
		return nil
	}
	_, _ = sc.drain(t)
	time.Sleep(10 * time.Second) // the panic ends the process first
}
