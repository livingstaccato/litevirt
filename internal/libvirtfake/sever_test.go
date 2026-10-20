package libvirtfake

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// kill ends the calling goroutine, as a scenario's kill does.
func kill() { runtime.Goexit() }

// severedCall calls fn in a goroutine of its own and reports whether that
// goroutine ended inside it (returned=false) or fn returned.
func severedCall(t *testing.T, fn func()) (returned bool) {
	t.Helper()
	ended := make(chan bool, 1)
	go func() {
		ret := false
		defer func() { ended <- ret }()
		fn()
		ret = true
	}()
	select {
	case r := <-ended:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("the call neither returned nor ended its goroutine")
		return false
	}
}

// Every method a daemon can call on a severed Fake ends the caller before
// libvirt is asked anything: each exported method but the scenario's readers
// (severExempt), whatever its arguments, and a StateReader's calls. A method
// added without the gate fails here by name.
//
// Mutation: remove the gate from StartDomain — "StartDomain returned past a
// dead gate", red.
func TestDaemonGate_EveryDaemonMethodEndsTheCaller(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	reader := f.StateReader()
	before := f.Fingerprint()
	f.FenceDaemon()
	f.KillDaemon()
	typ := reflect.TypeOf(f)
	gated := 0
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		if severExempt[m.Name] {
			continue
		}
		args := []reflect.Value{reflect.ValueOf(f)}
		for j := 1; j < m.Type.NumIn(); j++ {
			args = append(args, reflect.Zero(m.Type.In(j)))
		}
		if m.Type.IsVariadic() {
			if severedCall(t, func() { m.Func.CallSlice(args) }) {
				t.Errorf("%s returned past a dead gate", m.Name)
			}
		} else if severedCall(t, func() { m.Func.Call(args) }) {
			t.Errorf("%s returned past a dead gate", m.Name)
		}
		gated++
	}
	if severedCall(t, func() { _, _ = reader.DomainState("vm1") }) {
		t.Error("a StateReader call returned past a dead gate")
	}
	calls := f.ReviveDaemon()
	if len(calls) != gated+1 {
		t.Errorf("the sever ended %d calls, want %d", len(calls), gated+1)
	}
	if after := f.Fingerprint(); after != before {
		t.Error("libvirt changed while the daemon was severed")
	}
	// Restored: the daemon's calls are answered again.
	if st, err := f.DomainState("vm1"); err != nil || st != "running" {
		t.Errorf("after the sever: DomainState = %q, %v", st, err)
	}
}

// A goroutine the sever ends runs its deferred calls, as Goexit does, and a
// deferred call that asks libvirt again is ended in turn without stopping the
// ones after it: the goroutine's own bookkeeping (a WaitGroup, a lock) is
// released.
func TestDaemonGate_DeferredCallsRunAndEndInTurn(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	f.FenceDaemon()
	f.KillDaemon()
	defer f.ReviveDaemon()
	done := make(chan struct{})
	reachedOuter := false
	go func() {
		defer close(done)
		defer func() { reachedOuter = true }()
		defer func() { _ = f.DestroyDomain("vm1") }() // ended in turn
		_ = f.StartDomain("vm1")
		t.Error("StartDomain returned past a dead gate")
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the goroutine did not end")
	}
	if !reachedOuter {
		t.Error("a deferred call after the one the sever ended did not run")
	}
	if st, _ := f.RawState("vm1"); st != StateRunning {
		t.Errorf("vm1 is %s, want running: nothing reached libvirt", st)
	}
}

// A callback that ends its goroutine while the Fake has released its lock
// for it (a scenario killing the daemon inside a migrate or at a resume)
// leaves the lock free: the next call is answered.
func TestDaemonGate_CallbackEndingItsGoroutineLeavesTheLockFree(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	f.OnMigrateToTarget = func(string, string, libvirt.MigrateParams) error {
		kill()
		return errors.New("unreachable")
	}
	if severedCall(t, func() { _ = f.MigrateToTarget("vm1", "qemu+tls://dst/system", libvirt.MigrateParams{Live: true}) }) {
		t.Fatal("MigrateToTarget returned past a callback that ended its goroutine")
	}
	f.SetState("vm2", StatePaused)
	f.OnRunning = func(name string) {
		if name == "vm2" {
			kill()
		}
	}
	if severedCall(t, func() { _ = f.ResumeDomain("vm2") }) {
		t.Fatal("ResumeDomain returned past a callback that ended its goroutine")
	}
	got := make(chan struct{})
	go func() {
		_, _ = f.DomainState("vm1")
		close(got)
	}()
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the Fake's lock was left held by the ended goroutine")
	}
}

// The fingerprint covers all of libvirtd's state, not only domains and
// operations: a snapshot, a bridge's MTU or a secret changes it.
//
// Mutation: Fingerprint hashes only the domains and the events — the bridge
// MTU change goes unseen, red.
func TestFingerprint_CoversTheWholeState(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	for _, change := range []struct {
		what string
		do   func()
	}{
		{"a bridge MTU", func() { f.SetBridgeMTU("br0", 9000) }},
		{"a secret", func() { _ = f.DefineCephSecret("8a1b2c3d-0000-4000-8000-000000000001", "client.x", []byte("k")) }},
		{"a domain's owner epoch", func() { _ = f.SetDomainOwnerEpoch("vm1", 7, true) }},
	} {
		before := f.Fingerprint()
		change.do()
		if f.Fingerprint() == before {
			t.Errorf("%s changed and the fingerprint did not", change.what)
		}
	}
	if a, b := f.Fingerprint(), f.Fingerprint(); a != b {
		t.Error("the fingerprint of an unchanged Fake differs between two reads")
	}
}

// A migration landing on a Fake whose daemon is dead is libvirtd's own
// doing: the source's goroutine that lands it is not ended.
func TestDaemonGate_MigrationLandingIsNotTheDaemons(t *testing.T) {
	f := New()
	f.FenceDaemon()
	f.KillDaemon()
	defer f.ReviveDaemon()
	if !severedCall(t, func() {
		f.LandMigratedState("<domain><name>vm9</name><uuid>8a1b2c3d-0000-4000-8000-000000000009</uuid></domain>", true)
	}) {
		t.Fatal("landing a migration on a severed Fake ended the caller")
	}
	if st, ok := f.RawState("vm9"); !ok || st != StatePaused {
		t.Errorf("vm9 is %v (present %v), want landed paused", st, ok)
	}
}

// A fenced gate holds a new call where it is, with no answer and no error,
// while a call admitted before the fence runs to its end and is counted
// until then; killing the gate then ends the held call. Nothing the held
// call would do reaches libvirt, and what the admitted call did is in the
// state taken once it returned (Codex I4: an effect admitted before the
// cutover lands before it, not after).
//
// Mutation: a fenced gate admits the call (state treated as alive) — the
// held call defines its domain, red.
func TestDaemonGate_FenceHoldsNewCallsAndDrainsAdmittedOnes(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	release := make(chan struct{})
	f.OnMigrateToTarget = func(string, string, libvirt.MigrateParams) error {
		<-release
		return nil
	}
	admitted := make(chan error, 1)
	go func() {
		admitted <- f.MigrateToTarget("vm1", "qemu+tls://dst/system", libvirt.MigrateParams{Live: true})
	}()
	if !waitFor(func() bool { return f.DaemonInFlight() == 1 }) {
		t.Fatal("the migrate was not admitted")
	}
	f.FenceDaemon()
	held := make(chan bool, 1)
	go func() {
		ret := false
		defer func() { held <- ret }()
		_ = f.DefineDomain("<domain><name>held</name><uuid>8a1b2c3d-0000-4000-8000-0000000000bb</uuid></domain>")
		ret = true
	}()
	select {
	case r := <-held:
		t.Fatalf("a call on a fenced gate went on (returned %v)", r)
	case <-time.After(200 * time.Millisecond):
	}
	if n := f.DaemonInFlight(); n != 1 {
		t.Errorf("%d calls in flight on the fenced gate, want the 1 admitted", n)
	}
	close(release)
	if err := <-admitted; err != nil {
		t.Fatalf("the admitted migrate: %v", err)
	}
	if !waitFor(func() bool { return f.DaemonInFlight() == 0 }) {
		t.Fatal("the admitted call is still counted once it returned")
	}
	before := f.Fingerprint()
	f.KillDaemon()
	if r := <-held; r {
		t.Error("the held call returned past the dead gate")
	}
	if _, ok := f.RawState("held"); ok {
		t.Error("the held call reached libvirt")
	}
	if f.Fingerprint() != before {
		t.Error("libvirt changed after the death")
	}
	if calls := f.ReviveDaemon(); len(calls) != 1 || calls[0] != "DefineDomain" {
		t.Errorf("the dead gate ended %v, want [DefineDomain]", calls)
	}
}

func waitFor(cond func() bool) bool {
	for i := 0; i < 1000; i++ {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// A call admitted before the fence that asks the Fake again on its own
// goroutine (a hook of its, or DomainState asking its connection) is one
// logical call: it passes the fenced gate and the drain completes. A new
// call on another goroutine still waits (Codex fix1 review I5).
//
// Mutation: admission is per gate pass, not per goroutine — the nested
// DomainExists waits at the fence and the admitted call never ends, red.
func TestDaemonGate_ANestedCallOfAnAdmittedOnePasses(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	f.DefineStoppedDomain("vm2", "52:54:00:00:00:02")
	fenced, nested := make(chan struct{}), make(chan bool, 1)
	f.FailUndefinePreserv = func(name string) error {
		<-fenced
		nested <- f.DomainExists("vm1")
		return nil
	}
	admitted := make(chan error, 1)
	go func() { admitted <- f.UndefineDomainPreservingState("vm2") }()
	if !waitFor(func() bool { return f.DaemonInFlight() == 1 }) {
		t.Fatal("the undefine was not admitted")
	}
	f.FenceDaemon()
	close(fenced)
	select {
	case ok := <-nested:
		if !ok {
			t.Error("the nested DomainExists did not see vm1")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the nested call of an admitted one waited at the fence")
	}
	if err := <-admitted; err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return f.DaemonInFlight() == 0 }) {
		t.Fatal("the admitted call did not drain")
	}
	other := make(chan struct{})
	go func() {
		defer close(other)
		_ = f.DomainExists("vm1")
	}()
	select {
	case <-other:
		t.Fatal("a new call went past the fence")
	case <-time.After(100 * time.Millisecond):
	}
	f.KillDaemon()
	<-other
	f.ReviveDaemon()
}

// A goroutine ended inside MigrateToTarget's hook runs MigrateToTarget's
// deferred calls with its MigrateParams unread since the hook was called.
// While those run, the Go runtime (1.26) scans the frame's parameter through
// the Goexit's _panic record, whose fp is the parameter's address; what the
// parameter held must still be allocated then, or the GC marks a freed object
// and the process dies: "fatal error: found pointer to free object". Each run
// is a child process: two cycles while the hook holds, then two more while
// MigrateToTarget's deferred leave waits on the gate.
//
// Mutation: without MigrateToTarget's keep-alive of its parameter, the child
// dies with "found pointer to free object", red.
const goexitMigrateChild = "LV_LIBVIRTFAKE_GOEXIT_MIGRATE_CHILD"

func TestDaemonGate_AGoexitInTheMigrateHookFreesNothingItsDefersFind(t *testing.T) {
	if os.Getenv(goexitMigrateChild) == "1" {
		goexitInTheMigrateHook()
		return
	}
	for i := 0; i < 5; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
		cmd.Env = append(os.Environ(), goexitMigrateChild+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil || bytes.Contains(out, []byte("fatal error")) {
			t.Fatalf("run %d: the child died (%v):\n%s", i, err, out)
		}
	}
}

// goexitInTheMigrateHook is the child of the test above.
func goexitInTheMigrateHook() {
	f := New()
	f.SetState("vm1", StateRunning)
	inGoexit := make(chan struct{})
	f.OnMigrateToTarget = func(string, string, libvirt.MigrateParams) error {
		// MigrateToTarget reads its parameter no more: two cycles free what
		// only the parameter holds, unless it is kept alive.
		runtime.GC()
		runtime.GC()
		// MigrateToTarget's deferred leave waits here, inside the Goexit.
		f.gate.mu.Lock()
		close(inGoexit)
		kill()
		return errors.New("unreachable")
	}
	go func() {
		// A fresh allocation that only the parameter references.
		p := libvirt.MigrateParams{Live: true, TargetAddress: strings.Repeat("a", 512)}
		_ = f.MigrateToTarget("vm1", "qemu+tls://dst/system", p)
	}()
	<-inGoexit
	time.Sleep(100 * time.Millisecond) // the goroutine parks in leave
	runtime.GC()
	runtime.GC()
	f.gate.mu.Unlock()
}
