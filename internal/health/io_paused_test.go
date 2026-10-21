package health

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func ioPausedOpen(t *testing.T, db *corrosion.Client, vm string) bool {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), db, VMIOPausedEvaluator, CondVMIOPaused, "vm", vm)
	if err != nil {
		t.Fatalf("read vm_io_paused %s: %v", vm, err)
	}
	return ok && row.Lifecycle != corrosion.ConditionResolved
}

// A domain paused on an I/O error raises vm_io_paused for a VM this host
// owns; an operator's pause, a running domain and another host's VM raise
// nothing. Resumed, it resolves; while libvirt does not answer for the
// domain, it stays as it was.
//
// Mutation: compare st.Reason alone ("paused") in reportIOPausedVMs — the
// operator-paused VM raises the condition too, and this goes red.
func TestReconciler_IOPausedVMRaisesAndResolves(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	fake := libvirtfake.New()
	for _, vm := range []struct{ name, host string }{
		{"full", "node-a"}, {"user", "node-a"}, {"up", "node-a"}, {"elsewhere", "node-b"},
	} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: vm.name, HostName: vm.host, State: "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
		if err := fake.DefineDomain(`<domain type='kvm'><name>` + vm.name + `</name></domain>`); err != nil {
			t.Fatalf("DefineDomain: %v", err)
		}
		fake.SetState(vm.name, libvirtfake.StateRunning)
	}
	for _, name := range []string{"full", "elsewhere"} {
		if err := fake.PauseOnIOError(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := fake.SuspendDomain("user"); err != nil {
		t.Fatal(err)
	}
	r := NewReconciler("node-a", t.TempDir(), db, fake)

	// The decisions a paused-on-I/O-error domain reaches: not a stop, no restart.
	st, err := fake.DomainStateReason("full")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, sync := classifyStop(st.State, st.Reason); sync {
		t.Errorf("classifyStop(%q, %q) syncs a stop for a guest paused on an I/O error", st.State, st.Reason)
	}
	if restart, why := restartDecision(st.Reason, "", false, "always"); restart {
		t.Errorf("restartDecision restarts a guest paused on an I/O error: %s", why)
	}

	r.reportIOPausedVMs(ctx)
	r.reportIOPausedVMs(ctx) // idempotent: an open row is not rewritten
	for name, want := range map[string]bool{"full": true, "user": false, "up": false, "elsewhere": false} {
		if got := ioPausedOpen(t, db, name); got != want {
			t.Errorf("vm_io_paused open for %s = %v, want %v", name, got, want)
		}
	}

	// libvirt does not answer for the domain: what it was stays.
	if err := fake.ResumeDomain("full"); err != nil {
		t.Fatal(err)
	}
	fake.FailDomainStateReason = func(name string) error {
		if name == "full" {
			return errors.New("libvirt: no answer")
		}
		return nil
	}
	r.reportIOPausedVMs(ctx)
	if !ioPausedOpen(t, db, "full") {
		t.Errorf("vm_io_paused resolved for a domain whose state libvirt did not report")
	}
	fake.FailDomainStateReason = nil
	r.reportIOPausedVMs(ctx)
	if ioPausedOpen(t, db, "full") {
		t.Errorf("vm_io_paused still open for a resumed guest")
	}
}

// On a host in write quarantine every pass's raise is refused. The warning
// about it is logged once, not once per pass, until ioPausedWarnEvery has
// gone by.
//
// Mutation: log on every failed raise (skip ioPausedWarn.due) — three
// passes log three warnings and this goes red.
func TestReconciler_IOPausedRaiseFailureWarnsRateLimited(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	fake := libvirtfake.New()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "full", HostName: "node-a", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>full</name></domain>`); err != nil {
		t.Fatal(err)
	}
	fake.SetState("full", libvirtfake.StateRunning)
	if err := fake.PauseOnIOError("full"); err != nil {
		t.Fatal(err)
	}
	db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): test" })
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	now := time.Now()
	r.Now = func() time.Time { return now }

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for i := 0; i < 3; i++ {
		r.reportIOPausedVMs(ctx)
	}
	if n := strings.Count(buf.String(), "raising vm_io_paused failed"); n != 1 {
		t.Errorf("3 refused passes logged %d warnings, want 1:\n%s", n, buf.String())
	}
	now = now.Add(ioPausedWarnEvery)
	r.reportIOPausedVMs(ctx)
	if n := strings.Count(buf.String(), "raising vm_io_paused failed"); n != 2 {
		t.Errorf("a refused pass %v later logged no new warning (%d in all)", ioPausedWarnEvery, n)
	}
}
