package libvirtfake

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// TestFake_FireEvent_NoCallbackIsNoOp pins the constraint that keeps the fake
// safe for the ~40 fleet scenarios that never register a callback: firing into
// a fake with nothing registered must return silently, not panic.
func TestFake_FireEvent_NoCallbackIsNoOp(t *testing.T) {
	New().FireEvent("vm1", libvirt.DomainEventCrashed, 0)
}

// TestFake_FireEvent_DeliversToRegisteredCallback is the dispatch property: the
// callback sees exactly the domain, event and detail that were fired, and a
// second registration replaces the first rather than fanning out to both.
func TestFake_FireEvent_DeliversToRegisteredCallback(t *testing.T) {
	f := New()

	type call struct {
		domain string
		event  libvirt.DomainEventType
		detail int
	}
	var first, second []call
	f.RegisterDomainEventCallback(func(domain string, event libvirt.DomainEventType, detail int) {
		first = append(first, call{domain, event, detail})
	})

	f.FireEvent("vm1", libvirt.DomainEventCrashed, 7)
	if len(first) != 1 {
		t.Fatalf("callback got %d calls, want 1: %+v", len(first), first)
	}
	if got, want := (first[0]), (call{"vm1", libvirt.DomainEventCrashed, 7}); got != want {
		t.Fatalf("callback saw %+v, want %+v", got, want)
	}

	// Re-registering must hand every subsequent event to the NEW callback only.
	f.RegisterDomainEventCallback(func(domain string, event libvirt.DomainEventType, detail int) {
		second = append(second, call{domain, event, detail})
	})
	f.FireEvent("vm2", libvirt.DomainEventStopped, 1)
	if len(first) != 1 {
		t.Fatalf("replaced callback still received: %+v", first)
	}
	if got, want := len(second), 1; got != want {
		t.Fatalf("new callback got %d calls, want %d", got, want)
	}
	if got, want := (second[0]), (call{"vm2", libvirt.DomainEventStopped, 1}); got != want {
		t.Fatalf("new callback saw %+v, want %+v", got, want)
	}
}

// TestFake_FireEvent_CallbackMayReenterTheFake is the lock-discipline test. The
// registered callback is arbitrary daemon code that may call straight back into
// the fake, and f.mu is not reentrant — so FireEvent must copy the callback out
// and RELEASE the lock before invoking it. Someone "simplifying" FireEvent to
// `defer f.mu.Unlock()` deadlocks here.
//
// The call runs in a goroutine behind a 2s deadline so that bug surfaces as a
// red test in two seconds instead of hanging the package until the 10-minute
// panic timeout.
func TestFake_FireEvent_CallbackMayReenterTheFake(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)

	var (
		mu     sync.Mutex
		exists bool
	)
	f.RegisterDomainEventCallback(func(domain string, _ libvirt.DomainEventType, _ int) {
		// Both of these take f.mu.
		ok := f.DomainExists(domain)
		f.SetState(domain, StateShutdown)
		mu.Lock()
		exists = ok
		mu.Unlock()
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		f.FireEvent("vm1", libvirt.DomainEventCrashed, 0)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("FireEvent did not return within 2s: the callback deadlocked on f.mu " +
			"(FireEvent must release the lock before invoking it)")
	}

	mu.Lock()
	sawDomain := exists
	mu.Unlock()
	if !sawDomain {
		t.Error("callback's DomainExists(vm1) returned false, want true")
	}
	if got, err := f.DomainState("vm1"); err != nil || got != string(StateShutdown) {
		t.Errorf("callback's SetState did not take effect: state=%q err=%v", got, err)
	}
}

// TestFakeSetDomainOwnerEpoch_RefusesAPreEpochValue keeps the fake's marker
// contract identical to the real client's. A generation starts at 1, so 0 and
// negatives are refused — without this, a test could pass against a marker state
// internal/libvirt would never write.
func TestFakeSetDomainOwnerEpoch_RefusesAPreEpochValue(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	for _, epoch := range []int64{0, -1} {
		if err := f.SetDomainOwnerEpoch("vm1", epoch, true); err == nil {
			t.Errorf("the fake accepted epoch %d; the real client refuses it", epoch)
		}
	}
	if _, ok, _ := f.GetDomainOwnerEpoch("vm1"); ok {
		t.Error("a refused write still recorded a marker")
	}
	if err := f.SetDomainOwnerEpoch("vm1", 1, true); err != nil {
		t.Fatalf("epoch 1 is the first legal generation and must be accepted: %v", err)
	}
}

// Undefining an ACTIVE domain does not remove it: it survives as a TRANSIENT
// domain, keeps running and keeps its UUID — so it still holds its name, and a
// definition reusing that name with a different UUID must be refused.
//
// The contract matters because the production cutover depends on it: a handoff
// that undefined a running replacement and then redefined it under the new name
// would look like a rename here and fail against a real daemon.
func TestFake_TransientDomainStillHoldsItsName(t *testing.T) {
	f := New()
	if err := f.DefineDomain(`<domain><name>vm1</name><uuid>uuid-one</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := f.StartDomain("vm1"); err != nil {
		t.Fatal(err)
	}
	if err := f.UndefineDomainPreservingState("vm1"); err != nil {
		t.Fatal(err)
	}

	// Still there, still active, still holding the UUID.
	active, err := f.DomainIsActive("vm1")
	if err != nil || !active {
		t.Fatalf("an undefined ACTIVE domain must survive as transient: active=%v err=%v", active, err)
	}
	// Its name is not a free slot.
	if err := f.DefineDomain(`<domain><name>vm1</name><uuid>uuid-two</uuid></domain>`); err == nil {
		t.Error("a different UUID was accepted at a transient domain's name")
	}
	// Nor is its UUID available under another name.
	if err := f.DefineDomain(`<domain><name>vm2</name><uuid>uuid-one</uuid></domain>`); err == nil {
		t.Error("a transient domain's UUID was accepted under another name")
	}
	// Redefining it as ITSELF is how a transient domain is made persistent again.
	if err := f.DefineDomain(`<domain><name>vm1</name><uuid>uuid-one</uuid></domain>`); err != nil {
		t.Errorf("redefining a transient domain as itself must be allowed: %v", err)
	}

	// An INACTIVE domain, by contrast, is really gone after an undefine.
	if err := f.DefineDomain(`<domain><name>vm3</name><uuid>uuid-three</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := f.UndefineDomainPreservingState("vm3"); err != nil {
		t.Fatal(err)
	}
	if err := f.DefineDomain(`<domain><name>vm3</name><uuid>uuid-four</uuid></domain>`); err != nil {
		t.Errorf("a freed name must be reusable: %v", err)
	}
}

// libvirt gives a definition with no <uuid> a random one, so a redefine of an
// existing name without a uuid is refused there ("already exists with uuid"),
// as is a uuid an INACTIVE domain of another name holds ("already defined
// with uuid"). The fake refuses both, so a path that would fail on a real
// host fails here too (dupcreate re-review 3, m-5).
//
// Mutation: keep the existing domain's uuid on a no-uuid redefine — red; skip
// inactive domains in the uuid check — red.
func TestFake_DefineRefusesWhatLibvirtRefuses(t *testing.T) {
	f := New()
	if err := f.DefineDomain(`<domain><name>vm1</name><uuid>uuid-one</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := f.DefineDomain(`<domain><name>vm1</name></domain>`); err == nil {
		t.Error("a redefine of an existing name with no uuid was accepted")
	}
	if err := f.DefineDomain(`<domain><name>vm2</name><uuid>uuid-one</uuid></domain>`); err == nil {
		t.Error("an inactive domain's uuid was accepted under another name")
	}
	// A new name with no uuid gets one, and the domain itself redefines.
	if err := f.DefineDomain(`<domain type='kvm'><name>vm3</name></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := f.DefineDomain(`<domain><name>vm1</name><uuid>uuid-one</uuid></domain>`); err != nil {
		t.Errorf("redefining a domain as itself: %v", err)
	}
	if x, _ := f.DumpXMLInactive("vm3"); domainUUIDFromXML(x) == "" {
		t.Errorf("a definition with no uuid was stored with none: %s", x)
	}
}

// A redefine of an ACTIVE domain updates its persistent definition only: it
// keeps its runtime state and its live XML (virDomainDefineXML applies the new
// config at the next boot).
func TestFake_RedefineKeepsActiveRuntimeState(t *testing.T) {
	const (
		v1 = `<domain><name>vm1</name><uuid>uuid-one</uuid><memory>1</memory></domain>`
		v2 = `<domain><name>vm1</name><uuid>uuid-one</uuid><memory>2</memory></domain>`
	)
	for _, tc := range []struct {
		name  string
		setup func(f *Fake)
	}{
		{"running", func(f *Fake) {}},
		{"paused", func(f *Fake) { f.SetPaused("vm1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := New()
			if err := f.DefineDomain(v1); err != nil {
				t.Fatal(err)
			}
			if err := f.StartDomain("vm1"); err != nil {
				t.Fatal(err)
			}
			tc.setup(f)
			if err := f.DefineDomain(v2); err != nil {
				t.Fatal(err)
			}
			if active, err := f.DomainIsActive("vm1"); err != nil || !active {
				t.Fatalf("a redefined %s domain must stay active: active=%v err=%v", tc.name, active, err)
			}
			st, err := f.DomainStateReason("vm1")
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "paused" && st.Reason != "paused" {
				t.Errorf("redefined paused domain reason = %q, want paused", st.Reason)
			}
			if tc.name == "running" && st.State != "running" {
				t.Errorf("redefined running domain state = %q, want running", st.State)
			}
			if got := f.DefinedXML("vm1"); got != v2 {
				t.Errorf("persistent definition not updated: %s", got)
			}
			if live := f.liveXMLLocked("vm1"); live != v1 {
				t.Errorf("live XML must stay the booted one, got %s", live)
			}
		})
	}
}

// libvirt refuses to undefine a SHUT-OFF domain that holds snapshot metadata
// unless SNAPSHOTS_METADATA is passed ("cannot delete inactive domain with N
// snapshots"), and the fake refuses it the same way: the keep-state undefine
// and the plain undefine without removeStorage are refused, the --keep-disks
// undefine and the plain undefine with removeStorage are not. An ACTIVE domain
// is not refused: it survives as a transient one.
//
// Mutation: drop hasSnapshotsRefusalLocked from undefineKeepingState: red.
func TestFake_UndefineRefusedWhileSnapshotsExist(t *testing.T) {
	setup := func(t *testing.T, name string) *Fake {
		t.Helper()
		f := New()
		if err := f.DefineDomain(`<domain><name>` + name + `</name><uuid>uuid-` + name + `</uuid></domain>`); err != nil {
			t.Fatal(err)
		}
		if _, err := f.CreateSnapshot(name, "s1"); err != nil {
			t.Fatal(err)
		}
		return f
	}
	refused := func(t *testing.T, f *Fake, name string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "cannot delete inactive domain with 1 snapshots") {
			t.Fatalf("undefine of a shut-off domain with a snapshot = %v; want libvirt's refusal", err)
		}
		if !f.DomainExists(name) {
			t.Fatal("a refused undefine removed the domain")
		}
	}
	t.Run("preserving state", func(t *testing.T) {
		f := setup(t, "vm1")
		refused(t, f, "vm1", f.UndefineDomainPreservingState("vm1"))
	})
	t.Run("plain without storage", func(t *testing.T) {
		f := setup(t, "vm1")
		refused(t, f, "vm1", f.UndefineDomain("vm1", false))
	})
	for name, undef := range map[string]func(*Fake) error{
		"keep disks":         func(f *Fake) error { return f.UndefineDeletedDomainKeepingState("vm1") },
		"plain with storage": func(f *Fake) error { return f.UndefineDomain("vm1", true) },
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t, "vm1")
			if err := undef(f); err != nil {
				t.Fatalf("undefine: %v", err)
			}
			if f.DomainExists("vm1") {
				t.Fatal("the domain is still defined")
			}
		})
	}
	t.Run("active", func(t *testing.T) {
		f := setup(t, "vm1")
		if err := f.StartDomain("vm1"); err != nil {
			t.Fatal(err)
		}
		if err := f.UndefineDomainPreservingState("vm1"); err != nil {
			t.Fatalf("keep-state undefine of an active domain with a snapshot: %v", err)
		}
	})
}
