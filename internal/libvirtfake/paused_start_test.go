package libvirtfake

import (
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// As libvirt.Client (review I4, F7 m3 X2): a paused start that fails reports
// PausedDone only once its domain is no longer paused; one whose destroy does
// not land is left paused and reported kept (PausedKept).
//
// Mutation: the fake's PausedDone unconditional — red.
func TestStartDomain_PausedDoneOnlyOnceTheStartEnded(t *testing.T) {
	for name, tc := range map[string]struct {
		destroyFails bool
		done, kept   bool
	}{
		"destroy lands":        {done: true},
		"destroy did not land": {destroyFails: true, kept: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := New()
			if err := f.DefineDomain(`<domain type='kvm'><name>web</name></domain>`); err != nil {
				t.Fatal(err)
			}
			done, kept := false, false
			f.SetStartGuard(libvirt.StartGuard{
				Before:      func(string) (bool, error) { return true, nil },
				AfterPaused: func(string) error { return errors.New("refused") },
				PausedDone:  func(string) { done = true },
				PausedKept:  func(string, error) { kept = true },
			})
			if tc.destroyFails {
				f.FailDestroyDomain = func(string) error { return errors.New("connection reset") }
			}
			if err := f.StartDomain("web"); err == nil {
				t.Fatal("a refused start succeeded")
			}
			if done != tc.done || kept != tc.kept {
				t.Fatalf("PausedDone %v, PausedKept %v; want %v, %v", done, kept, tc.done, tc.kept)
			}
		})
	}
}

// DomainQEMUStatus mirrors QMP query-status: prelaunch only for a domain
// created paused whose vCPUs never ran.
func TestDomainQEMUStatus(t *testing.T) {
	f := New()
	if err := f.DefineDomain(`<domain type='kvm'><name>web</name></domain>`); err != nil {
		t.Fatal(err)
	}
	f.SetState("web", StatePaused)
	if st, err := f.DomainQEMUStatus("web"); err != nil || st != libvirt.QEMUStatusPrelaunch {
		t.Fatalf("created paused: %q, %v; want prelaunch", st, err)
	}
	if err := f.ResumeDomain("web"); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.DomainQEMUStatus("web"); st != "running" {
		t.Fatalf("resumed: %q, want running", st)
	}
	if err := f.SuspendDomain("web"); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.DomainQEMUStatus("web"); st != "paused" {
		t.Fatalf("suspended after it ran: %q, want paused", st)
	}
	f.SetState("web", StateShutdown)
	if _, err := f.DomainQEMUStatus("web"); err == nil {
		t.Fatal("an inactive domain reported a run state")
	}
	f.SetState("web", StatePaused)
	if st, _ := f.DomainQEMUStatus("web"); st != libvirt.QEMUStatusPrelaunch {
		t.Fatalf("a new QEMU created paused: %q, want prelaunch", st)
	}
}
