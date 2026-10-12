package grpcapi

import (
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// console_password_v1 is advertised on the BUILD, whatever
// enforcement.console_password says. Ask where the guarantee is enforced:
// presenting a password is unconditional in this build, so a flag-off host
// still opens every console another host passworded, and nobody relies on a
// peer's flag. Withholding the token on a flag-off host would let one
// opted-out host (a witness, an operator who wants open consoles on one
// machine) keep every console in the fleet open. The flag-off posture is
// reported in not_enforcing instead.
//
// Mutation "withhold console_password_v1 while the flag is off" — red.
func TestAdvertise_ConsolePasswordIsUnconditional(t *testing.T) {
	for _, on := range []bool{false, true} {
		s := testServer(t)
		s.SetConsolePassword(on)
		if !slices.Contains(s.advertisedCapabilities(), capabilities.ConsolePasswordV1) {
			t.Errorf("%s is not advertised with enforcement.console_password=%v; the token states "+
				"that this build presents a console's password, which no flag changes",
				capabilities.ConsolePasswordV1, on)
		}
	}
	off := testServer(t)
	off.SetConsolePassword(false)
	if !slices.Contains(off.notEnforcingTokens(), capabilities.ConsolePasswordV1) {
		t.Error("the token is advertised with the flag off but not_enforcing does not say so")
	}
	if !capabilities.ReplicationGated(capabilities.ConsolePasswordV1) {
		t.Error("console_password_v1 must wait for every replication recipient, a maintenance host on an older build included")
	}
	if capabilities.Mandatory(capabilities.ConsolePasswordV1) {
		t.Error("console_password_v1 has a kill switch (enforcement.console_password); it is not mandatory")
	}
}

// policyRecorder is a backend that records the console password policy it is
// handed.
type policyRecorder struct {
	*libvirtfake.Fake
	policy func() bool
}

func (p *policyRecorder) SetConsolePasswordPolicy(fn func() bool) { p.policy = fn }

// The production constructor hands the libvirt client ConsolePasswordActive,
// so every define on the host — the health reconciler's too, which shares the
// client — applies it. (The fleet builds its servers with NewServerForTests,
// so it cannot catch this wiring going missing.)
//
// Mutation "NewServer does not wire the policy" — red.
func TestNewServer_WiresTheConsolePasswordPolicy(t *testing.T) {
	rec := &policyRecorder{Fake: libvirtfake.New()}
	s := NewServer("h1", t.TempDir(), t.TempDir(), nil, rec, nil)
	if rec.policy == nil {
		t.Fatal("NewServer did not hand the backend a console password policy")
	}
	s.SetConsolePassword(true)
	if rec.policy() {
		t.Error("the wired policy is on with nothing latched")
	}
}

// Without a gate nothing has latched, so no password is set even with the
// flag on: an older host could be holding the guest next.
func TestConsolePasswordActive_NeedsTheLatch(t *testing.T) {
	s := testServer(t)
	s.SetConsolePassword(true)
	if s.ConsolePasswordActive() {
		t.Fatal("ConsolePasswordActive with no gate (nothing latched)")
	}
}
