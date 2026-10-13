package grpcapi

import (
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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
	policy func() lv.ConsolePolicy
}

func (p *policyRecorder) SetConsolePasswordPolicy(fn func() lv.ConsolePolicy) { p.policy = fn }

// The production constructor hands the libvirt client ConsolePasswordPolicy,
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
	if got := rec.policy(); got != lv.PolicyLeave {
		t.Errorf("the wired policy is %d with nothing latched, want PolicyLeave", got)
	}
}

// The policy is the latch of console_password_v1 — not another token's — and
// then the flag: untouched before it, fresh passwords with the flag on, none
// with it off (the kill switch).
//
// Mutation "Latched(SplitBrainGateV1)" — red. Mutation "flag ignored" — red.
func TestConsolePasswordPolicy_LatchThenFlag(t *testing.T) {
	s := testServer(t)
	s.SetConsolePassword(true)
	if got := s.ConsolePasswordPolicy(); got != lv.PolicyLeave {
		t.Fatalf("no gate: policy %d, want PolicyLeave", got)
	}
	// Every OTHER token latched, console_password_v1 not: an older peer.
	others := map[string]bool{}
	for _, tok := range capabilities.All() {
		others[tok] = tok != capabilities.ConsolePasswordV1
	}
	s.SetGate(fakeServerGate{enforcedTok: others})
	if got := s.ConsolePasswordPolicy(); got != lv.PolicyLeave {
		t.Fatalf("console_password_v1 not latched (everything else is): policy %d, want PolicyLeave", got)
	}
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.ConsolePasswordV1: true}})
	if got := s.ConsolePasswordPolicy(); got != lv.PolicySet {
		t.Fatalf("latched, flag on: policy %d, want PolicySet", got)
	}
	s.SetConsolePassword(false)
	if got := s.ConsolePasswordPolicy(); got != lv.PolicyStrip {
		t.Fatalf("latched, flag off: policy %d, want PolicyStrip", got)
	}
}

// vncUnavailableVirt is a backend on a host whose QEMU cannot do VNC
// passwords (FIPS).
type vncUnavailableVirt struct{ *libvirtfake.Fake }

func (vncUnavailableVirt) VNCPasswordUnavailable() string {
	return "qemu-kvm refuses VNC password authentication: Cipher backend does not support DES algorithm"
}

// A FIPS host with the flag on reports console_password_v1 in not_enforcing:
// it advertises the token (it presents every password a guest it holds has)
// but sets no VNC passwords.
//
// Mutation "not reported" — red.
func TestNotEnforcing_AHostWithoutVNCPasswordsReportsIt(t *testing.T) {
	s := testServer(t)
	s.virt = vncUnavailableVirt{libvirtfake.New()}
	s.SetConsolePassword(true)
	if !slices.Contains(s.advertisedCapabilities(), capabilities.ConsolePasswordV1) {
		t.Fatal("a host without VNC passwords withheld the token; it must not hold the latch off")
	}
	if !slices.Contains(s.notEnforcingTokens(), capabilities.ConsolePasswordV1) {
		t.Fatal("a host without VNC passwords does not report console_password_v1 in not_enforcing")
	}
	able := testServer(t)
	able.SetConsolePassword(true)
	if slices.Contains(able.notEnforcingTokens(), capabilities.ConsolePasswordV1) {
		t.Error("a host that sets passwords reports console_password_v1 in not_enforcing")
	}
}
