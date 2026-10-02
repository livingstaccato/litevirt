package corrosion

import "testing"

// Every (method, result) pair the fence paths actually write, and what each one
// establishes about the host.
//
// The pairs come from internal/fence (Method) and the two writers that turn a
// fence.Result into a row: the failover coordinator and the operator FenceHost
// RPC both write "fenced" for Success and "partial" otherwise, and the operator
// confirmation writes ("manual", "manual-confirmed").
//
// The distinction this exists for: an ssh "fenced" row and an ipmi "fenced" row
// look identical in the table and mean different things. IPMI powered the host
// off and then OBSERVED it off. SSH had a shell accept a poweroff command —
// nothing looks afterwards. Both used to read as "fenced".
func TestFenceAssurance_ClassifiesEveryWrittenPair(t *testing.T) {
	cases := []struct {
		method, result, want string
	}{
		{"ipmi", "fenced", FenceVerified},
		{"ipmi", "partial", FenceFailed},
		{"manual", "manual-confirmed", FenceOperatorConfirmed},
		// A manual fence never "succeeds" on its own; it waits for a human.
		// That is not a failure, whatever fence_failures_total says about it.
		{"manual", "partial", FenceAwaitingConfirmation},
		{"ssh", "fenced", FenceRequested},
		{"ssh", "partial", FenceFailed},
		// best-effort-ssh is the Method fenceSSH reports only when SSH itself
		// FAILED and lenient mode proceeded anyway: not even the request is known
		// to have arrived.
		{"best-effort-ssh", "fenced", FenceAssumed},
		// A watchdog fence stops the heartbeat; the reboot is a timer nobody
		// observes firing.
		{"watchdog", "fenced", FenceRequested},
		{"watchdog", "partial", FenceFailed},
	}
	for _, c := range cases {
		if got := FenceAssurance(c.method, c.result); got != c.want {
			t.Errorf("FenceAssurance(%q, %q) = %q, want %q", c.method, c.result, got, c.want)
		}
	}
}

// A pair this code does not recognise is unknown, never a success. A future
// strategy that forgot to extend the classification must not be counted as
// having powered anything off.
func TestFenceAssurance_UnrecognisedIsUnknown(t *testing.T) {
	for _, p := range [][2]string{{"redfish", "fenced"}, {"ssh", "weird"}, {"", ""}} {
		if got := FenceAssurance(p[0], p[1]); got != FenceUnknown {
			t.Errorf("FenceAssurance(%q, %q) = %q, want %q", p[0], p[1], got, FenceUnknown)
		}
	}
}

// FenceProofGrade is now DEFINED by the classification, and its answers must
// not move: it gates shared-disk ownership transfers, and this is a labelling
// change. Exactly verified and operator-confirmed pass.
func TestFenceProofGrade_IsUnchangedAndAgreesWithAssurance(t *testing.T) {
	proof := map[[2]string]bool{
		{"ipmi", "fenced"}:             true,
		{"manual", "manual-confirmed"}: true,
		{"ipmi", "partial"}:            false,
		{"manual", "partial"}:          false,
		{"ssh", "fenced"}:              false,
		{"ssh", "partial"}:             false,
		{"best-effort-ssh", "fenced"}:  false,
		{"watchdog", "fenced"}:         false,
		{"watchdog", "partial"}:        false,
		{"redfish", "fenced"}:          false,
	}
	for p, want := range proof {
		if got := FenceProofGrade(p[0], p[1]); got != want {
			t.Errorf("FenceProofGrade(%q, %q) = %v, want %v — a labelling change moved a shared-disk gate", p[0], p[1], got, want)
		}
		a := FenceAssurance(p[0], p[1])
		if agrees := a == FenceVerified || a == FenceOperatorConfirmed; agrees != want {
			t.Errorf("(%q, %q): assurance %q disagrees with FenceProofGrade=%v", p[0], p[1], a, want)
		}
	}
}

// A best-effort fence whose recovery relied on the host's partition pause is
// still a best-effort-ssh row — an older coordinator reads it as assumed — and
// only FenceAssuranceDetail, reading the detail, calls it self_paused.
//
// Mutation: classify by method alone — the relied-on row reads assumed and
// this goes red; drop the method check — an ipmi row with the prefix reads
// self_paused and this goes red.
func TestFenceAssuranceDetail_SelfPaused(t *testing.T) {
	relied := FencePauseReliance + "SSH failed (no route), proceeding anyway"
	if got := FenceAssuranceDetail("best-effort-ssh", "fenced", relied); got != FenceSelfPaused {
		t.Fatalf("relied-on best-effort row = %s, want %s", got, FenceSelfPaused)
	}
	if got := FenceAssurance("best-effort-ssh", "fenced"); got != FenceAssumed {
		t.Fatalf("the method/result classification moved: %s", got)
	}
	if got := FenceAssuranceDetail("best-effort-ssh", "fenced", "SSH failed"); got != FenceAssumed {
		t.Fatalf("a best-effort row without the prefix = %s, want assumed", got)
	}
	if got := FenceAssuranceDetail("ipmi", "fenced", relied); got != FenceVerified {
		t.Fatalf("an ipmi row with the prefix = %s, want verified", got)
	}
	if FenceProofGrade("best-effort-ssh", "fenced") {
		t.Fatal("a relied-on pause became proof-grade")
	}
	// The coordinator waits only for a best-effort fence that relied on it.
	if ReliesOnPartitionPause("ipmi", relied) {
		t.Fatal("a verified fence carrying the prefix reads as relying on the pause")
	}
}
