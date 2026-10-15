package e2e

import (
	"reflect"
	"testing"
	"time"
)

// Pure tests of the witness drills' parsers (LITEVIRT_E2E_UNIT=1; no cluster).

// TestParseClaimView parses `lv cluster claim` as printClaimInspection prints
// it: ballots with spaces, an unreachable voter, an undecided and a decided
// attempt.
func TestParseClaimView(t *testing.T) {
	out := `claim of vm/e2e-w4a-1 by node-3

Attempt 0 (key vm/e2e-w4a-1(inc9)@3#0): no value accepted by a majority
VOTER   PROMISED              ACCEPTED              VALUE         PROOF  DEST    SOURCE  INCARNATION  LAST REFUSAL
node-1  (2, node-2, ab12cd)   (2, node-2, ab12cd)   0123456789ab  p-one  node-4  node-1  ok           -
node-2  (2, node-2, ab12cd)   -                     -             -      -       -       ok           recovery_claim_owner_reachable: it answers
node-5  -                     -                     -             -      -       -       -            unreachable: dial timeout

Attempt 1 (key vm/e2e-w4a-1(inc9)@3#1): DECIDED for node-3 (value fedcba987654)
VOTER   PROMISED              ACCEPTED              VALUE         PROOF  DEST    SOURCE  INCARNATION  LAST REFUSAL
node-1  (3, node-3, 01)       (3, node-3, 01)       fedcba987654  p-two  node-3  node-1  ok           -
node-2  (3, node-3, 01)       (3, node-3, 01)       fedcba987654  p-two  node-3  node-1  MISMATCH (abstains)  -
`
	as := parseClaimView(out)
	if len(as) != 2 {
		t.Fatalf("attempts %d, want 2: %+v", len(as), as)
	}
	a0, a1 := as[0], as[1]
	if a0.N != 0 || a0.Decided || len(a0.Voters) != 3 {
		t.Fatalf("attempt 0: %+v", a0)
	}
	if v := a0.Voters[0]; v.Voter != "node-1" || v.Accepted != "(2, node-2, ab12cd)" || v.Proof != "p-one" || v.Dest != "node-4" {
		t.Errorf("attempt 0 voter 0: %+v", v)
	}
	if !a0.Voters[2].Unreachable || a0.Voters[1].Unreachable {
		t.Errorf("unreachable flags: %+v", a0.Voters)
	}
	acc := a0.acceptedUndecided()
	if len(acc) != 1 || acc[0].Voter != "node-1" {
		t.Errorf("accepted undecided %+v, want node-1 only", acc)
	}
	if a1.N != 1 || !a1.Decided || a1.DecidedDest != "node-3" || a1.DecidedValue != "fedcba987654" {
		t.Fatalf("attempt 1: %+v", a1)
	}
	if got := a1.decidedProof(); got != "p-two" {
		t.Errorf("decided proof %q, want p-two", got)
	}
	if a1.acceptedUndecided() != nil || a0.decidedProof() != "" {
		t.Errorf("a decided attempt has no undecided acceptors, an undecided one no decided proof")
	}
}

// TestParseLogLines reads the time= of slog text records, quoted or not.
func TestParseLogLines(t *testing.T) {
	ls := parseLogLines(`time=2026-10-15T10:00:01.250Z level=ERROR msg="failover: recovery of a fenced host has stalled" host=node-1
no time here
time="2026-10-15T13:00:02+03:00" level=INFO msg=x
`)
	if len(ls) != 3 {
		t.Fatalf("lines %d, want 3", len(ls))
	}
	if want := time.Date(2026, 10, 15, 10, 0, 1, 250e6, time.UTC); !ls[0].At.Equal(want) {
		t.Errorf("line 0 at %v, want %v", ls[0].At, want)
	}
	if !ls[1].At.IsZero() {
		t.Errorf("a line without time= has a time: %v", ls[1].At)
	}
	if want := time.Date(2026, 10, 15, 10, 0, 2, 0, time.UTC); !ls[2].At.Equal(want) {
		t.Errorf("line 2 at %v, want %v", ls[2].At, want)
	}
}

// TestMailpitMatches filters Mailpit's message list by subject and time.
func TestMailpitMatches(t *testing.T) {
	body := []byte(`{"total":3,"messages":[
{"ID":"a","Subject":"[lab] error: host.recovery.stalled node-1","Created":"2026-10-15T10:05:00.000Z"},
{"ID":"b","Subject":"error: host.recovery.stalled node-1","Created":"2026-10-15T09:00:00Z"},
{"ID":"c","Subject":"error: host.recovery.stalled node-2","Created":"2026-10-15T10:06:00Z"}]}`)
	got, err := mailpitMatches(body, "host.recovery.stalled node-1", time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"[lab] error: host.recovery.stalled node-1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if _, err := mailpitMatches([]byte("not json"), "x", time.Time{}); err == nil {
		t.Errorf("a body that is not JSON parsed")
	}
}

// TestCutPlan puts a rule for each edge on both of its ends, once.
func TestCutPlan(t *testing.T) {
	got := cutPlan(append(edgesFrom("node-1", "node-3", "node-4"), [2]string{"node-1", "node-3"}, [2]string{"node-6", "node-1"}))
	want := map[string][]string{
		"node-1": {"node-3", "node-4", "node-6"},
		"node-3": {"node-1"},
		"node-4": {"node-1"},
		"node-6": {"node-1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestHoldersBetween names the holder at the window's start and every later one.
func TestHoldersBetween(t *testing.T) {
	t0 := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	lw := &leaseWatch{changes: []leaseChange{
		{At: t0, Holder: "node-2", Term: 4},
		{At: t0.Add(time.Minute), Holder: "node-3", Term: 5},
		{At: t0.Add(2 * time.Minute), Holder: "node-2", Term: 6},
		{At: t0.Add(5 * time.Minute), Holder: "node-4", Term: 7},
	}}
	if got := holdersBetween(lw, t0.Add(30*time.Second), t0.Add(3*time.Minute)); !reflect.DeepEqual(got, []string{"node-2", "node-3"}) {
		t.Errorf("got %v", got)
	}
	if got := holdersBetween(lw, t0.Add(150*time.Second), t0.Add(4*time.Minute)); !reflect.DeepEqual(got, []string{"node-2"}) {
		t.Errorf("one holder throughout: got %v", got)
	}
}

// TestTenureAt judges a proof against the tenure in force when it was minted,
// not against a later one.
func TestTenureAt(t *testing.T) {
	t0 := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	h := []leaseChange{
		{At: t0, Holder: "node-2", Term: 7},
		{At: t0.Add(40 * time.Second), Holder: "node-3", Term: 8},
	}
	if _, ok := tenureAt(h, t0.Add(20*time.Second), "node-2", 7); !ok {
		t.Errorf("a proof minted at term 7 before the takeover was refused")
	}
	if _, ok := tenureAt(h, t0.Add(60*time.Second), "node-2", 7); ok {
		t.Errorf("a proof minted at term 7 after node-3 took term 8 was accepted")
	}
	if _, ok := tenureAt(h, t0.Add(39*time.Second), "node-2", 7); !ok {
		t.Errorf("a proof minted a second before a sampled takeover was refused")
	}
	if _, ok := tenureAt(h, t0.Add(20*time.Second), "node-3", 7); ok {
		t.Errorf("the wrong holder was accepted")
	}
	if _, ok := tenureAt(h, t0.Add(-time.Minute), "node-2", 7); ok {
		t.Errorf("a proof before any sample was accepted")
	}
}

// TestMintTime dates a proof the skewed holder minted: shifted by its 20 s
// skew without hlc_lww_v1, not with it (created_at is then the HLC, about the
// true time). The HLC case is judged against a takeover 10 s after the mint.
func TestMintTime(t *testing.T) {
	t0 := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	stepAt := t0.Add(-30 * time.Second)
	h := []leaseChange{
		{At: t0.Add(-time.Minute), Holder: "node-2", Term: 7},
		{At: t0.Add(10 * time.Second), Holder: "node-3", Term: 8},
	}
	// HLC: created_at reads the true mint time t0, under term 7.
	if _, ok := tenureAt(h, mintTime(t0, "node-2", "node-2", stepAt, true), "node-2", 7); !ok {
		t.Errorf("with hlc_lww_v1 a proof minted at term 7 before the takeover was dated into term 8")
	}
	// No HLC: created_at reads the skewed wall clock, t0 − 20 s.
	if got := mintTime(t0.Add(-20*time.Second), "node-2", "node-2", stepAt, false); !got.Equal(t0) {
		t.Errorf("without hlc_lww_v1 the skewed created_at maps to %v, want %v", got, t0)
	}
	if got := mintTime(t0, "node-4", "node-2", stepAt, false); !got.Equal(t0) {
		t.Errorf("a proof by an unskewed coordinator was shifted to %v", got)
	}
	if got := mintTime(stepAt.Add(-time.Minute), "node-2", "node-2", stepAt, false); !got.Equal(stepAt.Add(-time.Minute)) {
		t.Errorf("a time written before the step was shifted to %v", got)
	}
}
