package e2e

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
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
	lw := &leaseWatch{all: []leaseChange{
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

// TestParseEnforcementGauges reads one feature's config and latch gauges from a
// node's /metrics, and refuses a scrape that lacks either.
func TestParseEnforcementGauges(t *testing.T) {
	out := `litevirt_enforcement_config_enabled{feature="lease_term_ledger_v1"} 0
litevirt_enforcement_config_enabled{feature="lease_term_v1"} 1
litevirt_enforcement_latched{feature="lease_term_ledger_v1"} 1
litevirt_enforcement_latched{feature="lease_term_v1"} 0
`
	cfg, latched, ok := parseEnforcementGauges(out, "lease_term_v1")
	if !ok || !cfg || latched {
		t.Errorf("lease_term_v1: config=%v latched=%v ok=%v, want true false true", cfg, latched, ok)
	}
	cfg, latched, ok = parseEnforcementGauges(out, "lease_term_ledger_v1")
	if !ok || cfg || !latched {
		t.Errorf("lease_term_ledger_v1: config=%v latched=%v ok=%v, want false true true", cfg, latched, ok)
	}
	if _, _, ok := parseEnforcementGauges("litevirt_enforcement_config_enabled{feature=\"lease_term_v1\"} 1\n", "lease_term_v1"); ok {
		t.Errorf("a scrape with no latch gauge was read")
	}
}

// TestLeaseTermModeOf takes the mode from every host's own flag and latch:
// enforcing needs both, so a latch with the flag off is off, and a cluster
// that disagrees is mixed.
func TestLeaseTermModeOf(t *testing.T) {
	p := func(h string, cfg, latched bool) leaseTermPosture {
		return leaseTermPosture{Host: h, Config: cfg, Latched: latched}
	}
	for _, tc := range []struct {
		name string
		ps   []leaseTermPosture
		want leaseTermMode
	}{
		{"default: flag off, not latched", []leaseTermPosture{p("node-1", false, false), p("node-6", false, false)}, leaseTermOff},
		{"latched, then every flag turned off", []leaseTermPosture{p("node-1", false, true), p("node-6", false, true)}, leaseTermOff},
		{"flag on everywhere, not latched yet", []leaseTermPosture{p("node-1", true, false), p("node-6", true, false)}, leaseTermPending},
		{"one host still latching among enforcing ones", []leaseTermPosture{p("node-1", true, true), p("node-6", true, false)}, leaseTermPending},
		{"flag on and latched everywhere", []leaseTermPosture{p("node-1", true, true), p("node-6", true, true)}, leaseTermOn},
		{"the witness alone has its flag off", []leaseTermPosture{p("node-1", true, true), p("node-6", false, true)}, leaseTermMixed},
	} {
		got, err := leaseTermModeOf(tc.ps)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q (%v), want %q", tc.name, got, err, tc.want)
		}
	}
	if _, err := leaseTermModeOf([]leaseTermPosture{p("node-1", true, true), {Host: "node-2", Err: "no gauge"}}); err == nil {
		t.Errorf("a host whose posture could not be read did not fail the reading")
	}
	if _, err := leaseTermModeOf(nil); err == nil {
		t.Errorf("no hosts did not fail the reading")
	}
}

// TestLeaseTermExpectFor selects the drills' lease-term expectations by mode:
// off, the regime is inert and a proof's term is not held to its tenure; on,
// the reverse.
func TestLeaseTermExpectFor(t *testing.T) {
	off, on := leaseTermExpectFor(leaseTermOff), leaseTermExpectFor(leaseTermOn)
	if off.Mode != leaseTermOff || !off.Inert || off.TenureStrict {
		t.Errorf("off: %+v, want inert and not tenure-strict", off)
	}
	if on.Mode != leaseTermOn || on.Inert || !on.TenureStrict {
		t.Errorf("on: %+v, want enforcing and tenure-strict", on)
	}
	if m := leaseTermExpectFor(leaseTermMixed); m.Inert || m.TenureStrict {
		t.Errorf("mixed: %+v asserts a mode", m)
	}
}

// TestW4aVerdict judges W4a's second outage under each mode. Outcome C (the
// adopted earlier-tenure value refused by the lease-term gate) is design Q5
// with lease_term on; off, the gate must not refuse at all.
func TestW4aVerdict(t *testing.T) {
	off, on := leaseTermExpectFor(leaseTermOff), leaseTermExpectFor(leaseTermOn)
	for _, tc := range []struct {
		name                        string
		e                           leaseTermExpect
		recovered, decided, gateRef bool
		dp                          string
		wantName, wantFail, mustSay string
	}{
		{"A on", on, true, true, false, "p1", "A", "", ""},
		{"A off", off, true, true, false, "p1", "A", "", ""},
		{"B off", off, true, true, false, "p2", "B", "", ""},
		{"B undecided", on, true, false, false, "", "B", "fail", "no attempt reads decided"},
		{"C on is Q5", on, false, true, true, "p1", "C", "fail", "design Q5"},
		{"C off: the gate refused while not enforced", off, false, true, true, "p1", "C", "fail", "not enforced"},
		{"stranded on, no gate line", on, false, true, false, "p1", "stranded", "fail", "no lease-term refusal"},
		{"stranded off, gate inert", off, false, true, false, "p1", "stranded", "fail", "inert"},
		{"not recovered", off, false, false, false, "", "not recovered", "fail", ""},
	} {
		v := w4aVerdict(tc.e, tc.recovered, tc.decided, tc.dp, "p1", tc.gateRef)
		if v.Name != tc.wantName || (v.Fail != "") != (tc.wantFail != "") || !strings.Contains(v.Fail, tc.mustSay) {
			t.Errorf("%s: got %+v, want outcome %q fail=%v saying %q", tc.name, v, tc.wantName, tc.wantFail != "", tc.mustSay)
		}
	}
}

// TestFreshTenureAt requires the tenure in force at the mint to be the
// holder's and taken since the loss; a re-take it lost again before the mint
// does not count.
func TestFreshTenureAt(t *testing.T) {
	t0 := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	h := []leaseChange{
		{At: t0, Holder: "node-2", Term: 7},
		{At: t0.Add(40 * time.Second), Holder: "node-3", Term: 8},
		{At: t0.Add(100 * time.Second), Holder: "node-2", Term: 9},
		{At: t0.Add(200 * time.Second), Holder: "node-4", Term: 10},
	}
	if !freshTenureAt(h, "node-2", t0.Add(30*time.Second), t0.Add(150*time.Second)) {
		t.Errorf("node-2's term 9, in force at the mint, was missed")
	}
	if freshTenureAt(h, "node-2", t0.Add(30*time.Second), t0.Add(250*time.Second)) {
		t.Errorf("node-2's term 9, lost to node-4 before the mint, counted")
	}
	if freshTenureAt(h, "node-2", t0.Add(30*time.Second), t0.Add(20*time.Second)) {
		t.Errorf("node-2's term 7, taken before the loss, counted")
	}
	if !freshTenureAt(h, "node-2", t0.Add(30*time.Second), t0.Add(199*time.Second)) {
		t.Errorf("a mint a second before a sampled takeover was refused")
	}
}

// TestLeaseTermRefusalPattern pins the off-mode refusal pattern against every
// message with which the product refuses on a lease term only while enforcing
// (health/reconciler.go, failover/coordinator.go), and against a line that is
// no refusal.
func TestLeaseTermRefusalPattern(t *testing.T) {
	re := regexp.MustCompile(leaseTermRefusalPattern)
	for _, msg := range []string{
		"reconciler: pending proof refused by the lease-term gate",
		"reconciler: this host has already acted at this lease term for another coordinator — refusing start",
		"failover: this coordinator holds no usable lease term — refusing to stamp (never acquired one, or holdLease cleared it on a loss path)",
		"failover: this coordinator's lease term is superseded — refusing to stamp",
		"failover: refusing to stamp an action proof — this coordinator's lease term is unusable, so the workload is ABANDONED (a fenced host is processed only once)",
	} {
		if !re.MatchString(`time=2026-10-15T10:00:00Z level=WARN msg="` + msg + `" vm=e2e-w4a-1`) {
			t.Errorf("not matched: %s", msg)
		}
	}
	if re.MatchString(`level=INFO msg="failover: lease acquired" term=9`) {
		t.Errorf("a line that is no refusal matched")
	}
}

// TestInertJournalVerdict: with lease_term off, a refusal line or an unread
// journal fails; an empty read passes.
func TestInertJournalVerdict(t *testing.T) {
	if v := inertJournalVerdict("node-9", "", fmt.Errorf("ssh: no route to host")); !strings.Contains(v, "could not read") {
		t.Errorf("an unread journal passed: %q", v)
	}
	if v := inertJournalVerdict("node-2", "reconciler: pending proof refused by the lease-term gate\n", nil); !strings.Contains(v, "refused on a lease term") {
		t.Errorf("a refusal line passed: %q", v)
	}
	if v := inertJournalVerdict("node-2", "\n", nil); v != "" {
		t.Errorf("a clean journal failed: %q", v)
	}
}

// TestRefusalVerdict reads the refused-actions counter and judges its change:
// lease_term_unconfirmed rising fails, stale_lease_term is noted, and a
// restart or a reset is not compared.
func TestRefusalVerdict(t *testing.T) {
	snap := func(pid string, unconf, stale int) refusalSnap {
		return parseRefusalSnap(fmt.Sprintf("PID=%s\n"+
			`litevirt_runtime_action_refused_total{action="reschedule",reason="lease_term_unconfirmed"} %d`+"\n"+
			`litevirt_runtime_action_refused_total{action="promote",reason="stale_lease_term"} %d`+"\n"+
			`litevirt_runtime_action_refused_total{action="reschedule",reason="stale_lease_term"} 1`+"\n", pid, unconf, stale))
	}
	if s := snap("42", 2, 3); s.Err != "" || s.ByReason["lease_term_unconfirmed"] != 2 || s.ByReason["stale_lease_term"] != 4 {
		t.Fatalf("parse: %+v", s)
	}
	if f, _ := refusalVerdict(snap("42", 0, 0), snap("42", 1, 0)); !strings.Contains(f, "lease_term_unconfirmed") {
		t.Errorf("a rise in lease_term_unconfirmed passed: %q", f)
	}
	if f, n := refusalVerdict(snap("42", 0, 0), snap("42", 0, 2)); f != "" || !strings.Contains(n, "stale_lease_term +2") {
		t.Errorf("stale_lease_term: fail %q note %q, want a note only", f, n)
	}
	if f, n := refusalVerdict(snap("42", 3, 0), snap("43", 5, 0)); f != "" || !strings.Contains(n, "restarted") {
		t.Errorf("a restart: fail %q note %q", f, n)
	}
	if f, n := refusalVerdict(snap("42", 3, 0), snap("42", 1, 0)); f != "" || !strings.Contains(n, "reset") {
		t.Errorf("a reset: fail %q note %q", f, n)
	}
	if f, _ := refusalVerdict(snap("42", 0, 0), refusalSnap{Err: "ssh: timeout"}); f == "" {
		t.Errorf("an unread counter after the drill passed")
	}
	if s := parseRefusalSnap("PID=0\n"); s.Err == "" {
		t.Errorf("a stopped daemon read as a snapshot")
	}
}
