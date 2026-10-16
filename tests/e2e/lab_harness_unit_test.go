package e2e

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestEnforcementEditScript runs the harness's config edit against real files:
// whatever indentation the file's enforcement block uses, the key comes out
// with it, whether it is replaced or added, and no line is ever indented
// differently from its siblings.
// Run with LITEVIRT_E2E_UNIT=1 (it needs no cluster).
func TestEnforcementEditScript(t *testing.T) {
	for _, c := range []struct {
		name, in, want string
	}{
		{"two-space add", "a: 1\nenforcement:\n  x: true\nb: 2\n", "a: 1\nenforcement:\n  y: false\n  x: true\nb: 2\n"},
		{"four-space add", "a: 1\nenforcement:\n    x: true\nb: 2\n", "a: 1\nenforcement:\n    y: false\n    x: true\nb: 2\n"},
		{"four-space replace", "enforcement:\n    x: true\n    y: true\nb: 2\n", "enforcement:\n    x: true\n    y: false\nb: 2\n"},
		{"two-space replace", "enforcement:\n  y: true\nb: 2\n", "enforcement:\n  y: false\nb: 2\n"},
		{"three-space add", "enforcement:\n   x: true\n", "enforcement:\n   y: false\n   x: true\n"},
		{"comment first", "enforcement:\n    # note\n    x: true\n", "enforcement:\n    y: false\n    # note\n    x: true\n"},
		{"empty block", "enforcement:\nb: 2\n", "enforcement:\n  y: false\nb: 2\n"},
		{"same key elsewhere is left alone", "other:\n    y: keep\nenforcement:\n    x: true\n", "other:\n    y: keep\nenforcement:\n    y: false\n    x: true\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(f, []byte(c.in), 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("sh", "-c", enforcementEditScript(f, "y", "false")).CombinedOutput(); err != nil {
				t.Fatalf("script: %v\n%s", err, out)
			}
			got, _ := os.ReadFile(f)
			if string(got) != c.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, c.want)
			}
			if orig, _ := os.ReadFile(f + ".e2e-orig"); string(orig) != c.in {
				t.Errorf("the original was not kept: %q", orig)
			}
			if strings.Contains(string(got), "\t") {
				t.Error("tab in YAML")
			}
		})
	}
}

// TestEnforcementEditScriptRefusesAnInlineBlock: a flow-style or valued
// `enforcement:` header cannot take an inserted child, so the edit must fail
// and leave the file alone rather than write invalid YAML. A matching line in
// another section must not satisfy the final verification either.
func TestEnforcementEditScriptRefusesAnInlineBlock(t *testing.T) {
	for _, in := range []string{"enforcement: {}\nb: 2\n", "enforcement: {x: true}\n", "enforcement: on\n"} {
		f := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(f, []byte(in), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("sh", "-c", enforcementEditScript(f, "y", "false")).CombinedOutput(); err == nil {
			t.Errorf("%q: the edit succeeded:\n%s", in, out)
		}
		if got, _ := os.ReadFile(f); string(got) != in {
			t.Errorf("%q: the file was changed to %q", in, got)
		}
	}
	// No enforcement block at all, the key present elsewhere: must fail.
	f := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(f, []byte("other:\n  y: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.Command("sh", "-c", enforcementEditScript(f, "y", "false")).CombinedOutput(); err == nil {
		t.Error("an identical line in another section satisfied the verification")
	}
}

// TestJoinMajority pins which side an unnamed host (a witness) lands on.
// Run with LITEVIRT_E2E_UNIT=1 (it needs no cluster).
func TestJoinMajority(t *testing.T) {
	all := []string{"node-1", "node-2", "node-3", "node-4", "node-5", "node-6"}
	got := joinMajority([][]string{{"node-1", "node-2"}, {"node-3", "node-4", "node-5"}}, all)
	want := map[string]int{"node-1": 0, "node-2": 0, "node-3": 1, "node-4": 1, "node-5": 1, "node-6": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("2|3 split with a witness: %v, want %v", got, want)
	}
	// Every host alone (a fleet-wide blip): no majority, nobody is added.
	got = joinMajority([][]string{{"node-1"}, {"node-2"}, {"node-3"}}, all)
	if len(got) != 3 {
		t.Errorf("a tie must not assign unnamed hosts: %v", got)
	}
	// A larger named group wins whichever side it is listed on.
	got = joinMajority([][]string{{"node-1", "node-2", "node-3"}, {"node-4"}}, all)
	if got["node-6"] != 0 || got["node-5"] != 0 {
		t.Errorf("unnamed hosts must join the larger group: %v", got)
	}
}

// TestMinorityCopyStopped pins what drill 1b takes as proof that a minority
// copy stopped executing (review I3): a host the sampler could not read for
// any reason but a power-off proves nothing.
// Run with LITEVIRT_E2E_UNIT=1 (it needs no cluster).
func TestMinorityCopyStopped(t *testing.T) {
	const h, k = "node-1", "vm/a"
	read := func(st string) round {
		r := round{Copies: map[string]map[string]string{}, Down: map[string]string{}}
		if st != "" {
			r.Copies[k] = map[string]string{h: st}
		}
		return r
	}
	down := func(why string) round {
		return round{Copies: map[string]map[string]string{}, Down: map[string]string{h: why}}
	}
	for name, c := range map[string]struct {
		r    round
		want bool
	}{
		"paused":                    {read("paused"), true},
		"shut off":                  {read("shut_off"), true},
		"read, guest absent":        {read(""), true},
		"running":                   {read("running"), false},
		"host powered off":          {down("powered off"), true},
		"host read failed over ssh": {down("ssh node-1: timed out after 20s"), false},
	} {
		if got := minorityCopyStopped(c.r, h, k); got != c.want {
			t.Errorf("%s: minorityCopyStopped = %v, want %v", name, got, c.want)
		}
	}
}

// TestPollFor pins the wait helper getVMIP uses: it returns as soon as the
// condition holds, and gives up once the next attempt would pass the bound.
func TestPollFor(t *testing.T) {
	n := 0
	if _, ok := pollFor(time.Second, time.Millisecond, func() bool { n++; return n == 3 }); !ok || n != 3 {
		t.Fatalf("ok=%v after %d calls, want true after 3", ok, n)
	}
	n = 0
	took, ok := pollFor(50*time.Millisecond, 10*time.Millisecond, func() bool { n++; return false })
	if ok || took < 50*time.Millisecond || took > time.Second || n < 4 {
		t.Fatalf("a never-true poll: ok=%v after %v and %d calls, want false at the 50 ms bound", ok, took, n)
	}
}

// TestHostStateInLs pins the parse waitServing relies on.
func TestHostStateInLs(t *testing.T) {
	out := "NAME ADDR STATE\nnode-1 10.0.0.1 HOST_DRAINING x\nnode-2 10.0.0.2 HOST_ACTIVE x\n"
	got := parseHostStates(out)
	for host, want := range map[string]string{"node-1": "HOST_DRAINING", "node-2": "HOST_ACTIVE", "node-3": ""} {
		if got[host] != want {
			t.Errorf("%s: %q, want %q", host, got[host], want)
		}
	}
}

// TestIncoherenceTracker: incoherence is judged over a sliding window, so
// sparse samples pass and a flapping row (alternating coherent/incoherent) fails.
func TestIncoherenceTracker(t *testing.T) {
	t0 := time.Unix(1000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	var c incoherenceTracker
	for i := 0; i < 10; i++ { // one every 6 s never puts 3 in 10 s
		if c.observe(at(i*6), false) {
			t.Fatalf("sparse sample %d failed", i)
		}
	}
	var f incoherenceTracker
	fails := 0
	for i := 0; i < 8; i++ { // flapping: incoherent on even seconds
		if f.observe(at(i), i%2 == 1) {
			fails++
		}
	}
	if fails != 1 {
		t.Fatalf("a flapping row failed %d times, want once", fails)
	}
	var d incoherenceTracker
	d.observe(at(0), false)
	d.observe(at(1), false)
	if d.observe(at(30), true); d.n != 0 {
		t.Fatalf("the window did not drain: n=%d", d.n)
	}
}

// TestPingVerdict: only a ping that ran and lost its packets counts as
// "unreachable"; a transport failure of lv exec is inconclusive.
func TestPingVerdict(t *testing.T) {
	for _, c := range []struct {
		out         string
		err         error
		reached, ok bool
	}{
		{"3 packets transmitted, 3 received", nil, true, true},
		{"3 packets transmitted, 0 received, 100% packet loss", errors.New("exit 1"), false, true},
		{"From 10.0.0.1 icmp_seq=1 Destination Host Unreachable", errors.New("exit 1"), false, true},
		{"rpc error: connection refused", errors.New("exit 1"), false, false},
	} {
		if r, ok := pingVerdict(c.out, c.err); r != c.reached || ok != c.ok {
			t.Errorf("%q: reached=%v conclusive=%v, want %v %v", c.out, r, ok, c.reached, c.ok)
		}
	}
}

// TestClassifyLease: the W3 case (a restarted replica's old election holder
// beside a newer ledger term) is lag; a holder with no earlier term is not.
func TestClassifyLease(t *testing.T) {
	terms := map[int]string{50: "node-2", 51: "node-4"}
	for _, c := range []struct {
		election, ledger string
		want             leaseSampleKind
	}{{"node-4", "node-4", leaseCoherent}, {"node-2", "node-4", leaseLag}, {"", "node-4", leaseNeutral}, {"node-9", "node-4", leaseUnexplained}} {
		if got := classifyLease(leaseSample{Election: c.election, Term: 51, Ledger: c.ledger, Terms: terms}); got != c.want {
			t.Errorf("(%q,%q) = %v, want %v", c.election, c.ledger, got, c.want)
		}
	}
}

// TestLeaseWatchObserve pins the sampler's wiring: per-reader windows, neutral
// samples neither reset nor extend, a persistent or flapping run and a
// same-term conflict fail, lag is logged and summarised, every reader's
// tenures are recorded, and a ledger reset forgets term holders.
func TestLeaseWatchObserve(t *testing.T) {
	var fails, logs []string
	newW := func() *leaseWatch {
		fails, logs = nil, nil
		return &leaseWatch{incoh: map[string]*incoherenceTracker{}, termHolder: map[int]string{}, lastBy: map[string]leaseChange{}, maxTerm: map[string]int{},
			fail: func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) },
			logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	}
	terms := map[int]string{50: "node-2", 51: "node-4"}
	lag := leaseSample{Election: "node-2", Term: 51, Ledger: "node-4", Terms: terms}
	ok := leaseSample{Election: "node-4", Term: 51, Ledger: "node-4", Terms: terms}
	neutral := leaseSample{Election: "", Term: 51, Ledger: "node-4", Terms: terms}
	t0 := time.Unix(1000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

	// Transient lag (2 samples, then sparse ones): logged and summarised, no failure.
	w := newW()
	w.observe("a", at(0), lag, true)
	w.observe("a", at(1), lag, true)
	w.observe("a", at(2), ok, true)
	for i := 1; i <= 4; i++ {
		w.observe("a", at(2+i*12), lag, true)
	}
	if len(fails) != 0 || !strings.Contains(w.summary(), "6 incoherent") {
		t.Fatalf("transient lag: fails=%v summary=%q", fails, w.summary())
	}
	if len(w.history()) != 1 || w.history()[0].Holder != "node-4" {
		t.Fatalf("a lagging sample was recorded as a lease change: %+v", w.history())
	}
	// Lag never fails, however long it lasts or how it flaps.
	w = newW()
	for i := 0; i < 30; i++ {
		s := lag
		if i%2 == 1 {
			s = ok
		}
		w.observe("a", at(i), s, true)
		w.observe("b", at(i), lag, false)
	}
	if len(fails) != 0 {
		t.Fatalf("lag failed the drill: %v", fails)
	}
	// A persistent unexplained live holder fails, per reader: another reader's
	// coherent samples and neutral samples must not reset it.
	unexp := leaseSample{Election: "node-9", Term: 51, Ledger: "node-4", Terms: terms}
	w = newW()
	for i := 0; i < 5; i++ {
		w.observe("a", at(i), unexp, true)
		w.observe("b", at(i), ok, false)
		w.observe("a", at(i), neutral, false)
	}
	if len(fails) != 1 || !strings.Contains(fails[0], "a's replica") {
		t.Fatalf("persistent lag on reader a: fails=%v", fails)
	}
	// A flapping unexplained row fails.
	w = newW()
	for i := 0; i < 6; i++ {
		s := unexp
		if i%2 == 1 {
			s = ok
		}
		w.observe("a", at(i), s, true)
	}
	if len(fails) != 1 {
		t.Fatalf("a flapping election row: fails=%v", fails)
	}
	// avoid resets the reader's window.
	w.avoided = map[string]bool{}
	w.avoid("a", true)
	if _, held := w.incoh["a"]; held {
		t.Fatal("avoid did not reset the reader's window")
	}
	// Two holders for one term fail at once, with no time bound.
	w = newW()
	w.observe("a", t0, ok, true)
	w.observe("b", t0, leaseSample{Election: "node-5", Term: 51, Ledger: "node-5", Terms: map[int]string{51: "node-5"}}, false)
	if len(fails) != 1 || !strings.Contains(fails[0], "two holders for one term") {
		t.Fatalf("a same-term conflict: fails=%v", fails)
	}
	// Every reader's tenures are kept, tagged; the stale-but-consistent one too.
	w = newW()
	w.observe("a", t0, ok, true)
	w.observe("b", t0, leaseSample{Election: "node-2", Term: 50, Ledger: "node-2", Terms: map[int]string{50: "node-2"}}, false)
	all := w.allHistory()
	if len(all) != 2 || all[0].Reader != "a" || all[1].Reader != "b" || all[1].Holder != "node-2" {
		t.Fatalf("per-reader history: %+v", all)
	}
	// A ledger that goes backwards (a lease reset) forgets term holders.
	w = newW()
	w.observe("a", t0, ok, true)
	w.observe("a", at(1), leaseSample{Election: "node-9", Term: 1, Ledger: "node-9", Terms: map[int]string{1: "node-9"}}, true)
	w.observe("a", at(2), leaseSample{Election: "node-8", Term: 2, Ledger: "node-8", Terms: map[int]string{1: "node-9", 2: "node-8"}}, true)
	w2 := newW()
	w2.observe("a", t0, leaseSample{Election: "node-2", Term: 51, Ledger: "node-2", Terms: map[int]string{1: "node-2", 51: "node-2"}}, true)
	w2.observe("a", at(1), leaseSample{Election: "node-9", Term: 1, Ledger: "node-9", Terms: map[int]string{1: "node-9"}}, true)
	if len(fails) != 0 {
		t.Fatalf("a reused term after a reset false-failed: %v", fails)
	}
	// Stop prints the summary, once.
	w = newW()
	w.stop, w.done = make(chan struct{}), make(chan struct{})
	close(w.done)
	w.observe("a", t0, lag, true)
	logs = nil
	w.Stop()
	w.Stop()
	if len(logs) != 1 || !strings.Contains(logs[0], "1 incoherent") {
		t.Fatalf("Stop's summary: %v", logs)
	}
}

// TestObserveTick: two different nodes naming themselves holder in their own
// replicas is a dual holder once it lasts 2 ticks; one tick (a handover seen
// from both ends) is logged only, and a lone claimant is nothing.
func TestObserveTick(t *testing.T) {
	var fails, logs []string
	w := &leaseWatch{
		fail: func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) },
		logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	t0 := time.Unix(1000, 0)
	two := map[string]string{"node-2": "node-2", "node-4": "node-4"}
	w.observeTick(t0, two, nil)
	w.observeTick(t0.Add(time.Second), map[string]string{"node-4": "node-4"}, nil)
	w.observeTick(t0.Add(2*time.Second), two, nil)
	if len(fails) != 0 || len(logs) != 2 {
		t.Fatalf("a one-tick overlap: fails=%v logs=%v", fails, logs)
	}
	w.observeTick(t0.Add(3*time.Second), two, nil)
	w.observeTick(t0.Add(4*time.Second), two, nil)
	if len(fails) != 1 || !strings.Contains(fails[0], "dual holder") {
		t.Fatalf("a two-tick dual holder: fails=%v", fails)
	}
}

// TestObserveTickUnknown: a failed read of a claimant is unknown. It neither
// resets nor extends the 2-tick run, so alternating sql errors cannot evade it;
// persistent unknowns are logged and summarised.
func TestObserveTickUnknown(t *testing.T) {
	var fails, logs []string
	w := &leaseWatch{
		fail: func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) },
		logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	t0 := time.Unix(1000, 0)
	two := map[string]string{"node-2": "node-2", "node-4": "node-4"}
	one := map[string]string{"node-2": "node-2"}
	w.observeTick(t0, two, nil)                                 // n=1
	w.observeTick(t0.Add(time.Second), one, []string{"node-4"}) // held, not reset
	if len(fails) != 0 || w.selfClaim.n != 1 {
		t.Fatalf("held tick: n=%d fails=%v", w.selfClaim.n, fails)
	}
	w.observeTick(t0.Add(2*time.Second), two, nil) // n=2: fails
	if len(fails) != 1 {
		t.Fatalf("an unreadable claimant evaded the run: fails=%v", fails)
	}
	// An unknown that was NOT a claimant does not hold a run.
	w = &leaseWatch{fail: func(f string, a ...any) { fails = append(fails, f) }, logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	fails = nil
	w.observeTick(t0, two, nil)
	w.observeTick(t0.Add(time.Second), one, []string{"node-9"})
	w.observeTick(t0.Add(2*time.Second), two, nil)
	if len(fails) != 0 {
		t.Fatalf("an unrelated unknown held a run: %v", fails)
	}
	// A claimant unreadable for good while a run is held fails the drill (once),
	// the hold is logged on entry only, and the held run is cleared.
	w = &leaseWatch{fail: func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }, logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	fails, logs = nil, nil
	w.observeTick(t0, two, nil)
	for i := 1; i <= unknownPersistent+unknownHeldExtra; i++ {
		w.observeTick(t0.Add(time.Duration(i)*time.Second), one, []string{"node-4"})
	}
	if len(fails) != 0 {
		t.Fatalf("failed before the bound: %v", fails)
	}
	held := 0
	for _, l := range logs {
		if strings.Contains(l, "run held") {
			held++
		}
	}
	if held != 1 {
		t.Fatalf("held-run line logged %d times, want 1", held)
	}
	w.observeTick(t0.Add(20*time.Second), one, []string{"node-4"})
	if len(fails) != 1 || !strings.Contains(fails[0], "unverifiable") || w.selfClaim.n != 0 {
		t.Fatalf("an unreadable claimant held a run forever: fails=%v n=%d", fails, w.selfClaim.n)
	}
	// A reader unreadable on every tick fails at Stop.
	w = &leaseWatch{fail: func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }, logf: func(string, ...any) {}, stop: make(chan struct{}), done: make(chan struct{})}
	close(w.done)
	fails = nil
	for i := 0; i < 8; i++ {
		w.observeTick(t0.Add(time.Duration(i)*time.Second), nil, []string{"node-3"})
	}
	w.Stop()
	if len(fails) != 1 || !strings.Contains(fails[0], "inconclusive") || !strings.Contains(w.summary(), "8 of 8") {
		t.Fatalf("a never-readable reader: fails=%v summary=%q", fails, w.summary())
	}
	short := &leaseWatch{}
	short.noteUnknown([]string{"node-3"})
	short.noteUnknown(nil)
	if len(short.neverReadable()) != 0 {
		t.Fatal("too short a run reported never-readable")
	}
	// Persistent unknowns are logged once at the threshold and summarised.
	w = &leaseWatch{fail: func(f string, a ...any) {}, logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	logs = nil
	for i := 0; i < 5; i++ {
		w.observeTick(t0.Add(time.Duration(10+i)*time.Second), nil, []string{"node-3"})
	}
	n := 0
	for _, l := range logs {
		if strings.Contains(l, "could not be read") {
			n++
		}
	}
	if n != 1 || !strings.Contains(w.summary(), "node-3 unreadable on 5 of") {
		t.Fatalf("persistent unknown: logged %d, summary %q", n, w.summary())
	}
}

// TestSampleTick: the change history follows the highest-term usable sample,
// not the first reader; a self-claim on a lagging replica is left to the window
// tracker, while one on a caught-up replica still fails at 2 ticks.
func TestSampleTick(t *testing.T) {
	var fails []string
	newW := func() *leaseWatch {
		fails = nil
		return &leaseWatch{incoh: map[string]*incoherenceTracker{}, termHolder: map[int]string{}, lastBy: map[string]leaseChange{}, maxTerm: map[string]int{},
			fail: func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) },
			logf: func(string, ...any) {}}
	}
	terms := map[int]string{50: "node-2", 51: "node-4"}
	stale := leaseSample{Election: "node-2", Term: 50, Ledger: "node-2", Terms: map[int]string{50: "node-2"}}
	fresh := leaseSample{Election: "node-4", Term: 51, Ledger: "node-4", Terms: terms}
	t0 := time.Unix(1000, 0)

	w := newW()
	w.sampleTick(t0, []readerSample{{Reader: "node-1", S: stale}, {Reader: "node-4", S: fresh}})
	if h := w.history(); len(h) != 1 || h[0].Holder != "node-4" || h[0].Term != 51 {
		t.Fatalf("history followed the first reader, not the highest term: %+v", h)
	}
	if got := recorderOf([]readerSample{{Reader: "a", Failed: true}, {Reader: "b", S: stale}}); got != "b" {
		t.Fatalf("a failed read picked as recorder: %q", got)
	}
	if got := recorderOf(nil); got != "" {
		t.Fatalf("no samples: %q", got)
	}

	// node-2 caught up to nothing yet: its own old row beside node-4's newer term.
	lagging := leaseSample{Election: "node-2", Term: 51, Ledger: "node-4", Terms: terms}
	w = newW()
	for i := 0; i < 2; i++ {
		w.sampleTick(t0.Add(time.Duration(i)*time.Second), []readerSample{{Reader: "node-2", S: lagging}, {Reader: "node-4", S: fresh}})
	}
	if len(fails) != 0 {
		t.Fatalf("a lagging self-claim failed at 2 ticks: %v", fails)
	}
	// Lag is recorded however long it persists, and never fails.
	for i := 2; i < 12; i++ {
		w.sampleTick(t0.Add(time.Duration(i)*time.Second), []readerSample{{Reader: "node-2", S: lagging}, {Reader: "node-4", S: fresh}})
	}
	if len(fails) != 0 {
		t.Fatalf("persistent lag self-claim failed: %v", fails)
	}
	// A caught-up replica self-claiming beside a newer holder still fails at 2 ticks.
	selfConsistent := stale
	w = newW()
	for i := 0; i < 2; i++ {
		w.sampleTick(t0.Add(time.Duration(i)*time.Second), []readerSample{{Reader: "node-2", S: selfConsistent}, {Reader: "node-4", S: fresh}})
	}
	if len(fails) != 1 || !strings.Contains(fails[0], "dual holder") {
		t.Fatalf("a caught-up self-claim did not fail: %v", fails)
	}
}

// TestHoldersIn: tenures seen by any reader count, each reader's holder at
// from included.
func TestHoldersIn(t *testing.T) {
	t0 := time.Unix(1000, 0)
	h := []leaseChange{
		{At: t0, Holder: "node-2", Term: 4, Reader: "a"},
		{At: t0, Holder: "node-1", Term: 3, Reader: "b"}, // a stale replica
		{At: t0.Add(time.Minute), Holder: "node-3", Term: 5, Reader: "b"},
	}
	got := holdersIn(h, t0.Add(30*time.Second), t0.Add(2*time.Minute))
	if !reflect.DeepEqual(got, []string{"node-2", "node-1", "node-3"}) {
		t.Fatalf("got %v", got)
	}
}

// TestUncertifiedDeclineVerdict: W1's heal accepts a decline only when it says
// the move to the destination completed on an uncertified proof and its remedy
// confirms the replacement by its runtime and stops the copy with virsh, never
// by a claim a derived voter set did not decide.
// Run with LITEVIRT_E2E_UNIT=1 (it needs no cluster).
func TestUncertifiedDeclineVerdict(t *testing.T) {
	good := settleDeclinedEv{ReasonClass: "proof_uncertified", RowHost: "node-3",
		Reason: "proof p1 completed on node-3 but carries no recovery-claim certificate",
		Remedy: "… `virsh domstate w1-1` on node-3 must report it running … `virsh destroy w1-1` …"}
	if err := uncertifiedDeclineVerdict(good, "w1-1", "node-3"); err != nil {
		t.Fatalf("a correct decline was refused: %v", err)
	}
	for name, mut := range map[string]func(*settleDeclinedEv){
		"no_certificate":    func(e *settleDeclinedEv) { e.ReasonClass = "no_certificate" },
		"another row host":  func(e *settleDeclinedEv) { e.RowHost = "node-4" },
		"claim remedy":      func(e *settleDeclinedEv) { e.Remedy += " `lv cluster claim vm/w1-1`" },
		"no runtime check":  func(e *settleDeclinedEv) { e.Remedy = "`virsh destroy w1-1`" },
		"no destroy remedy": func(e *settleDeclinedEv) { e.Remedy = "`virsh domstate w1-1`" },
	} {
		ev := good
		mut(&ev)
		if err := uncertifiedDeclineVerdict(ev, "w1-1", "node-3"); err == nil {
			t.Errorf("%s: accepted %+v", name, ev)
		}
	}
}

// TestGuestBootVerdict: zero transmitted frames on every NIC means the guest
// never booted; any traffic, or unreadable counters, says nothing.
func TestGuestBootVerdict(t *testing.T) {
	for _, c := range []struct {
		name, in string
		boot     bool
	}{
		{"silent", "Domain: 'vm'\n  net.count=1\n  net.0.name=vnet0\n  net.0.rx.pkts=3\n  net.0.tx.pkts=0\n", true},
		{"two silent", "net.0.tx.pkts=0\nnet.1.tx.pkts=0\n", true},
		{"sent", "net.0.tx.pkts=12\n", false},
		{"one sent", "net.0.tx.pkts=0\nnet.1.tx.pkts=1\n", false},
		{"unreadable", "", false},
	} {
		if got := guestBootVerdict(c.in) != ""; got != c.boot {
			t.Errorf("%s: never-booted = %v, want %v", c.name, got, c.boot)
		}
	}
}

// TestLeaseSampleExpiry: an election row is expired only when the reader's own
// clock is past expires_at plus the skew margin; unknown times are not expired.
func TestLeaseSampleExpiry(t *testing.T) {
	exp := time.Unix(1000, 0)
	terms := map[int]string{50: "node-2", 51: "node-4"}
	for _, c := range []struct {
		name         string
		expires, now time.Time
		want         bool
	}{
		{"unknown expiry", time.Time{}, exp.Add(time.Hour), false},
		{"unknown clock", exp, time.Time{}, false},
		{"live", exp, exp.Add(-time.Second), false},
		{"inside skew margin", exp, exp.Add(leaseSkewMargin), false},
		{"expired", exp, exp.Add(leaseSkewMargin + time.Second), true},
	} {
		s := leaseSample{Election: "node-2", Term: 51, Ledger: "node-4", Terms: terms, Expires: c.expires, Now: c.now}
		if got := s.expired(); got != c.want {
			t.Errorf("%s: expired=%v, want %v", c.name, got, c.want)
		}
	}
	// A holder no earlier term explains: live is unexplained, expired is neutral.
	live := leaseSample{Election: "node-9", Term: 51, Ledger: "node-4", Terms: terms, Expires: exp, Now: exp}
	if k := classifyLease(live); k != leaseUnexplained {
		t.Errorf("live unexplained = %v", k)
	}
	live.Now = exp.Add(time.Minute)
	if k := classifyLease(live); k != leaseNeutral {
		t.Errorf("expired unexplained = %v, want neutral", k)
	}
	// Lag stays lag whether or not the row expired: it is always recorded.
	lag := leaseSample{Election: "node-2", Term: 51, Ledger: "node-4", Terms: terms, Expires: exp, Now: exp.Add(time.Minute)}
	if k := classifyLease(lag); k != leaseLag {
		t.Errorf("expired lag = %v, want lag", k)
	}
	if got := parseLeaseTime("2026-10-14T21:04:45Z"); got.IsZero() || !parseLeaseTime("").IsZero() || !parseLeaseTime("x").IsZero() {
		t.Errorf("parseLeaseTime: %v", got)
	}
}

// TestLagNeverFails: the W3 replay. node-2 restarted and its replica still
// shows its own expired term-71 row while node-6 holds term 72: three lag
// samples, no failure, no self-claim. Two live self-claimants still fail; an
// expired self-claim beside a live one does not.
func TestLagNeverFails(t *testing.T) {
	var fails []string
	w := &leaseWatch{incoh: map[string]*incoherenceTracker{}, termHolder: map[int]string{}, lastBy: map[string]leaseChange{}, maxTerm: map[string]int{},
		fail: func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }, logf: func(string, ...any) {}}
	t0 := time.Unix(5000, 0)
	terms := map[int]string{71: "node-2", 72: "node-6"}
	stale := leaseSample{Election: "node-2", Term: 72, Ledger: "node-6", Terms: terms, Expires: t0.Add(-80 * time.Second), Now: t0}
	for i := 0; i < 3; i++ {
		now := t0.Add(time.Duration(i) * time.Second)
		w.sampleTick(now, []readerSample{{Reader: "node-2", S: stale}, {Reader: "node-6", S: leaseSample{Election: "node-6", Term: 72, Ledger: "node-6", Terms: terms, Expires: t0.Add(30 * time.Second), Now: t0}}})
	}
	if len(fails) != 0 {
		t.Fatalf("W3 replay failed the drill: %v", fails)
	}
	// Even an unexpired lag row (a real self-claim on a lagging replica) is not failed on.
	stale.Expires = t0.Add(time.Hour)
	for i := 3; i < 20; i++ {
		w.sampleTick(t0.Add(time.Duration(i)*time.Second), []readerSample{{Reader: "node-2", S: stale}, {Reader: "node-6", S: leaseSample{Election: "node-6", Term: 72, Ledger: "node-6", Terms: terms, Expires: t0.Add(time.Hour), Now: t0}}})
	}
	if len(fails) != 0 {
		t.Fatalf("unexpired lag failed the drill: %v", fails)
	}
	// Two live self-claims on coherent-looking replicas: a real dual holder.
	w = &leaseWatch{incoh: map[string]*incoherenceTracker{}, termHolder: map[int]string{}, lastBy: map[string]leaseChange{}, maxTerm: map[string]int{},
		fail: func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }, logf: func(string, ...any) {}}
	live := func(h string) leaseSample {
		return leaseSample{Election: h, Term: 72, Ledger: h, Terms: map[int]string{72: h}, Expires: t0.Add(time.Hour), Now: t0}
	}
	for i := 0; i < 2; i++ {
		w.sampleTick(t0.Add(time.Duration(i)*time.Second), []readerSample{{Reader: "node-2", S: live("node-2")}, {Reader: "node-6", S: live("node-6")}})
	}
	if len(fails) == 0 || !strings.Contains(fails[len(fails)-1], "dual holder") {
		t.Fatalf("two live holders: %v", fails)
	}
	// An expired self-claim is not a holder.
	fails = nil
	w = &leaseWatch{incoh: map[string]*incoherenceTracker{}, termHolder: map[int]string{}, lastBy: map[string]leaseChange{}, maxTerm: map[string]int{},
		fail: func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }, logf: func(string, ...any) {}}
	dead := leaseSample{Election: "node-2", Term: 71, Ledger: "node-2", Terms: map[int]string{71: "node-2"}, Expires: t0.Add(-time.Minute), Now: t0}
	for i := 0; i < 4; i++ {
		w.sampleTick(t0.Add(time.Duration(i)*time.Second), []readerSample{{Reader: "node-2", S: dead}, {Reader: "node-6", S: leaseSample{Election: "node-6", Term: 72, Ledger: "node-6", Terms: map[int]string{71: "node-2", 72: "node-6"}, Expires: t0.Add(time.Hour), Now: t0}}})
	}
	if len(fails) != 0 {
		t.Fatalf("an expired self-claim failed: %v", fails)
	}
}
