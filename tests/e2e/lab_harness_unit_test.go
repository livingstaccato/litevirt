package e2e

import (
	"errors"
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

// TestIncoherenceTracker: a transient incoherent run is tolerated (and ends on
// a coherent sample); one that lasts the bound fails, once.
func TestIncoherenceTracker(t *testing.T) {
	t0 := time.Unix(1000, 0)
	var c incoherenceTracker
	for i := 0; i < 5; i++ { // 5 s, under the bound
		if c.observe(t0.Add(time.Duration(i)*time.Second), false) {
			t.Fatalf("a %d s run failed", i)
		}
	}
	c.observe(t0.Add(6*time.Second), true)
	if c.n != 0 {
		t.Fatal("a coherent sample did not end the run")
	}
	var fails int
	for i := 0; i < 30; i++ { // persistent
		if c.observe(t0.Add(time.Duration(20+i)*time.Second), false) {
			fails++
		}
	}
	if fails != 1 {
		t.Fatalf("a persistent run failed %d times, want once", fails)
	}
	// Three fast samples are not enough without the time bound, and the time
	// bound is not enough with fewer than three samples.
	var d incoherenceTracker
	d.observe(t0, false)
	if d.observe(t0.Add(11*time.Second), false) {
		t.Fatal("two samples failed")
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

// TestLeaseSampleCoherent pins the W3 fix: a restarted replica's stale election
// holder must not be paired with the ledger's newer term.
func TestLeaseSampleCoherent(t *testing.T) {
	for _, c := range []struct {
		election, ledger string
		want             bool
	}{{"node-4", "node-4", true}, {"node-2", "node-4", false}, {"", "node-4", true}, {"node-2", "", true}} {
		if got := leaseSampleCoherent(c.election, c.ledger); got != c.want {
			t.Errorf("(%q,%q) = %v, want %v", c.election, c.ledger, got, c.want)
		}
	}
}
