package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
