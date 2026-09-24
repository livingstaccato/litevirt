package compose

import (
	"strings"
	"testing"
)

const hcBase = `name: s
vms:
  db:
    image: u
    healthcheck:
      type: tcp
      target: "22"
`

// A misspelt healthcheck field is refused with the field it most likely
// meant, positioned at the key — not silently ignored, which left the
// default in force with nothing to say so.
func TestHealthcheck_UnknownFieldDidYouMean(t *testing.T) {
	ps := problemsOf(t, hcBase+"      retires: 5\n      intervl: 30s\n      tpye: tcp\n")
	for _, c := range []struct {
		key, hint string
		line, col int
	}{
		{"retires", `did you mean "retries"?`, 8, 7},
		{"intervl", `did you mean "interval"?`, 9, 7},
		{"tpye", `did you mean "type"?`, 10, 7},
	} {
		p, ok := findProblem(ps, "vms.db.healthcheck", `unknown field "`+c.key+`"`)
		if !ok {
			t.Errorf("no unknown-field problem for %q; got:\n%s", c.key, dumpProblems(ps))
			continue
		}
		if p.Hint != c.hint {
			t.Errorf("%s: hint %q, want %q", c.key, p.Hint, c.hint)
		}
		if p.Line != c.line || p.Column != c.col {
			t.Errorf("%s at %d:%d, want %d:%d", c.key, p.Line, p.Column, c.line, c.col)
		}
	}
	want := `vms.db.healthcheck: unknown field "retires" — did you mean "retries"?`
	if _, err := ParseBytes([]byte(hcBase + "      retires: 5\n")); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("error does not contain %q: %v", want, err)
	}
}

// An unknown field does not hide the file's other problems.
func TestHealthcheck_UnknownFieldAndOtherProblemsTogether(t *testing.T) {
	ps := problemsOf(t, hcBase+"      retires: 5\n      retries: 0\n  web:\n    cpu: 1\n")
	for _, w := range []struct{ path, substr string }{
		{"vms.db.healthcheck", `unknown field "retires"`},
		{"vms.db.healthcheck.retries", "at least 1"},
		{"vms.web", "image or iso required"},
	} {
		if _, ok := findProblem(ps, w.path, w.substr); !ok {
			t.Errorf("no problem %q at %s; got:\n%s", w.substr, w.path, dumpProblems(ps))
		}
	}
}

// A broken extends is reported alone for its child: the child's inherited
// fields were never merged, and reporting them missing would mislead.
func TestValidation_BrokenExtendsDoesNotReportInheritedFieldsMissing(t *testing.T) {
	ps := problemsOf(t, "name: s\nvms:\n  web:\n    extends: base\n")
	if _, ok := findProblem(ps, "vms.web.extends", `extends unknown vm "base"`); !ok {
		t.Errorf("no extends problem; got:\n%s", dumpProblems(ps))
	}
	if _, ok := findProblem(ps, "vms.web", "image or iso required"); ok {
		t.Errorf("an unmerged child was reported missing its image:\n%s", dumpProblems(ps))
	}
}

// With nothing close to suggest, the hint lists the fields there are.
func TestHealthcheck_UnknownFieldListsValidFields(t *testing.T) {
	ps := problemsOf(t, hcBase+"      colour: red\n")
	p, ok := findProblem(ps, "vms.db.healthcheck", `unknown field "colour"`)
	if !ok {
		t.Fatalf("no unknown-field problem; got:\n%s", dumpProblems(ps))
	}
	if want := "valid fields: type, target, interval, timeout, retries, action"; p.Hint != want {
		t.Errorf("hint %q, want %q", p.Hint, want)
	}
}

// Extension fields (x-*) and YAML merge keys are legitimate and pass; a typo
// inside a merged anchor is still caught, positioned where it is written.
func TestHealthcheck_ExtensionFieldsAndMergeKeys(t *testing.T) {
	ok := `name: s
x-hc: &hc
  type: tcp
  target: "22"
vms:
  db:
    image: u
    healthcheck:
      <<: *hc
      x-note: "probe postgres"
      retries: 2
`
	if _, err := ParseBytes([]byte(ok)); err != nil {
		t.Errorf("merge key / extension field refused: %v", err)
	}

	bad := strings.Replace(ok, `  target: "22"`, "  target: \"22\"\n  timout: 2s", 1)
	ps := problemsOf(t, bad)
	p, found := findProblem(ps, "vms.db.healthcheck", `unknown field "timout"`)
	if !found {
		t.Fatalf("typo in a merged anchor not reported; got:\n%s", dumpProblems(ps))
	}
	if p.Line != 5 {
		t.Errorf("typo reported at line %d, want 5 (inside the anchor)", p.Line)
	}
}

func TestHealthcheck_UnknownFieldUnderWorkloads(t *testing.T) {
	ps := problemsOf(t, `name: s
workloads:
  c:
    kind: lxc
    image: alpine
    healthcheck:
      type: ping
      acton: alert
`)
	if _, ok := findProblem(ps, "workloads.c.healthcheck", `did you mean "action"?`); !ok {
		t.Errorf("want workloads.c.healthcheck problem; got:\n%s", dumpProblems(ps))
	}
}

// YAML already accepted and stored (a deployed stack) is re-read leniently:
// a field a later build refuses must not make the stack unreadable to the
// code that tears it down or resolves its volumes.
func TestParseStored_AcceptsUnknownFields(t *testing.T) {
	src := hcBase + "      retires: 5\n"
	if _, err := ParseBytes([]byte(src)); err == nil {
		t.Fatal("ParseBytes accepted an unknown healthcheck field")
	}
	f, err := ParseStored([]byte(src))
	if err != nil {
		t.Fatalf("ParseStored refused stored YAML over an unknown field: %v", err)
	}
	if f.VMs["db"].HealthCheck == nil || f.VMs["db"].HealthCheck.Target != "22" {
		t.Errorf("ParseStored lost the healthcheck: %+v", f.VMs["db"].HealthCheck)
	}
}

// Case never stands between a key and the field it meant, and '_' for '-' is
// one edit.
func TestSuggest_IgnoresCase(t *testing.T) {
	for _, c := range []struct{ key, want string }{
		{"depends_on", "depends-on"},
		{"CLOUD-INIT", "cloud-init"},
		{"stop_grace_period", "stop-grace-period"},
		{"zzz", ""},
	} {
		if got := suggest(c.key, []string{"depends-on", "cloud-init", "stop-grace-period", "image"}); got != c.want {
			t.Errorf("suggest(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}
