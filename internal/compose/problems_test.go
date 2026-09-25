package compose

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// problemsOf parses src and returns its validation problems, failing the test
// when the error is not a *ValidationError.
func problemsOf(t *testing.T, src string) []Problem {
	t.Helper()
	_, err := ParseBytes([]byte(src))
	if err == nil {
		t.Fatalf("expected validation errors, got none for:\n%s", src)
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error is %T, want *ValidationError: %v", err, err)
	}
	return ve.Problems
}

func findProblem(ps []Problem, path, substr string) (Problem, bool) {
	for _, p := range ps {
		if p.Path == path && strings.Contains(p.Message+" "+p.Hint, substr) {
			return p, true
		}
	}
	return Problem{}, false
}

// Every problem in the file is reported in one pass, each naming its field
// path and where in the file it is, instead of the first problem only.
func TestValidation_ReportsEveryProblemWithPathAndPosition(t *testing.T) {
	src := `name: s
vms:
  db:
    image: ubuntu
    healthcheck:
      type: tcp
      target: "ssh"
      action: reboot
  web:
    cpu: 2
  lb:
    image: ubuntu
    loadbalancer:
      vip: "10.0.0.50"
      ports:
        - listen: 0
          target: 80
`
	ps := problemsOf(t, src)
	want := []struct {
		path, substr string
		line, col    int
	}{
		{"vms.db.healthcheck.target", "port", 7, 15},
		{"vms.db.healthcheck.action", "unknown healthcheck action", 8, 15},
		{"vms.web", "image or iso required", 9, 3},
		{"vms.lb.loadbalancer.vip", "valid CIDR", 14, 12},
		{"vms.lb.loadbalancer.ports[0].listen", "listen must be > 0", 16, 19},
	}
	for _, w := range want {
		p, ok := findProblem(ps, w.path, w.substr)
		if !ok {
			t.Errorf("no problem at %s mentioning %q; got:\n%s", w.path, w.substr, dumpProblems(ps))
			continue
		}
		if p.Line != w.line || p.Column != w.col {
			t.Errorf("%s at %d:%d, want %d:%d", w.path, p.Line, p.Column, w.line, w.col)
		}
	}
}

// The rendered error puts position, path, message and hint on one line, in the
// file:line:col form editors and terminals recognise.
func TestValidation_ErrorFormat(t *testing.T) {
	src := `name: s
vms:
  web:
    cpu: 2
`
	_, err := ParseBytes([]byte(src))
	if err == nil {
		t.Fatal("expected an error")
	}
	want := "compose validation errors:\n  - 3:3: vms.web: image or iso required — set image: or iso:"
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error =\n%s\nwant prefix\n%s", err, want)
	}

	path := filepath.Join(t.TempDir(), "stack.yaml")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Parse(path)
	if err == nil || !strings.Contains(err.Error(), "  - "+path+":3:3: vms.web: ") {
		t.Errorf("Parse(path) error does not name the file: %v", err)
	}
}

// A problem under workloads: is reported under workloads:, where the operator
// wrote it, not under the vms: map the parser folds it into.
func TestValidation_WorkloadPathsNameTheirMap(t *testing.T) {
	ps := problemsOf(t, `name: s
workloads:
  c1:
    kind: lxc
    replicas: -1
    image: alpine
`)
	if _, ok := findProblem(ps, "workloads.c1.replicas", "replicas must be >= 0"); !ok {
		t.Errorf("want workloads.c1.replicas problem; got:\n%s", dumpProblems(ps))
	}
}

// depends-on problems are all reported, not only the first.
func TestValidation_AllUnknownDependenciesReported(t *testing.T) {
	ps := problemsOf(t, `name: s
vms:
  a:
    image: u
    depends-on: [x, y]
`)
	for _, dep := range []string{"x", "y"} {
		if _, ok := findProblem(ps, "vms.a.depends-on."+dep, "unknown vm"); !ok {
			t.Errorf("no problem for depends-on %s; got:\n%s", dep, dumpProblems(ps))
		}
	}
}

func dumpProblems(ps []Problem) string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteString("  " + p.String() + "\n")
	}
	return b.String()
}
