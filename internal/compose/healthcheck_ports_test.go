package compose

import (
	"strings"
	"testing"
)

// A service name where a port number belongs is refused, and for the
// well-known names the error gives the number to write instead.
func TestHealthcheck_NamedPortSaysWhichNumber(t *testing.T) {
	for _, c := range []struct{ typ, target, msg, hint string }{
		{"tcp", "ssh", `"ssh" is not a port number`, "use 22"},
		{"tcp", "localhost:postgres", `"postgres" is not a port number`, "use 5432"},
		{"tcp", "db.internal:postgresql", `"postgresql" is not a port number`, "use 5432"},
		{"tcp", ":redis", `"redis" is not a port number`, "use 6379"},
		{"http", "http://localhost:http/health", `"http" is not a port number`, "use 80"},
		{"https", "https://[::1]:https/", `"https" is not a port number`, "use 443"},
		{"tcp", "db:frobnicate", `"frobnicate" is not a port number`, "ports are numbers from 1 to 65535"},
	} {
		src := hcVM + "      type: " + c.typ + "\n      target: \"" + c.target + "\"\n"
		ps := problemsOf(t, src)
		p, ok := findProblem(ps, "vms.web.healthcheck.target", c.msg)
		if !ok {
			t.Errorf("%s %q: no problem %q; got:\n%s", c.typ, c.target, c.msg, dumpProblems(ps))
			continue
		}
		if p.Hint != c.hint {
			t.Errorf("%s %q: hint %q, want %q", c.typ, c.target, p.Hint, c.hint)
		}
	}
	_, err := ParseBytes([]byte(hcVM + "      type: tcp\n      target: ssh\n"))
	if want := `vms.web.healthcheck.target: "ssh" is not a port number — use 22`; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("error does not contain %q: %v", want, err)
	}
}

// The table is fixed, never the host's /etc/services, which differs from host
// to host: a name only /etc/services knows gets no number.
func TestHealthcheck_NamedPortTableIsFixed(t *testing.T) {
	ps := problemsOf(t, hcVM+"      type: tcp\n      target: \"gopher\"\n")
	p, ok := findProblem(ps, "vms.web.healthcheck.target", `"gopher" is not a port number`)
	if !ok {
		t.Fatalf("no problem; got:\n%s", dumpProblems(ps))
	}
	if strings.Contains(p.Hint, "use ") {
		t.Errorf("hint %q names a number for a name outside the fixed table", p.Hint)
	}
}

// A tcp target that names a host but no port says to add one.
func TestHealthcheck_TCPHostWithoutPort(t *testing.T) {
	ps := problemsOf(t, hcVM+"      type: tcp\n      target: \"db.internal\"\n")
	p, ok := findProblem(ps, "vms.web.healthcheck.target", "no port")
	if !ok {
		t.Fatalf("no problem; got:\n%s", dumpProblems(ps))
	}
	if want := `add one, e.g. "db.internal:22"`; p.Hint != want {
		t.Errorf("hint %q, want %q", p.Hint, want)
	}
}
