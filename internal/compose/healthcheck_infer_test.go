package compose

import (
	"strings"
	"testing"
)

const hcVM = "name: hc\nvms:\n  web:\n    image: ubuntu\n    healthcheck:\n"

// The type is inferred when the target leaves no doubt: an http:// or
// https:// URL, or a port, :port or host:port (tcp). A type that is given
// always wins, and ping and exec are never inferred.
func TestParseBytes_HealthcheckTypeInferredFromTarget(t *testing.T) {
	for _, c := range []struct{ hc, want string }{
		{"      target: \"22\"\n", "tcp"},
		{"      target: \":22\"\n", "tcp"},
		{"      target: \"db.internal:5432\"\n", "tcp"},
		{"      target: \"[::1]:22\"\n", "tcp"},
		{"      target: \"http://localhost:8080/health\"\n", "http"},
		{"      target: \"https://localhost:8443/ready\"\n", "https"},
		{"      type: http\n      target: \"8080\"\n", "http"},
		{"      type: https\n      target: \"http://localhost/\"\n", "https"},
	} {
		f, err := ParseBytes([]byte(hcVM + c.hc))
		if err != nil {
			t.Errorf("healthcheck\n%s\nrefused: %v", c.hc, err)
			continue
		}
		if got := f.VMs["web"].HealthCheck.Type; got != c.want {
			t.Errorf("healthcheck\n%s\ntype = %q, want %q", c.hc, got, c.want)
		}
	}
}

// When the target does not settle the type, the error lists the valid types
// and says what can be inferred.
func TestParseBytes_HealthcheckTypeNotInferable(t *testing.T) {
	for _, hc := range []string{
		"      retries: 3\n",
		"      target: \"/health\"\n",
		"      target: \"10.0.0.1\"\n",
		"      target: \"systemctl is-active nginx\"\n",
		"      target: \"ftp://x/\"\n",
	} {
		ps := problemsOf(t, hcVM+hc)
		p, ok := findProblem(ps, "vms.web.healthcheck.type", "type is required")
		if !ok {
			t.Errorf("healthcheck\n%s\nno type problem; got:\n%s", hc, dumpProblems(ps))
			continue
		}
		if !strings.Contains(p.Hint, "tcp | http | https | ping | exec") || !strings.Contains(p.Hint, "inferred") {
			t.Errorf("hint %q does not list the types and what is inferred", p.Hint)
		}
	}
}
