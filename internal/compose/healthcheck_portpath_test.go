package compose

import (
	"strings"
	"testing"
)

// A port followed by a path, query or fragment, written without a scheme, is
// a port on the VM — as a bare port is. It used to become a URL whose HOST was
// the port ("8080/health" → http://8080/health), a probe that could never
// pass, which with the default restart action restarted a healthy VM over
// and over.
func TestParseHealthTarget_PortWithPathIsOnTheVM(t *testing.T) {
	const vm = "10.0.5.7"
	for _, c := range []struct{ typ, target, want string }{
		{"http", "8080/health", "http://10.0.5.7:8080/health"},
		{"https", "8443/healthz", "https://10.0.5.7:8443/healthz"},
		{"http", "8080?x=1", "http://10.0.5.7:8080?x=1"},
		{"http", "8080#frag", "http://10.0.5.7:8080#frag"},
		{"http", "8080/", "http://10.0.5.7:8080/"},
		{"http", "8080", "http://10.0.5.7:8080"},
	} {
		ht, err := ParseHealthTarget(c.typ, c.target)
		if err != nil {
			t.Errorf("ParseHealthTarget(%q, %q): %v", c.typ, c.target, err)
			continue
		}
		if !ht.VMRelative {
			t.Errorf("ParseHealthTarget(%q, %q) is not VM-relative", c.typ, c.target)
		}
		if got := ht.Resolve(vm); got != c.want {
			t.Errorf("ParseHealthTarget(%q, %q).Resolve = %q, want %q", c.typ, c.target, got, c.want)
		}
	}
}

// A host name made only of digits is no host anyone means: it is refused, not
// probed. A numeric IP address is still a host.
func TestParseHealthTarget_AllNumericHostIsRefused(t *testing.T) {
	for _, c := range []struct{ typ, target string }{
		{"http", "http://8080/health"},
		{"https", "https://8443"},
		{"http", "8080:80/health"},
		{"http", "http://1.2.3/x"},
		{"tcp", "8080:22"},
		{"ping", "8080"},
	} {
		if _, err := ParseHealthTarget(c.typ, c.target); err == nil || !strings.Contains(err.Error(), "numeric") {
			t.Errorf("ParseHealthTarget(%q, %q) = %v, want an all-numeric host refused", c.typ, c.target, err)
		}
	}
	for _, target := range []string{"http://10.0.0.9:8080/health", "http://example.com/health", "http://web-1:8080/"} {
		if _, err := ParseHealthTarget("http", target); err != nil {
			t.Errorf("ParseHealthTarget(http, %q): %v", target, err)
		}
	}
}
