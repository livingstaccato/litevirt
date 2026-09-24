package compose

import (
	"strings"
	"testing"
)

// A healthcheck target is resolved relative to the VM: a bare port, an empty
// host and localhost all mean the VM's own address, because the probe runs on
// the VM's owning HOST, where "localhost" is the host.
func TestParseHealthTarget_ResolvesAgainstTheVM(t *testing.T) {
	const vm = "10.0.5.7"
	cases := []struct {
		typ, target string
		relative    bool
		want        string
	}{
		// tcp
		{"tcp", "22", true, "10.0.5.7:22"},
		{"tcp", ":22", true, "10.0.5.7:22"},
		{"tcp", "localhost:22", true, "10.0.5.7:22"},
		{"tcp", "LOCALHOST:22", true, "10.0.5.7:22"},
		{"tcp", "127.0.0.1:22", true, "10.0.5.7:22"},
		{"tcp", "127.0.1.1:22", true, "10.0.5.7:22"},
		{"tcp", "[::1]:22", true, "10.0.5.7:22"},
		{"tcp", "db.internal:5432", false, "db.internal:5432"},
		{"tcp", "10.0.0.9:80", false, "10.0.0.9:80"},
		// http / https
		{"http", "http://localhost:8080/health", true, "http://10.0.5.7:8080/health"},
		{"http", "http://127.0.0.1/health?x=1", true, "http://10.0.5.7/health?x=1"},
		{"http", "http://[::1]:8080/", true, "http://10.0.5.7:8080/"},
		{"http", ":8080/health", true, "http://10.0.5.7:8080/health"},
		{"http", "8080", true, "http://10.0.5.7:8080"},
		{"http", "/health", true, "http://10.0.5.7/health"},
		{"https", "443", true, "https://10.0.5.7:443"},
		{"http", "https://localhost:8443/ready", true, "https://10.0.5.7:8443/ready"},
		{"http", "http://example.com/health", false, "http://example.com/health"},
		{"http", "http://10.0.0.9:8080/health", false, "http://10.0.0.9:8080/health"},
		// ping
		{"ping", "", true, "10.0.5.7"},
		{"ping", "localhost", true, "10.0.5.7"},
		{"ping", "127.0.0.1", true, "10.0.5.7"},
		{"ping", "10.0.0.1", false, "10.0.0.1"},
		{"ping", "gw.internal", false, "gw.internal"},
		// exec runs inside the guest: never rewritten, never VM-relative.
		{"exec", "systemctl is-active nginx", false, "systemctl is-active nginx"},
	}
	for _, c := range cases {
		ht, err := ParseHealthTarget(c.typ, c.target)
		if err != nil {
			t.Errorf("ParseHealthTarget(%q, %q): %v", c.typ, c.target, err)
			continue
		}
		if ht.VMRelative != c.relative {
			t.Errorf("ParseHealthTarget(%q, %q).VMRelative = %v, want %v", c.typ, c.target, ht.VMRelative, c.relative)
		}
		if got := ht.Resolve(vm); got != c.want {
			t.Errorf("ParseHealthTarget(%q, %q).Resolve(%s) = %q, want %q", c.typ, c.target, vm, got, c.want)
		}
	}
}

// An IPv6 VM address is bracketed wherever a port or URL follows it.
func TestParseHealthTarget_IPv6VMAddress(t *testing.T) {
	for _, c := range []struct{ typ, target, want string }{
		{"tcp", "22", "[fd00::5]:22"},
		{"http", "http://localhost:8080/h", "http://[fd00::5]:8080/h"},
		{"http", "http://localhost/h", "http://[fd00::5]/h"},
		{"ping", "", "fd00::5"},
	} {
		ht, err := ParseHealthTarget(c.typ, c.target)
		if err != nil {
			t.Fatalf("ParseHealthTarget(%q, %q): %v", c.typ, c.target, err)
		}
		if got := ht.Resolve("fd00::5"); got != c.want {
			t.Errorf("%s %q resolved against fd00::5 = %q, want %q", c.typ, c.target, got, c.want)
		}
	}
}

func TestParseHealthTarget_RejectsWhatCannotBeProbed(t *testing.T) {
	cases := []struct{ typ, target, want string }{
		{"tcp", "", "needs a target"},
		{"tcp", "ssh", "port"},
		{"tcp", "0", "port"},
		{"tcp", "70000", "port"},
		{"tcp", "host:", "port"},
		{"tcp", "host:ssh", "port"},
		{"tcp", "http://localhost:22", "port"},
		{"http", "ftp://localhost/x", "http or https"},
		{"http", "http://localhost:99999/", "port"},
		{"http", "", "needs a target"},
		{"ping", "-f", "host"},
		{"ping", "a b", "host"},
		{"ping", "localhost:22", "host"},
		{"exec", "", "needs a command"},
		{"exec", "   ", "needs a command"},
		{"", "22", "type"},
		{"udp", "53", "type"},
	}
	for _, c := range cases {
		_, err := ParseHealthTarget(c.typ, c.target)
		if err == nil {
			t.Errorf("ParseHealthTarget(%q, %q) accepted a target that cannot be probed", c.typ, c.target)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseHealthTarget(%q, %q) error %q does not mention %q", c.typ, c.target, err, c.want)
		}
	}
}

// The lab failure: `target: "22"` was accepted and then dialled literally
// ("missing port in address"). It is valid now. What cannot be interpreted is
// refused when the compose file is parsed, before anything is deployed.
func TestParseBytes_HealthcheckTargetIsValidated(t *testing.T) {
	base := `
name: hc
vms:
  web:
    image: ubuntu
    healthcheck:
`
	ok := []string{
		"      type: tcp\n      target: \"22\"\n",
		"      type: http\n      target: \"http://localhost:8080/health\"\n",
		"      type: ping\n",
		"      type: exec\n      target: \"true\"\n      action: alert\n",
	}
	for _, hc := range ok {
		if _, err := ParseBytes([]byte(base + hc)); err != nil {
			t.Errorf("valid healthcheck refused:\n%s\nerror: %v", hc, err)
		}
	}
	bad := []struct{ hc, want string }{
		{"      type: tcp\n      target: \"ssh\"\n", `vm "web" healthcheck`},
		{"      type: tcp\n      target: \"ssh\"\n", "port"},
		{"      type: http\n      target: \"ftp://x/\"\n", "http or https"},
		{"      type: tcp\n      target: \"22\"\n      action: reboot\n", "action"},
		{"      target: \"22\"\n", "type"},
	}
	for _, c := range bad {
		_, err := ParseBytes([]byte(base + c.hc))
		if err == nil {
			t.Errorf("healthcheck that cannot run was accepted:\n%s", c.hc)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("healthcheck\n%s\nerror %q does not mention %q", c.hc, err, c.want)
		}
	}
}
