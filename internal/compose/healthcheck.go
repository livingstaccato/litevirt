package compose

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Healthcheck targets are resolved relative to the VM.
//
// The VM health checker runs on the VM's OWNING HOST, not in the guest. A
// target taken literally there probes the host: `localhost` is the host's
// loopback, and a bare port is not an address at all ("missing port in
// address"), so a documented healthcheck either never passed or checked the
// wrong machine — and with the default `restart` action, a probe that could
// never pass restarted a healthy VM over and over.
//
// So a target names a place on the VM unless it names another host:
//
//	tcp    "22", ":22", "localhost:22", "127.0.0.1:22"  → <vm>:22
//	       "db.internal:5432"                           → as given
//	http   "http://localhost:8080/health", ":8080/health", "8080", "/health"
//	                                                    → http://<vm>:8080/health …
//	       "http://example.com/health"                  → as given
//	ping   "" or "localhost"                            → <vm>
//	       "10.0.0.1"                                   → as given
//	exec   the command, run in the guest by its agent   → never rewritten
//
// Every loopback address (127.0.0.0/8, ::1) and the name localhost count as
// the VM: from the host they would name the host, which is never what a VM's
// healthcheck means.

// HealthTarget is a healthcheck target as the VM health checker interprets it.
type HealthTarget struct {
	// Type is the probe type: tcp | http | https | ping | exec.
	Type string
	// VMRelative is true when the probe goes to the VM's own address, which
	// the checker must know before it can probe at all.
	VMRelative bool

	host string   // tcp, ping: the explicit host ("" when VMRelative)
	port string   // tcp: the port
	u    *url.URL // http/https
	cmd  string   // exec
}

// ParseHealthTarget interprets a healthcheck's type and target, or says why it
// cannot be probed.
func ParseHealthTarget(typ, target string) (HealthTarget, error) {
	ht := HealthTarget{Type: typ}
	target = strings.TrimSpace(target)
	switch typ {
	case "tcp":
		if target == "" {
			return ht, fmt.Errorf(`tcp healthcheck needs a target: a port ("22") or host:port`)
		}
		host, port := "", target
		if !isAllDigits(target) {
			h, p, err := net.SplitHostPort(target)
			if err != nil {
				return ht, fmt.Errorf("tcp target %q is not a port or host:port: %v", target, err)
			}
			host, port = h, p
		}
		if err := checkPort(port); err != nil {
			return ht, fmt.Errorf("tcp target %q: %v", target, err)
		}
		ht.port = port
		if isVMSelf(host) {
			ht.VMRelative = true
		} else {
			ht.host = host
		}
		return ht, nil

	case "http", "https":
		if target == "" {
			return ht, fmt.Errorf(`%s healthcheck needs a target: a URL, a port ("8080") or ":8080/path"`, typ)
		}
		raw := target
		if !strings.Contains(raw, "://") {
			if isAllDigits(raw) {
				raw = ":" + raw
			}
			raw = typ + "://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			return ht, fmt.Errorf("%s target %q is not a URL: %v", typ, target, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return ht, fmt.Errorf("%s target %q: scheme must be http or https, got %q", typ, target, u.Scheme)
		}
		if p := u.Port(); p != "" {
			if err := checkPort(p); err != nil {
				return ht, fmt.Errorf("%s target %q: %v", typ, target, err)
			}
		} else if strings.HasSuffix(u.Host, ":") {
			return ht, fmt.Errorf("%s target %q: empty port", typ, target)
		}
		ht.u = u
		ht.VMRelative = isVMSelf(u.Hostname())
		return ht, nil

	case "ping":
		if isVMSelf(target) {
			ht.VMRelative = true
			return ht, nil
		}
		if !validPingHost(target) {
			return ht, fmt.Errorf("ping target %q must be a host name or IP address (or empty, for the VM)", target)
		}
		ht.host = target
		return ht, nil

	case "exec":
		if target == "" {
			return ht, fmt.Errorf("exec healthcheck needs a command to run in the guest")
		}
		ht.cmd = target
		return ht, nil

	case "":
		return ht, fmt.Errorf("healthcheck type is required: tcp | http | https | ping | exec")
	default:
		return ht, fmt.Errorf("unknown healthcheck type %q: want tcp | http | https | ping | exec", typ)
	}
}

// Resolve returns the concrete target the probe transport uses: for a
// VM-relative target, vmAddr substituted for the host; otherwise the target as
// given. vmAddr is ignored when the target is not VM-relative.
func (t HealthTarget) Resolve(vmAddr string) string {
	switch t.Type {
	case "tcp":
		host := t.host
		if t.VMRelative {
			host = vmAddr
		}
		return net.JoinHostPort(host, t.port)
	case "http", "https":
		if t.u == nil {
			return ""
		}
		u := *t.u
		if t.VMRelative {
			if p := u.Port(); p != "" {
				u.Host = net.JoinHostPort(vmAddr, p)
			} else if strings.Contains(vmAddr, ":") {
				u.Host = "[" + vmAddr + "]"
			} else {
				u.Host = vmAddr
			}
		}
		return u.String()
	case "ping":
		if t.VMRelative {
			return vmAddr
		}
		return t.host
	case "exec":
		return t.cmd
	}
	return ""
}

// ValidateHealthCheck reports why hc cannot be run, or nil.
func ValidateHealthCheck(hc *HealthCheckDef) error {
	ps := healthProblems(hc)
	if len(ps) == 0 {
		return nil
	}
	msgs := make([]string, len(ps))
	for i, p := range ps {
		msgs[i] = p.field + ": " + p.msg
		if p.hint != "" {
			msgs[i] += " — " + p.hint
		}
	}
	return errors.New(strings.Join(msgs, "; "))
}

// fieldProblem is a problem with one field of a block, relative to it.
type fieldProblem struct {
	field, msg, hint string
}

// healthProblems is every reason hc cannot be run, each naming its field.
func healthProblems(hc *HealthCheckDef) []fieldProblem {
	if hc == nil {
		return nil
	}
	var out []fieldProblem
	switch hc.Type {
	case "tcp", "http", "https", "ping", "exec":
		if _, err := ParseHealthTarget(hc.Type, hc.Target); err != nil {
			out = append(out, fieldProblem{field: "target", msg: err.Error()})
		}
	case "":
		out = append(out, fieldProblem{field: "type", msg: "healthcheck type is required", hint: "want tcp | http | https | ping | exec"})
	default:
		out = append(out, fieldProblem{field: "type", msg: fmt.Sprintf("unknown healthcheck type %q", hc.Type), hint: "want tcp | http | https | ping | exec"})
	}
	switch hc.Action {
	case "", "restart", "migrate", "alert":
	default:
		out = append(out, fieldProblem{field: "action", msg: fmt.Sprintf("unknown healthcheck action %q", hc.Action), hint: "want restart | migrate | alert"})
	}
	return out
}

// isVMSelf reports whether host, in a healthcheck target, means the VM itself:
// empty, localhost, or any loopback address.
func isVMSelf(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" || h == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func checkPort(p string) error {
	if !isAllDigits(p) {
		return fmt.Errorf("port %q must be a number from 1 to 65535", p)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port %q must be a number from 1 to 65535", p)
	}
	return nil
}

// validPingHost accepts an IP literal or a DNS name. It refuses anything ping
// would read as an option (a leading '-') or that is not a single host.
func validPingHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if s == "" || len(s) > 253 || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	return true
}
