package compose

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
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
				if !strings.Contains(target, ":") {
					if isPortName(target) && !strings.Contains(target, ".") {
						return ht, namedPortError(target)
					}
					if validPingHost(target) {
						return ht, &targetError{msg: fmt.Sprintf("tcp target %q has no port", target),
							hint: fmt.Sprintf("add one, e.g. %q", target+":22")}
					}
				}
				return ht, fmt.Errorf("tcp target %q is not a port or host:port: %v", target, err)
			}
			host, port = h, p
		}
		if err := checkPort(port); err != nil {
			return ht, prefixTarget("tcp", target, err)
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
		if name := urlPortName(raw); name != "" {
			return ht, namedPortError(name)
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
				return ht, prefixTarget(typ, target, err)
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

// inferHealthType is the probe type an untyped target can only mean: an
// http:// or https:// URL is that scheme; a port, ":port" or "host:port" is
// tcp. Anything else — an empty target, a path, a bare host (ping?), a
// command (exec?) — is not inferred, and ok is false.
func inferHealthType(target string) (typ string, ok bool) {
	t := strings.TrimSpace(target)
	lower := strings.ToLower(t)
	switch {
	case strings.HasPrefix(lower, "http://"):
		return "http", true
	case strings.HasPrefix(lower, "https://"):
		return "https", true
	case strings.Contains(t, "/"), strings.ContainsAny(t, " \t"):
		return "", false
	case isAllDigits(t):
		return "tcp", true
	}
	if _, _, err := net.SplitHostPort(t); err == nil {
		return "tcp", true
	}
	return "", false
}

// inferHealthTypes fills in the type of every healthcheck that has none and
// whose target settles it.
func inferHealthTypes(f *File) {
	for _, vm := range f.VMs {
		if hc := vm.HealthCheck; hc != nil && hc.Type == "" {
			if typ, ok := inferHealthType(hc.Target); ok {
				hc.Type = typ
				hc.typeInferred = true
			}
		}
	}
}

// The healthcheck defaults, as the VM health checker applies them. interval's
// default is also its floor: the checker sweeps every 10 seconds, so a
// shorter interval probes at each sweep.
const (
	defaultHealthInterval = 10 * time.Second
	defaultHealthTimeout  = 5 * time.Second
	defaultHealthRetries  = 3
	defaultHealthAction   = "restart"
)

// healthTimingProblems checks interval, timeout and retries: durations must
// parse and be greater than zero, a timeout must not outlast the interval,
// and retries, when written, must be at least 1. written reports whether the
// file writes a field (an omitted retries decodes as 0, meaning the default).
func healthTimingProblems(hc *HealthCheckDef, written func(field string) bool) []fieldProblem {
	if hc == nil {
		return nil
	}
	var out []fieldProblem
	interval, intervalOK := parseHealthDuration("interval", hc.Interval, &out)
	timeout, timeoutOK := parseHealthDuration("timeout", hc.Timeout, &out)
	if hc.Timeout != "" && timeoutOK && intervalOK {
		shown := hc.Interval
		if hc.Interval == "" {
			interval, shown = defaultHealthInterval, defaultHealthInterval.String()+" (the default)"
		}
		if timeout > interval {
			out = append(out, fieldProblem{field: "timeout",
				msg:  fmt.Sprintf("timeout %s exceeds interval %s", hc.Timeout, shown),
				hint: "lower timeout or raise interval"})
		}
	}
	if hc.Retries < 0 || (hc.Retries == 0 && written("retries")) {
		out = append(out, fieldProblem{field: "retries", msg: "retries must be at least 1",
			hint: fmt.Sprintf("omit it for the default, %d", defaultHealthRetries)})
	}
	return out
}

// parseHealthDuration parses a written duration field; ok is false when it is
// written and invalid (a problem is appended). An omitted field is ok, 0.
func parseHealthDuration(field, s string, out *[]fieldProblem) (time.Duration, bool) {
	if s == "" {
		return 0, true
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		hint := `e.g. "10s" or "1m"`
		if isAllDigits(s) {
			hint = fmt.Sprintf("add a unit, e.g. %q", s+"s")
		}
		*out = append(*out, fieldProblem{field: field, msg: fmt.Sprintf("%s %q is not a duration", field, s), hint: hint})
		return 0, false
	}
	if d <= 0 {
		*out = append(*out, fieldProblem{field: field, msg: field + " must be greater than 0"})
		return 0, false
	}
	return d, true
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
			fp := fieldProblem{field: "target", msg: err.Error()}
			var te *targetError
			if errors.As(err, &te) {
				fp.msg, fp.hint = te.msg, te.hint
			}
			out = append(out, fp)
		}
	case "":
		out = append(out, fieldProblem{field: "type", msg: "healthcheck type is required",
			hint: "want tcp | http | https | ping | exec (inferred only from a port, host:port or http(s):// URL target)"})
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
		if isPortName(p) {
			return namedPortError(p)
		}
		return fmt.Errorf("port %q must be a number from 1 to 65535", p)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port %q must be a number from 1 to 65535", p)
	}
	return nil
}

// targetError is a healthcheck target problem with a one-line fix.
type targetError struct {
	msg, hint string
}

func (e *targetError) Error() string {
	if e.hint == "" {
		return e.msg
	}
	return e.msg + " — " + e.hint
}

// prefixTarget names the target in a plain error; a targetError already says
// what it needs to.
func prefixTarget(typ, target string, err error) error {
	var te *targetError
	if errors.As(err, &te) {
		return err
	}
	return fmt.Errorf("%s target %q: %v", typ, target, err)
}

// wellKnownPorts is the number to suggest for a service name written where a
// port belongs. It is fixed on purpose: /etc/services differs from host to
// host, and a healthcheck must mean the same thing on every one.
var wellKnownPorts = map[string]int{
	"ssh":        22,
	"smtp":       25,
	"dns":        53,
	"domain":     53,
	"http":       80,
	"https":      443,
	"submission": 587,
	"imap":       143,
	"imaps":      993,
	"ldap":       389,
	"ldaps":      636,
	"mysql":      3306,
	"mariadb":    3306,
	"rdp":        3389,
	"postgres":   5432,
	"postgresql": 5432,
	"amqp":       5672,
	"vnc":        5900,
	"redis":      6379,
	"etcd":       2379,
	"memcached":  11211,
	"mongodb":    27017,
}

// namedPortError refuses a service name where a port number belongs, naming
// the number when the name is well known.
func namedPortError(name string) error {
	e := &targetError{msg: fmt.Sprintf("%q is not a port number", name)}
	if n, ok := wellKnownPorts[strings.ToLower(name)]; ok {
		e.hint = fmt.Sprintf("use %d", n)
	} else {
		e.hint = "ports are numbers from 1 to 65535"
	}
	return e
}

// isPortName reports whether s looks like a service name: letters, digits and
// '-', with at least one letter.
func isPortName(s string) bool {
	letter := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letter = true
		case r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return letter
}

// urlPortName is the service name a URL writes in its port position
// ("http://localhost:http/"), or "".
func urlPortName(raw string) string {
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	// An IPv6 literal's last group ends in ']', which is never a name.
	i := strings.LastIndexByte(rest, ':')
	if i < 0 {
		return ""
	}
	if p := rest[i+1:]; isPortName(p) {
		return p
	}
	return ""
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
