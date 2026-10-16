package lb

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/safename"
)

// CertDir is where a stack LB's TLS certificate and key files live. A spec
// naming a file elsewhere needs the admin role (the daemon reads it as root).
const CertDir = "/etc/litevirt/lb-certs"

// Settings is what an LB's spec says about its listeners and backends, in
// lb's terms.
type Settings struct {
	Algorithm string
	Ports     []Port
	Health    *HealthConfig
	Sticky    bool
}

// SettingsFromPB converts an LB's wire settings: the one conversion for its
// apply (on the coordinator and on a peer) and for checking a spec at ingress.
func SettingsFromPB(algorithm string, ports []*pb.LBPort, health *pb.LBHealthSpec, sticky bool) Settings {
	out := Settings{Algorithm: algorithm, Sticky: sticky}
	if out.Algorithm == "" {
		out.Algorithm = "roundrobin"
	}
	for _, p := range ports {
		port := Port{
			Listen:        int(p.Listen),
			Target:        int(p.Target),
			Protocol:      p.Protocol,
			RedirectHTTPS: p.RedirectHttps,
		}
		if p.Tls != nil {
			port.TLS = &TLSConfig{Cert: p.Tls.Cert, Key: p.Tls.Key}
		}
		out.Ports = append(out.Ports, port)
	}
	if health != nil {
		out.Health = &HealthConfig{Type: health.Type, Path: health.Path}
		if health.Interval != "" {
			if d, err := time.ParseDuration(health.Interval); err == nil {
				out.Health.IntervalMS = int(d.Milliseconds())
			}
		}
	}
	return out
}

// Problem is one invalid LB setting. Field is relative to the LB
// ("algorithm", "ports[1].tls.cert", "health.path").
type Problem struct {
	Field string
	Msg   string
}

func (p Problem) Error() string { return p.Field + ": " + p.Msg }

// healthPathRe is an HTTP health-check path: one absolute token of visible
// ASCII, without anything haproxy's config parser treats specially.
var healthPathRe = regexp.MustCompile(`^/[!$%&(-\[\]-z|~]*$`)

const maxHealthPath = 512

// CheckSettings reports every setting of an LB that may not be rendered:
// values outside their enums, a health path that is not one plain token,
// TLS file paths that are not clean absolute paths, and redirect-https
// where it cannot work (RedirectProblem). Ingress refuses a spec with any.
func CheckSettings(s Settings) []Problem {
	var ps []Problem
	switch s.Algorithm {
	case "", "roundrobin", "leastconn", "source":
	default:
		ps = append(ps, Problem{"algorithm", fmt.Sprintf("%q is not one of roundrobin, leastconn, source", s.Algorithm)})
	}
	for i, p := range s.Ports {
		f := fmt.Sprintf("ports[%d]", i)
		switch p.Protocol {
		case "", "tcp", "http":
		default:
			ps = append(ps, Problem{f + ".protocol", fmt.Sprintf("%q is not one of tcp, http", p.Protocol)})
		}
		if p.TLS != nil {
			if err := checkTLSPath(p.TLS.Cert); err != nil {
				ps = append(ps, Problem{f + ".tls.cert", err.Error()})
			}
			if err := checkTLSPath(p.TLS.Key); err != nil {
				ps = append(ps, Problem{f + ".tls.key", err.Error()})
			}
		}
		if msg := RedirectProblem(s.Ports, i); msg != "" {
			ps = append(ps, Problem{f + ".redirect-https", msg})
		}
	}
	if h := s.Health; h != nil {
		switch h.Type {
		case "", "tcp", "http":
		default:
			ps = append(ps, Problem{"health.type", fmt.Sprintf("%q is not one of tcp, http", h.Type)})
		}
		if h.Path != "" && (len(h.Path) > maxHealthPath || !healthPathRe.MatchString(h.Path)) {
			ps = append(ps, Problem{"health.path", fmt.Sprintf("%q must be an absolute path of visible ASCII, at most %d characters, without spaces, quotes, '#' or '\\'", h.Path, maxHealthPath)})
		}
	}
	return ps
}

// RedirectProblem says why port i's redirect-https cannot be served, or ""
// when it can (or is not asked for). A redirect answers HTTP, so it needs an
// http listener without TLS, and somewhere to send the client: a TLS
// listener on the same LB.
func RedirectProblem(ports []Port, i int) string {
	p := ports[i]
	if !p.RedirectHTTPS {
		return ""
	}
	if p.TLS != nil {
		return "redirect-https on a tls listener would redirect to itself"
	}
	if p.Protocol != "http" {
		return "redirect-https needs protocol http"
	}
	for _, q := range ports {
		if q.TLS != nil {
			return ""
		}
	}
	return "redirect-https needs a tls listener on the same load balancer to redirect to"
}

// TLSPathOutsideCertDir reports whether path is not inside CertDir.
func TLSPathOutsideCertDir(path string) bool {
	return !safename.Contains(CertDir, path)
}

func checkTLSPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%q must be a clean absolute path", path)
	}
	if strings.IndexFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("%q contains a control character", path)
	}
	return nil
}

// checkToken refuses a value that would not stay one token in a rendered
// config: whitespace, control characters, quotes, a backslash, '#', or a
// brace. The renderers refuse such a config rather than escape it.
func checkToken(field, v string) error {
	if i := strings.IndexFunc(v, func(r rune) bool {
		return r <= 0x20 || r >= 0x7f || strings.ContainsRune("\"'\\#{}", r)
	}); i >= 0 {
		return fmt.Errorf("lb: %s %q contains %q, which may not appear in a rendered config", field, v, v[i:i+1])
	}
	return nil
}

// checkRender is the renderers' last line: the LB's name is a safe name (it
// names root-owned files and a shell script), and every value they render is
// one plain token.
func checkRender(cfg Config) error {
	if err := ValidateName(cfg.Name); err != nil {
		return err
	}
	fields := []struct{ name, v string }{
		{"vip", cfg.VIP}, {"interface", cfg.Interface}, {"algorithm", cfg.Algorithm},
		{"local ip", cfg.LocalIP}, {"peer ip", cfg.PeerIP}, {"subnet", cfg.Subnet},
		{"sync interface", cfg.SyncInterface}, {"config dir", cfg.ConfigDir},
		{"run dir", cfg.RunDir}, {"lock dir", cfg.LockDir}, {"control dir", cfg.ControlDir},
	}
	if cfg.Health != nil {
		fields = append(fields, struct{ name, v string }{"health type", cfg.Health.Type},
			struct{ name, v string }{"health path", cfg.Health.Path})
	}
	for _, b := range cfg.Backends {
		fields = append(fields, struct{ name, v string }{"backend name", b.Name},
			struct{ name, v string }{"backend ip", b.IP})
	}
	for _, p := range cfg.Ports {
		fields = append(fields, struct{ name, v string }{"protocol", p.Protocol})
	}
	for _, f := range fields {
		if err := checkToken(f.name, f.v); err != nil {
			return err
		}
	}
	return nil
}

// ValidateName refuses an LB name that is not a safe name. Every file the
// manager writes, and the notify script keepalived runs as root, is named
// after it.
func ValidateName(name string) error {
	if err := safename.ValidateName(name); err != nil {
		return fmt.Errorf("lb: invalid load balancer name: %w", err)
	}
	return nil
}
