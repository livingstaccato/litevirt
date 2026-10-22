package fencessh

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/pki"
)

// Row states a status reports (PeerStatus.Row).
const (
	RowVerified   = "verified"
	RowUnverified = "unverified"
	RowMissing    = "missing"
	RowRetired    = "retired"
)

// Paths a status reports (PeerStatus.Path), beside fence's.
const (
	PathRefused = "refused"
	PathSelf    = "self"
)

// PeerStatus is one host as this host holds and reaches it.
type PeerStatus struct {
	Host          string
	Row           string
	RowDetail     string
	Accepting     bool
	EverAccepting bool
	Generation    int64
	CertSerial    string
	Address       string
	Path          string
	PathDetail    string
	Probe         *ProbeResult
}

// Status is this host's view of every live host, itself included: its row,
// the path a fence from here would take to it, and the last probe of it.
func (a *Agent) Status(ctx context.Context) ([]PeerStatus, error) {
	hosts, err := corrosion.ListHosts(ctx, a.cfg.DB)
	if err != nil {
		return nil, err
	}
	tr, trErr := TrustFromPKIDir(a.cfg.PKIDir)
	probes := a.Probes()
	var out []PeerStatus
	for _, h := range hosts {
		ps := PeerStatus{Host: h.Name, Row: RowMissing}
		row, ok, err := corrosion.GetHostFenceSSH(ctx, a.cfg.DB, h.Name)
		switch {
		case err != nil:
			ps.Row, ps.RowDetail = RowUnverified, err.Error()
		case !ok:
		case row.Deleted:
			ps.Row = RowRetired
		default:
			ps.Accepting, ps.EverAccepting, ps.Generation = row.Accepting, row.EverAccepting, row.Generation
			ps.RowDetail = row.Detail
			if cert, perr := pki.ParseCertPEM([]byte(row.CertPEM)); perr == nil {
				ps.CertSerial = strings.ToLower(cert.SerialNumber.Text(16))
				if addr, aerr := FenceAddress(cert); aerr == nil {
					ps.Address = addr.String()
				}
			}
			if trErr != nil {
				ps.Row, ps.RowDetail = RowUnverified, trErr.Error()
			} else if v, verr := Verify(row, tr); verr != nil {
				ps.Row, ps.RowDetail = RowUnverified, verr.Error()
			} else {
				ps.Row = RowVerified
				if v.Expired {
					ps.RowDetail = strings.TrimSpace("its certificate expired " + v.NotAfter.UTC().Format(time.RFC3339) +
						"; renew it with `lv host renew-cert " + h.Name + "`. " + ps.RowDetail)
				}
			}
		}
		if h.Name == a.cfg.Self {
			ps.Path = PathSelf
		} else {
			sf := a.FenceConfig(ctx, h.Name)
			switch {
			case sf.Refusal != "":
				ps.Path, ps.PathDetail = PathRefused, sf.Refusal
			case sf.Path == fence.SSHPathManaged:
				ps.Path = "managed"
			case sf.Path == fence.SSHPathPinned:
				ps.Path = "legacy-pinned"
			default:
				ps.Path = "legacy-unpinned"
				ps.PathDetail = "no fence ssh row: a fence of this host checks no host key, so a machine answering " +
					"at its address would be powered off in its place"
			}
			if p, ok := probes[h.Name]; ok {
				p := p
				ps.Probe = &p
			}
		}
		out = append(out, ps)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

// ProbedAt is p's time in RFC3339, "" for none.
func (p *ProbeResult) ProbedAt() string {
	if p == nil || p.At.IsZero() {
		return ""
	}
	return p.At.UTC().Format(time.RFC3339)
}
