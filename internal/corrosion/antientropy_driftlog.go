package corrosion

import (
	"log/slog"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// driftRepeatInterval is how often a drift that has not changed is reported
// again. A pass runs every minute, and a drift that persists — a settled tie
// anti-entropy deliberately does not re-pull, or one it cannot repair — used
// to log the same line on every pass (leader_lease_terms on the kvm003 lab).
const driftRepeatInterval = time.Hour

// driftLog remembers, per peer and table, the drift last reported, so that a
// drift is logged when it first appears or changes and then once per
// driftRepeatInterval. Only the log is rate-limited: every mismatch is still
// returned, and so still pulled. A nil driftLog logs every mismatch.
type driftLog struct {
	now func() time.Time

	mu   sync.Mutex
	seen map[driftKey]driftSeen
}

type driftKey struct{ peer, table string }

type driftSeen struct {
	local, remote string
	logged, since time.Time
}

// note reports whether a drift (local, remote) of table against peer is to
// be logged now, and since when it has stood unchanged.
func (d *driftLog) note(peer, table, local, remote string) (bool, time.Time) {
	if d == nil {
		return true, time.Time{}
	}
	now := time.Now()
	if d.now != nil {
		now = d.now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[driftKey]driftSeen{}
	}
	k := driftKey{peer, table}
	s, ok := d.seen[k]
	if !ok || s.local != local || s.remote != remote {
		d.seen[k] = driftSeen{local: local, remote: remote, logged: now, since: now}
		return true, time.Time{}
	}
	if now.Sub(s.logged) >= driftRepeatInterval {
		s.logged = now
		d.seen[k] = s
		return true, s.since
	}
	return false, s.since
}

// agree forgets a table that is in sync with peer, so the same drift coming
// back is reported as new.
func (d *driftLog) agree(peer, table string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	delete(d.seen, driftKey{peer, table})
	d.mu.Unlock()
}

// mismatches returns the tables whose digest differs from the peer's.
func (d *driftLog) mismatches(peer string, remote []*pb.TableDigest, localMap map[string]TableDigest) []string {
	var out []string
	for _, r := range remote {
		local, exists := localMap[r.Name]
		lh, rh, digest := "", r.GetHash(), "v1"
		if exists {
			if TableDigestsAgree(local, r) {
				d.agree(peer, r.Name)
				continue // in sync
			}
			lh, rh = localAndRemoteHash(local, r)
			if local.HashV2 != "" && r.GetHashV2() != "" {
				digest = "v2"
			}
		}
		out = append(out, r.Name)
		attrs := []any{"peer", peer, "table", r.Name, "digest", digest, "local_hash", lh, "remote_hash", rh}
		if log, since := d.note(peer, r.Name, lh, rh); log {
			if !since.IsZero() {
				attrs = append(attrs, "unchanged_since", since.UTC().Format(time.RFC3339))
			}
			slog.Info("anti-entropy: drift detected", attrs...)
		} else {
			slog.Debug("anti-entropy: drift unchanged", attrs...)
		}
	}
	return out
}
