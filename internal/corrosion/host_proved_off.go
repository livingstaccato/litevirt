package corrosion

import (
	"context"
	"time"
)

// HostProvedOff reports whether the cluster has PROOF that host is powered
// off: it is recorded 'fenced' AND the newest fence on record for it
// (FenceRecordProvesOff) is proof-grade — a verified IPMI power-off or an
// operator's `lv host fence-confirm`.
//
// The state alone is not proof (colonelpanik/litevirt#253). A coordinator
// before fence_state_v1 latched — or on an older build — records 'fenced' for
// any successful fence, an SSH poweroff that nothing verified included, and
// such a host may still be running its workloads. Every reader that takes a
// host to be off, and so stops asking it anything, asks this instead of
// comparing the state. It reads the fence rows every row already carries, so
// it needs no backfill and judges 'fenced' rows an older leader wrote during
// the roll by the same rule.
//
// A read error is returned with false: callers fail closed, treating the
// host as possibly running.
func HostProvedOff(ctx context.Context, c *Client, host string) (bool, error) {
	h, err := GetHost(ctx, c, host)
	if err != nil {
		return false, err
	}
	if h == nil || h.State != "fenced" {
		return false, nil
	}
	return FenceRecordProvesOff(ctx, c, host)
}

// FenceRecordProvesOff reports whether the newest fence on record for host —
// the newest fencing_log row that is a fence attempt ("fenced" or "partial")
// or an operator confirmation ("manual-confirmed") — is proof-grade
// (FenceProofGrade). No row is no proof.
//
// The NEWEST row decides, not any proof-grade row: an IPMI power-off followed
// by a later SSH fence of the same host means the host was running again in
// between, and the SSH row proves nothing about it now. Rows that share a
// timestamp (fencing_log stamps to the second) are judged by the weaker one,
// so a tie never manufactures a proof. A row whose timestamp does not parse
// cannot be ordered and is skipped; every row this code writes parses.
func FenceRecordProvesOff(ctx context.Context, c *Client, host string) (bool, error) {
	rows, err := c.Query(ctx, `SELECT method, result, timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		return false, err
	}
	var newest time.Time
	found, proved := false, false
	for _, r := range rows {
		switch r.String("result") {
		case "fenced", "partial", "manual-confirmed":
		default:
			continue
		}
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			continue
		}
		pg := FenceProofGrade(r.String("method"), r.String("result"))
		switch {
		case !found || ts.After(newest):
			found, newest, proved = true, ts, pg
		case ts.Equal(newest):
			proved = proved && pg
		}
	}
	return found && proved, nil
}
