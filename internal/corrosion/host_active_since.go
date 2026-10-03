package corrosion

import (
	"context"
	"time"
)

// HostsActiveSince returns, for each live host whose membership row records it
// 'active', the instant of that row's last write: when the host last BECAME
// active, by its own boot write or by a recovery.
//
// host_membership.updated_at moves only with a state or isolation write
// (host_membership.go), never with the host's own reports, so for an active
// host it is the moment it turned active. Anything recorded about the host
// before that moment is about the host as it was before — joining, offline,
// fenced, or the machine removed under its name before `lv host add` gave the
// name to a new one — and not about the host that is active now. The failover
// coordinator uses it twice: a health observation older than it does not count
// toward a fence quorum, and a fence row older than it does not make the host
// "recently fenced".
//
// A host with no membership row, or a node not reading host_membership yet,
// is absent from the map: the caller then judges it as before.
func HostsActiveSince(ctx context.Context, c *Client) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if !c.HostMembershipLive() {
		return out, nil
	}
	rows, err := scanMembership(ctx, c, ` WHERE h.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if at, ok := activeSince(r); ok {
			out[r.name] = at
		}
	}
	return out, nil
}

// HostActiveSince is HostsActiveSince for one host: ok=false when host is not
// recorded active in a membership row this node reads.
func HostActiveSince(ctx context.Context, c *Client, host string) (time.Time, bool, error) {
	if !c.HostMembershipLive() {
		return time.Time{}, false, nil
	}
	rows, err := scanMembership(ctx, c, ` WHERE h.name = ? AND h.deleted_at IS NULL`, host)
	if err != nil || len(rows) == 0 {
		return time.Time{}, false, err
	}
	at, ok := activeSince(rows[0])
	return at, ok, nil
}

func activeSince(r membershipRow) (time.Time, bool) {
	if !r.memPresent || r.mem.State != "active" {
		return time.Time{}, false
	}
	return ParseUpdatedAt(r.memTS)
}
