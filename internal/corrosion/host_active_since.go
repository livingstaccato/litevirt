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

// fenceLifeSkew is how much older than the host's last membership change a
// proof-grade fence row may be and still count (HostFenceLife). The row is
// stamped with the fencer's wall clock to the second; the membership change
// with the writer's HLC, which runs ahead of its wall clock by as much as the
// furthest-ahead peer it has heard from. A fence and the state write beside it
// are one event (`lv host fence` writes 'offline' and then the row), so
// without a margin a peer a fraction of a second ahead could put the state
// write in the next second and disown the fence. Five seconds is the skew the
// upgrade preflight already refuses to call normal; any earlier life of the
// host ended at least a removal and an admission, or a boot, before it.
const fenceLifeSkew = 5 * time.Second

// HostFenceLife is the instant before which a fencing_log row of host says
// nothing about the host as it is now, with the membership state that sets
// it. ok=false when there is none to judge by — no live hosts row, no
// membership row, a node not reading host_membership yet, or a host recorded
// 'fenced' — and every row then counts, as before.
//
// host_membership.updated_at moves only with a state or isolation write, so it
// is when the host was last recorded as it is now: admitted under its name
// ('joining'), booted ('active'), lost without a proof ('offline'), drained.
// A fence row older than that is about an earlier life of the host — on the
// kvm003 lab (drill 6) the old node-5's confirmation, still in fencing_log
// when `lv host add` gave the name to a new machine, would have let
// `lv host rm --dead` remove the new one as proven off.
//
// A host recorded 'fenced' is exempt: that write IS a fence of the host as it
// is now (RecordFenceWithState, `lv host fence-confirm`), and its row stands
// beside it whatever the two clocks say.
func HostFenceLife(ctx context.Context, c *Client, host string) (since time.Time, state string, ok bool, err error) {
	if !c.HostMembershipLive() {
		return time.Time{}, "", false, nil
	}
	rows, err := scanMembership(ctx, c, ` WHERE h.name = ? AND h.deleted_at IS NULL`, host)
	if err != nil || len(rows) == 0 {
		return time.Time{}, "", false, err
	}
	r := rows[0]
	if !r.memPresent || r.mem.State == "fenced" {
		return time.Time{}, "", false, nil
	}
	at, ok := ParseUpdatedAt(r.memTS)
	if !ok {
		return time.Time{}, "", false, nil
	}
	return at.Add(-fenceLifeSkew).Truncate(time.Second), r.mem.State, true, nil
}
