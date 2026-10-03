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
// host it is the moment it turned active. A health observation older than that
// is about the host as it was before — joining, offline, fenced — and not about
// the host that is active now. The failover coordinator uses it to give a host
// that just turned active a fresh count: on the kvm003 lab a re-added host was
// fenced 2 s after its boot write, on counts observed while it was joining.
//
// A host with no membership row, or a node not reading host_membership yet,
// is absent from the map: the caller then judges its observations as before.
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
		if !r.memPresent || r.mem.State != "active" {
			continue
		}
		if at, ok := ParseUpdatedAt(r.memTS); ok {
			out[r.name] = at
		}
	}
	return out, nil
}
