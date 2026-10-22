package corrosion

import "context"

// ClusterOfOneBut reports whether host self has no peer at all — no gossip
// member, and no other host in its hosts table — except hosts still 'joining'
// that admitted accepts.
//
// A joining host was admitted by `lv host add` and its daemon has never
// booted on this admission: it has written nothing, no placement targets it,
// and it is no gossip member, since a daemon that had booted would have
// recorded itself 'upgrading' or 'active'. Workloads can still be recorded
// under a re-admitted name (stopped VMs, restart-same VMs failover holds), but
// those were already this node's to decide while the name was removed, when
// it was alone on any count. Without the exception a founder that has
// never had a peer (whose replica therefore never completes a catch-up) took
// its own half-admitted second host for a peer the moment `lv host add`
// wrote the joining row, and was no longer alone. admitted narrows which
// joining hosts are let through: the one host and certificate a decision is
// about, or any (AnyAdmission) for a decision that is about none of them.
//
// Any gossip member, any host in another state, or a joining host admitted
// refuses still means self is not alone. Both sources, because each alone can
// be empty on a node that does have peers: the hosts table on a node that has
// joined gossip but not yet received the table, gossip on a node whose
// memberlist has not formed.
func ClusterOfOneBut(ctx context.Context, c *Client, self string, admitted func(HostRecord) bool) (bool, error) {
	if len(c.Members()) > 0 {
		return false, nil
	}
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		return false, err
	}
	for _, h := range hosts {
		if h.Name == self {
			continue
		}
		if h.State == HostStateJoining && admitted(h) {
			continue
		}
		return false, nil
	}
	return true, nil
}

// AnyAdmission lets every joining host through ClusterOfOneBut.
func AnyAdmission(HostRecord) bool { return true }

// NoAdmission lets no joining host through ClusterOfOneBut: it is then a
// plain "no peer at all".
func NoAdmission(HostRecord) bool { return false }

// soleOrOnlyJoiners is the alone test of a gate that trusts a replica which
// has not caught up when there is nothing to catch up with: no host but self
// in its hosts table, or (ClusterOfOneBut) no gossip member and only hosts
// still joining. ReplicaTrusted and the genesis firewall seeds ask it.
func soleOrOnlyJoiners(ctx context.Context, c *Client, self string) (bool, error) {
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		return false, err
	}
	for _, h := range hosts {
		if h.Name != self {
			return ClusterOfOneBut(ctx, c, self, AnyAdmission)
		}
	}
	return true, nil
}
