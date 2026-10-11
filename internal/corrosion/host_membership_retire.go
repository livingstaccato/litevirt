package corrosion

// Retiring the hosts copy of a host's membership (host_membership_retire_v1,
// docs/design/host-membership-retire-old-columns.md, colonelpanik/litevirt#267).
//
// host_membership_split_v1 dual-writes state and isolation: host_membership,
// and hosts.state / hosts.isolation_epoch / hosts.isolation_reason in their
// previous-release shapes. The hosts copy exists for one reader, a host on a
// build that reads only hosts. While it is written, every fence, drain and
// isolation still moves the hosts row's clock, and so can still cost a
// concurrent version or resource report on some replica.
//
// Once host_membership_retire_v1 has durably latched — mandatory,
// ReplicationGated, so no replication recipient still reads only hosts — the
// pure state and isolation writers (UpdateHostState, RecordFenceWithState,
// IsolateHost, ClearHostIsolation) write host_membership alone.
//
// What does NOT change:
//
//   - Readers resolve from a present host_membership row on any node, live or
//     not; a host with no row on a retired node reads as HostStateUnknown,
//     never from the frozen copy (resolve).
//   - The split pass copies nothing once retired, and copied before that at a
//     floor timestamp (membershipCopyTS); an absorb creates a missing row only
//     from a complete write.
//   - The hosts columns are never cleared: hosts.state is NOT NULL, and a clear
//     would be the very hosts write this retires.
//   - Writers whose hosts statement carries other columns keep their shape —
//     InsertHost (the row is created whole), AdmitHost's re-admission (the
//     identity row is rewritten whole) and UpdateHostStartup (the host's own
//     version and resources): the hosts clock moves for those columns anyway,
//     and an unchanged shape needs no ledger entry.
//   - absorbUnlatchedMembershipWrite still runs. The design note says it can
//     go, because the latch proves every recipient runs this build — but a
//     latch is per node and ADVERTISING the token is not having latched
//     host_membership_split_v1. A neighbour on this build whose split latch has
//     not formed yet still writes hosts alone, and a retired node must still
//     take that write into its membership row. Absorbing is harmless otherwise:
//     a retired writer's entries carry their host_membership statement and are
//     skipped.

// SetHostMembershipRetireGate injects the predicate that retires the hosts
// copy. Wired at daemon start to the durable host_membership_retire_v1 marker.
// Nil-safe and FAIL CLOSED: unset, both homes are written.
func (c *Client) SetHostMembershipRetireGate(fn func() bool) {
	if fn == nil {
		c.hostMembershipRetire.Store(nil)
		return
	}
	c.hostMembershipRetire.Store(&fn)
}

// hostsCopyFrozen reports whether this node has latched the retire token,
// live or not: from then on the hosts copy of a host with no membership row
// may have stopped following (resolve), and a pass copies nothing from it.
func (c *Client) hostsCopyFrozen() bool {
	fn := c.hostMembershipRetire.Load()
	return fn != nil && (*fn)()
}

// hostsCopyRetired reports whether a live membership writer skips the hosts
// copy. Callers pass live (withMembershipWrite's argument): a node that is not
// writing host_membership yet always writes hosts.
func (c *Client) hostsCopyRetired(live bool) bool {
	return live && c.hostsCopyFrozen()
}
