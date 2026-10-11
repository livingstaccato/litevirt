package corrosion

// Retiring the hosts copy of a host's runtime reports (host_runtime_retire_v1,
// colonelpanik/litevirt#267).
//
// host_runtime_split_v1 dual-writes every runtime report: host_runtime, and
// hosts.version / schema_version / cpu_total / mem_total / disk_total in their
// previous-release shapes. That keeps the report itself from being lost — a
// replica that refuses the hosts half still applies the host_runtime half —
// but the hosts half still moves the hosts row's clock. So a host's boot
// report, newer than an operator's concurrent region or role change, is still
// what makes a replica refuse that change as older. That replica holds the
// old configuration under the report's newer clock, a replica that applied
// both holds the new one under the same clock, and nothing — neither LWW nor
// the hosts tie rule, which settles a benign column by content — knows which
// configuration is the newer. The dual write moved the loss from the report
// to the configuration.
//
// Once host_runtime_retire_v1 has durably latched — mandatory,
// ReplicationGated, and advertised by a node only once it is live on the
// split (grpcapi's advertisement filter, HostRuntimeLive), so it cannot latch
// anywhere before every replication recipient writes and reads host_runtime —
// the pure runtime writers write host_runtime alone:
//
//   - UpdateHostVersion and UpdateHostResources: no hosts statement at all;
//   - the boot report (UpdateHostStartup): no hosts statement once
//     host_membership_retire_v1 has stopped it carrying the boot state too,
//     and only the state (updateHostStateSQL, an existing shape) until then.
//
// The hosts row is then written by the operator and by identity changes
// (address, certificate, admission), one writer class: an operator's change
// and a host's report no longer share a clock anywhere.
//
// What does NOT change:
//
//   - Readers take a live host_runtime row on any node, and fall back to the
//     hosts columns only for a host with none. Every host has one on a node
//     that is live (the pass copies it), a host added later gets one in
//     InsertHost's batch, and a re-admitted host reads its reset hosts columns
//     until the new machine's first report brings its row back whole.
//   - The hosts columns are never cleared, and InsertHost and a re-admission
//     keep their shapes: they write the whole row anyway.
//   - absorbUnlatchedRuntimeWrite still runs. Under the advertisement rule no
//     recipient can still be writing hosts alone, but absorbing is harmless:
//     a live writer's entries carry host_runtime and are skipped.

// SetHostRuntimeRetireGate injects the predicate that retires the hosts copy
// of the runtime columns. Wired at daemon start to the durable
// host_runtime_retire_v1 marker. Nil-safe and FAIL CLOSED: unset, both homes
// are written, the dual-write build's behaviour.
func (c *Client) SetHostRuntimeRetireGate(fn func() bool) {
	if fn == nil {
		c.hostRuntimeRetire.Store(nil)
		return
	}
	c.hostRuntimeRetire.Store(&fn)
}

// runtimeCopyFrozen reports whether this node has latched the retire token.
func (c *Client) runtimeCopyFrozen() bool {
	fn := c.hostRuntimeRetire.Load()
	return fn != nil && (*fn)()
}

// hostsRuntimeRetired reports whether a live runtime writer skips the hosts
// copy. Callers pass live (withRuntimeWrite's argument): a node that is not
// writing host_runtime yet always writes hosts.
func (c *Client) hostsRuntimeRetired(live bool) bool {
	return live && c.runtimeCopyFrozen()
}
