package corrosion

import (
	"context"
	"sort"
)

// WorkloadsOnRemovedHost lists the live VM and container rows still recorded
// on host while host has no live hosts row: what the machine removed under the
// name left behind, as "vm/<name>" and "ct/<name>", sorted. Empty when host is
// live (they are its own) or nothing is recorded on it.
//
// A name with such rows must not be admitted again (grpcapi.AdmitHost). They
// belong to the machine that was removed. Its workloads are recovered by the
// claim path for a host removed for good, which runs only while the name has
// no live row: the coordinator's removed-host pass selects names without one,
// and every voter refuses the supersede for a host that has one
// (RemovedHostEvidence). Admitting the name ended both, and handed the rows to
// the new machine, whose reconciler started a VM it had never run, on a fresh
// overlay, with no claim and no proof (kvm003 drill 6, main-b3368d7c).
func WorkloadsOnRemovedHost(ctx context.Context, c *Client, host string) ([]string, error) {
	live, err := c.Query(ctx, `SELECT 1 FROM hosts WHERE name = ? AND deleted_at IS NULL`, host)
	if err != nil {
		return nil, err
	}
	if len(live) > 0 {
		return nil, nil
	}
	rows, err := c.Query(ctx, `SELECT 'vm/' || name AS w FROM vms WHERE host_name = ? AND deleted_at IS NULL
		UNION SELECT 'ct/' || name AS w FROM containers WHERE host_name = ? AND deleted_at IS NULL`, host, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("w"))
	}
	sort.Strings(out)
	return out, nil
}

// WorkloadsBlockingReadmission is WorkloadsOnRemovedHost without the stopped
// workloads: the ones a name's machine may take back when it is added again.
//
// A stopped workload is one failover leaves where it is — never started
// elsewhere, never rebuilt — so its data is on the removed machine, and it
// comes back with that machine (docs/migration-failover.md, "Stopped
// workloads"). The machine's reconciler never starts a stopped row, and a
// start an operator then asks for on a machine that does not have the disk
// is refused as vm_disk_missing rather than rebuilt blank. Every other row
// still blocks the name: it is the claim path's to recover, and a new machine
// would start it (kvm003 drill 6). A container failover marked
// relocate-skipped was running when its host died, so it still blocks.
func WorkloadsBlockingReadmission(ctx context.Context, c *Client, host string) ([]string, error) {
	live, err := c.Query(ctx, `SELECT 1 FROM hosts WHERE name = ? AND deleted_at IS NULL`, host)
	if err != nil {
		return nil, err
	}
	if len(live) > 0 {
		return nil, nil
	}
	rows, err := c.Query(ctx, `SELECT 'vm/' || name AS w FROM vms
		  WHERE host_name = ? AND deleted_at IS NULL AND state <> 'stopped'
		UNION SELECT 'ct/' || name AS w FROM containers
		  WHERE host_name = ? AND deleted_at IS NULL
		    AND NOT (state = 'stopped' AND COALESCE(state_detail, '') <> ?)`,
		host, host, ContainerRelocateSkippedDetail)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("w"))
	}
	sort.Strings(out)
	return out, nil
}

// HostRemoved reports whether host has been removed from the cluster: this
// replica holds its removed hosts row and no live one. A name it has no row
// for at all is not removed, only unknown (a host whose row has not arrived
// yet reads the same).
func HostRemoved(ctx context.Context, c *Client, host string) (bool, error) {
	rows, err := c.Query(ctx, `SELECT COALESCE(deleted_at, '') AS deleted_at FROM hosts WHERE name = ?`, host)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	for _, r := range rows {
		if r.String("deleted_at") == "" {
			return false, nil
		}
	}
	return true, nil
}
