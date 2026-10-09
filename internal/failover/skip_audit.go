package failover

import "context"

// auditSkip writes the failover.skip audit row for a workload recoverWorkloads
// leaves where it is, once per change of state: the first time it is skipped
// on host, and again only when the detail or result changes.
//
// recoverWorkloads runs once per fence, but the removed-host pass
// (recoverRemovedHosts) runs it for every removed host with workloads on EVERY
// tick, and a workload it cannot recover (a vTPM VM, one with no eligible
// host, one in an ownership dispute) wrote the same row every poll for as
// long as it stayed stranded. The audit log is a record of decisions, and this
// one was decided once. The log line, the metric and the health conditions
// still report every pass.
//
// The record is in memory, per coordinator: a restart or a new lease holder
// audits each standing skip once more. Keyed by host as well as workload, so
// a workload recovered elsewhere and stranded again there is audited afresh.
//
// It reports whether it wrote the row, so a caller that also emits an event
// for the skip emits it as rarely.
func (c *Coordinator) auditSkip(ctx context.Context, host, target, detail, result string) bool {
	key := host + "\x00" + target
	state := detail + "\x00" + result
	if c.skipAudited == nil {
		c.skipAudited = map[string]string{}
	}
	if c.skipAudited[key] == state {
		return false
	}
	c.skipAudited[key] = state
	c.audit(ctx, "failover.skip", target, detail, result)
	return true
}
