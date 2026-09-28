package corrosion

import (
	"sync"
	"time"
)

// Observations versus control state in anti-entropy (colonelpanik/litevirt#262 (d)).
//
// An OBSERVATION table holds measurements whose writer re-publishes them on
// its own cadence, where each write wholly supersedes the last and every
// reader that decides anything from a row bounds its age. A missed write is
// repaired by the writer's next one; anti-entropy only has to catch the rows
// whose writer went quiet. CONTROL state is everything else: operator intent,
// ownership, the journal, membership. A missed control write stays missed until
// something repairs it, and decisions read it with no freshness bound.
//
// The observation tables, and why each qualifies:
//
//   - host_health — each observer's verdict on each peer. The highest-rate
//     replicated table: a failing peer's row is rewritten by every observer on
//     every 2 s probe, and a recovery-pending one's every HeartbeatInterval
//     (10 s). The quorums that act on it (failover fence and recovery) count
//     only rows newer than healthFreshness (30 s); QuorumProof does not read it
//     at all. The one row with no refresh — a steadily healthy edge — is read
//     only by the operator's connectivity view and by dual-run last-alive
//     evidence, which tolerates hlc.MaxSkewMS.
//   - health_evaluator_status — the dual-run detector's last-scan stamp,
//     rewritten every scan (60 s); its reader treats a scan older than
//     evaluatorScanTTL (5 min) as stale regardless.
//   - host_capacity_observations — each host's own runtime-capacity sample,
//     rewritten by that host every 60 s, the whole row each time.
//
// Deliberately NOT observations, though they sound like them:
// health_conditions (the ownership admission gate refuses on a durable
// condition row; a lost confirmation must be repaired, not waited out),
// fencing_log and audit_log (append-only evidence, never re-published),
// image_hosts (which host holds an image is placement input with no refresh;
// its progress_pct churns only during a pull).
//
// What changes for them: a scheduled pass that finds only an observation
// table mismatched does not pull it, and one that finds it beside a control
// mismatch pulls the control tables alone — unless observations are due. They
// are due at most once per observationRepairInterval per node, and ALWAYS
// when the local replica is not caught up (a node back from a fence or a
// partition is judged by exactly these rows) or when the pass is the
// operator's full RunOnce. So a deferral only ever happens on a replica that
// is already caught up, and never holds the replica-freshness signal back.
var observationTables = map[string]bool{
	"host_health":                true,
	"health_evaluator_status":    true,
	"host_capacity_observations": true,
}

// defaultObservationRepairInterval bounds how often a scheduled pass repairs
// observation tables: well above their writers' own cadence (<= 60 s), so a
// row that is merely in flight is left to its writer, and well below anything
// that reads a quiet row (evaluatorScanTTL, 5 min, is the tightest).
const defaultObservationRepairInterval = 5 * time.Minute

// observationRepair is this process's record of its last observation repair.
// It lives on the Client, not the AntiEntropy, so it is per-node however many
// passes are built over one replica.
type observationRepair struct {
	mu          sync.Mutex
	at          time.Time // last completed observation repair; zero = never
	interval    time.Duration
	intervalSet bool
}

func (c *Client) observationRepairInterval() time.Duration {
	c.obsRepair.mu.Lock()
	defer c.obsRepair.mu.Unlock()
	if c.obsRepair.intervalSet {
		return c.obsRepair.interval
	}
	return defaultObservationRepairInterval
}

// observationRepairDue reports whether a scheduled pass should repair
// observation tables now.
func (c *Client) observationRepairDue(now time.Time) bool {
	if ok, _ := c.ReplicaCaughtUp(); !ok {
		return true
	}
	interval := c.observationRepairInterval()
	c.obsRepair.mu.Lock()
	defer c.obsRepair.mu.Unlock()
	return c.obsRepair.at.IsZero() || now.Sub(c.obsRepair.at) >= interval
}

// markObservationsRepaired records a completed observation repair.
func (c *Client) markObservationsRepaired(now time.Time) {
	c.obsRepair.mu.Lock()
	c.obsRepair.at = now
	c.obsRepair.mu.Unlock()
}

// SetObservationRepairIntervalForTests overrides the observation-repair
// interval and returns a func restoring the default.
func (c *Client) SetObservationRepairIntervalForTests(d time.Duration) func() {
	c.obsRepair.mu.Lock()
	c.obsRepair.interval, c.obsRepair.intervalSet = d, true
	c.obsRepair.mu.Unlock()
	return func() {
		c.obsRepair.mu.Lock()
		c.obsRepair.intervalSet = false
		c.obsRepair.mu.Unlock()
	}
}

// splitObservations partitions mismatched tables into control state and
// observations, preserving order.
func splitObservations(tables []string) (control, observations []string) {
	for _, t := range tables {
		if observationTables[t] {
			observations = append(observations, t)
		} else {
			control = append(control, t)
		}
	}
	return control, observations
}
