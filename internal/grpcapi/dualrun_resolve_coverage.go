package grpcapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hlc"
)

// Per-condition resolution coverage.
//
// Resolution used to demand that the WHOLE scan be complete: every non-witness
// host probed fully. The probe set deliberately includes offline and fenced
// hosts (see dualRunProbeTargets), so one registered-but-dead host kept every
// scan partial and froze every dual-run condition in the cluster — forever,
// and with them admission to every host those conditions named (lab,
// 2026-09-24: a VM created ten days after node-5 was powered off could not
// shed a stale owner-mismatch until node-5 was removed).
//
// What a clean scan must prove is narrower: that the workload is not running
// anywhere it could be running. So each condition asks only about the hosts
// that could hold ITS subject:
//
//   - host-scoped codes (coverage_gap, lww_unresolved on host H) are claims
//     about H's own runtime report. A complete probe of H is the whole proof
//     of absence; other hosts are irrelevant to it.
//
//   - VM-scoped codes (vm_dual_run, runtime_owner_mismatch,
//     owner_epoch_mismatch on VM W) need complete coverage of every probe
//     target EXCEPT an unreachable host that was last known alive before W was
//     created. A host that has not been alive since before W existed cannot
//     be running a copy of W: every way a copy gets onto a host — create,
//     migrate, failover, its own reconciler — needs that host running after W
//     existed.
//
//   - everything else (ct_dual_run, vip_dual_run, unknown codes) keeps the
//     cluster-wide rule. A container name is not cluster-unique and a VIP has
//     no incarnation stamp, so there is no instant before which a dead host
//     provably could not hold one.
//
// The observation side is unchanged: the dead host is still probed every pass,
// still carries its own coverage_gap, and the evaluator status still reports
// the scan as partial. Only what a clean pass may RESOLVE is per-condition.
//
// "Last known alive" is read from replicated host_health rows, and is the
// LATEST of two kinds of evidence (taking the latest only ever shrinks the
// exemption):
//
//   - rows the host wrote itself (observer = H): its health checker re-
//     publishes every peer verdict at least every HeartbeatInterval while it
//     runs, so these stop advancing exactly when H stops running or stops
//     replicating;
//   - rows a peer wrote after H ANSWERED it (target = H, consecutive_failures
//     = 0, or status unready — an unready reply is the host speaking).
//
// updated_at is the LWW key, stamped by the writer and preserved through
// replication; it is RFC3339 or HLC, both read with ParseUpdatedAt. An HLC
// stamp can be pushed FORWARD by a peer's clock but never back, which errs
// toward "alive later" — the safe direction. Clocks are compared across hosts
// (the creator's created_at against H's stamps), so the gap must exceed
// deadHostSkewMargin, the same bound the HLC layer already quarantines skew
// at.
//
// It fails CLOSED — the host blocks resolution — whenever the evidence is
// missing or unreadable: no host_health row about H at all, any unparseable
// stamp that could have been H's latest, a failed host_health read, an
// unparseable or future-dated created_at, a VM missing from the DB index, a
// failed DB index. And some hosts are never exempt whatever the clocks say:
// W's DB owner (the one host placed to run it), any host the condition itself
// records as involved (it was SEEN holding W), and any host that answered this
// pass partially or from an older binary (it is alive now, so its history is
// irrelevant).

// deadHostSkewMargin is how much earlier than a workload's created_at a host's
// last liveness evidence must be before the host counts as dead-before-it.
// It absorbs clock skew between the workload's creator and the dead host (and
// the heartbeat period), and matches hlc.MaxSkewMS — skew beyond it is already
// quarantined cluster-wide as clock corruption.
const deadHostSkewMargin = time.Duration(hlc.MaxSkewMS) * time.Millisecond

// resolutionCoverage is what one pass saw, in the form the per-condition
// resolution decision needs.
type resolutionCoverage struct {
	// complete is the cluster-wide verdict: every probe target answered fully
	// and both DB indexes were readable. It is the scan's reported coverage
	// and, when true, sufficient to resolve anything.
	complete bool
	// dbOK: the VM and container indexes were both readable. A failed index
	// read blinds the ownership checks, so nothing resolves without it.
	dbOK bool
	// probeTargets is the pass's probe set; snaps are the hosts that answered.
	probeTargets map[string]bool
	snaps        map[string]runtimeSnapshot
	unreachable  map[string]bool
	// lastAlive is each unreachable host's latest liveness instant. A host
	// absent from it has no trustworthy evidence and is never exempt.
	lastAlive map[string]time.Time
	vmOwner   map[string]string
	vmCreated map[string]string
	now       time.Time
}

// canResolve reports whether this pass's absence of f proves anything about f.
func (rc resolutionCoverage) canResolve(f finding, row corrosion.HealthCondition) bool {
	if !rc.dbOK {
		return false
	}
	if rc.complete {
		return true
	}
	switch f.kind {
	case kindDualRunCoverage, kindLWWUnresolved:
		// A host outside the probe set (removed, or a witness) has no report
		// to prove anything with; keep the cluster-wide rule for it.
		if !rc.probeTargets[f.target] {
			return false
		}
		return rc.completelyProbed(f.target)
	case kindDualRunVM, kindOwnerMismatch, kindEpochMismatch:
		return rc.vmCoverageComplete(f.target, row.Hosts)
	default:
		return false
	}
}

func (rc resolutionCoverage) completelyProbed(host string) bool {
	snap, ok := rc.snaps[host]
	return ok && !snap.partial
}

// vmCoverageComplete: every probe target is either completely probed or an
// unreachable host provably dead since before vm was created.
func (rc resolutionCoverage) vmCoverageComplete(vm string, involved []string) bool {
	createdRaw, ok := rc.vmCreated[vm]
	if !ok {
		return false // deleted or unknown VM: nothing to date it by
	}
	created, err := time.Parse(time.RFC3339, createdRaw)
	if err != nil || created.After(rc.now.Add(deadHostSkewMargin)) {
		return false // unreadable or post-dated: would exempt hosts it should not
	}
	for h := range rc.probeTargets {
		if rc.completelyProbed(h) {
			continue
		}
		if !rc.unreachable[h] {
			return false // partial or older-binary: alive now, could hold anything
		}
		if h == rc.vmOwner[vm] || containsString(involved, h) {
			return false
		}
		last, ok := rc.lastAlive[h]
		if !ok || !last.Add(deadHostSkewMargin).Before(created) {
			return false
		}
	}
	return true
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// hostLastAlive returns, for each host in hosts, the latest instant the
// replicated host_health rows show it alive (see the file comment for which
// rows count). A host with no evidence, or with any unparseable stamp among
// its evidence rows, is omitted — the caller treats omission as "could be
// alive now". ok=false means the read failed and nothing may be exempted.
func (s *Server) hostLastAlive(ctx context.Context, hosts map[string]bool) (map[string]time.Time, bool) {
	out := map[string]time.Time{}
	if len(hosts) == 0 {
		return out, true
	}
	rows, err := s.db.Query(ctx,
		`SELECT observer, target, status, consecutive_failures, updated_at
		 FROM host_health WHERE deleted_at IS NULL`)
	if err != nil {
		slog.Warn("dual-run detector: read host liveness", "error", err)
		return nil, false
	}
	poisoned := map[string]bool{}
	note := func(host, ts string) {
		if !hosts[host] || poisoned[host] {
			return
		}
		t, ok := corrosion.ParseUpdatedAt(ts)
		if !ok {
			poisoned[host] = true
			delete(out, host)
			return
		}
		if t.After(out[host]) {
			out[host] = t
		}
	}
	for _, r := range rows {
		ts := r.String("updated_at")
		note(r.String("observer"), ts)
		if r.Int("consecutive_failures") == 0 || r.String("status") == health.StatusUnready {
			note(r.String("target"), ts)
		}
	}
	return out, true
}
