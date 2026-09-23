package corrosion

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// Gossip isolation as a durable health finding.
//
// A node that has lost every gossip peer and cannot re-join logged "joined 0
// of N" and nothing else. A log line is a finding only for someone already
// reading that node's journal, and the isolated node is exactly the one nobody
// is looking at: its peers see it as a suspect host, which reads as "that
// machine is down", not "that machine is up, alone, and still running its
// workloads". This makes it a health_conditions row, so `lv health` says so.
//
// WHO WRITES: each node, about ITSELF only. The subject is the host, keyed by
// this node's own name, so every row has exactly one writer and the LWW merge
// never has two nodes arguing over one row — the same rule
// netbox_cluster_name_mismatch follows. It is not a leader-written finding,
// because a leader cannot observe another node's gossip view, and an isolated
// node by definition cannot reach the leader.
//
// WHEN IT IS SEEN: immediately on the isolated node itself (`lv health` run
// there reads its local store). Its peers see the row once replication is back
// — resolved by then, but carrying first_seen and resolved_at, which is the
// episode's duration on the record.
const (
	gossipEvaluator    = "gossip"
	condGossipIsolated = "gossip_isolated"
)

// isolationReporter keeps this node's gossip_isolated condition current across
// the re-join loop's passes.
type isolationReporter struct {
	c    *Client
	host string
	now  func() time.Time

	// loaded is set once the store has been read for a row an earlier PROCESS
	// left open. The daemon restart that has always been the cure for this
	// wedge would otherwise leave a confirmed isolation on record forever,
	// because the new process has no memory of having reported it.
	loaded bool
	// open is the current unresolved row, nil when there is none.
	open *HealthCondition
}

type isolationEvidence struct {
	Detail string   `json:"detail"`
	Error  string   `json:"error,omitempty"`
	Hosts  []string `json:"hosts,omitempty"`
}

func (r *isolationReporter) load(ctx context.Context) {
	if r.loaded {
		return
	}
	row, ok, err := GetHealthCondition(ctx, r.c, gossipEvaluator, condGossipIsolated, "host", r.host)
	if err != nil {
		// Retried next pass. Not a reason to skip reporting this one.
		slog.Warn("gossip: could not read the isolation condition", "error", err)
		return
	}
	r.loaded = true
	if ok && row.Lifecycle != ConditionResolved {
		r.open = &row
	}
}

// report records one re-join pass's verdict.
//
// Isolated: observed on the first pass, confirmed on the second, as every other
// evaluator does — one pass could be a restart racing its own seeds.
//
// Not isolated: resolves on the FIRST pass, with no run of clean passes. Most
// evaluators need several because a clean scan is only an absence of evidence;
// visible peers are positive evidence of membership.
//
// A node that was never isolated writes nothing, so a healthy fleet adds no
// replication traffic for a finding that is not there.
func (r *isolationReporter) report(ctx context.Context, isolated bool, lastErr error) {
	r.load(ctx)
	now := r.now().UTC().Format(time.RFC3339)

	if !isolated {
		if r.open == nil {
			return
		}
		row := *r.open
		row.Lifecycle = ConditionResolved
		row.ResolvedAt = now
		row.LastSeen = now
		row.ObserveCount = 0
		row.CleanCount = 1
		row.Reporter = r.host
		if err := UpsertHealthCondition(ctx, r.c, row); err != nil {
			slog.Error("gossip: could not resolve the isolation condition", "error", err)
			return // stays open in memory, so the next pass retries
		}
		slog.Info("gossip: isolation condition resolved", "host", r.host)
		r.open = nil
		return
	}

	var row HealthCondition
	if r.open == nil {
		row = HealthCondition{
			Evaluator: gossipEvaluator, Code: condGossipIsolated,
			SubjectKind: "host", SubjectID: r.host,
			Lifecycle: ConditionObserved, ObserveCount: 1, FirstSeen: now,
		}
	} else {
		row = *r.open
		row.ObserveCount++
		row.CleanCount = 0
		if row.Lifecycle != ConditionConfirmed && row.ObserveCount >= 2 {
			row.Lifecycle = ConditionConfirmed
			row.ConfirmedAt = now
		}
	}
	// Warning, not critical: in this tree critical is reserved for a workload
	// running in two places. An isolated node is how that can START — its peers
	// may fence it and restart its VMs — which is why it has to be visible, but
	// the finding itself is the precondition, not the corruption.
	row.Severity = SeverityWarning
	ev := isolationEvidence{
		Detail: "this node sees no gossip peers and could not re-join any seed or admitted host",
		Hosts:  []string{r.host},
	}
	if lastErr != nil {
		ev.Error = lastErr.Error()
	}
	if b, err := json.Marshal(ev); err == nil {
		row.Evidence = string(b)
	}
	row.LastSeen = now
	row.ResolvedAt = ""
	row.Reporter = r.host
	if err := UpsertHealthCondition(ctx, r.c, row); err != nil {
		slog.Error("gossip: could not record the isolation condition", "error", err)
		return
	}
	if row.Lifecycle == ConditionConfirmed && row.ObserveCount == 2 {
		slog.Warn("gossip: isolation condition confirmed", "host", r.host)
	}
	r.open = &row
}
