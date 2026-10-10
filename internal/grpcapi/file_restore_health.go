package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The reduced-barrier config of file restore as a durable health finding.
//
// file_restore.allow_unsandboxed and file_restore.allow_shared_run_as each
// let restore VMs run without one of their barriers. They are off by default
// and named dangerous, but a host that has one set looks like any other until
// someone reads its config. So while one is set the host keeps an
// informational file_restore_unsandboxed condition about itself; the
// daemon reconciles it at start, and it resolves once the keys are gone (or
// file restore is turned off). Every restore VM started that way is also
// audited (backup.file_restore_unsandboxed).
//
// WHO WRITES: each node, about itself only — one writer per row.
const (
	fileRestoreEvaluator = "file_restore"
	// CondFileRestoreUnsandboxed is the condition code for a host whose
	// config lets restore VMs run without one of their barriers.
	CondFileRestoreUnsandboxed = "file_restore_unsandboxed"
)

type fileRestoreUnsandboxedEvidence struct {
	Detail string   `json:"detail"`
	Keys   []string `json:"keys"`
}

// ReconcileFileRestoreCondition raises file_restore_unsandboxed about this
// host while keys (the reduced-barrier keys set, see
// daemon.FileRestoreConfig.ReducedBarrierKeys) is non-empty, and resolves it
// when it is empty. It writes only on a change.
func (s *Server) ReconcileFileRestoreCondition(ctx context.Context, keys []string) {
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, fileRestoreEvaluator, CondFileRestoreUnsandboxed, "host", s.hostName)
	if err != nil {
		slog.Warn("file restore: could not read the file_restore_unsandboxed condition", "error", err)
		return
	}
	open := ok && row.Lifecycle != corrosion.ConditionResolved
	now := time.Now().UTC().Format(time.RFC3339)
	if len(keys) == 0 {
		if !open {
			return
		}
		row.Lifecycle = corrosion.ConditionResolved
		row.ResolvedAt, row.LastSeen = now, now
		row.ObserveCount, row.CleanCount = 0, 1
		row.Reporter = s.hostName
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Error("file restore: could not resolve the file_restore_unsandboxed condition", "error", err)
		}
		return
	}
	b, err := json.Marshal(fileRestoreUnsandboxedEvidence{
		Detail: "this host's file_restore config lets restore VMs run without one of their barriers " +
			"(each such VM is audited as backup.file_restore_unsandboxed); remove the keys to resolve",
		Keys: keys,
	})
	if err != nil {
		return
	}
	if open && row.Evidence == string(b) {
		return
	}
	if !open {
		row = corrosion.HealthCondition{
			Evaluator: fileRestoreEvaluator, Code: CondFileRestoreUnsandboxed,
			SubjectKind: "host", SubjectID: s.hostName, FirstSeen: now,
		}
	}
	row.Lifecycle = corrosion.ConditionConfirmed
	if row.ConfirmedAt == "" {
		row.ConfirmedAt = now
	}
	row.Severity = corrosion.SeverityInfo
	row.Hosts = []string{s.hostName}
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen = now
	row.ResolvedAt = ""
	row.Reporter = s.hostName
	row.Evidence = string(b)
	slog.Warn("file restore: restore VMs may run without one of their barriers on this host", "keys", keys)
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Error("file restore: could not record the file_restore_unsandboxed condition", "error", err)
	}
}
