package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Per-schedule replication bandwidth limits (replication_rate): the request
// side. The record is corrosion.SetReplicationRate's; the runs that obey it
// are replication_rate_throttle.go's.
//
// A request's bwlimit is optional: unset keeps the stored limit of a live
// schedule, 0 clears it. A NEW schedule never inherits a limit a deleted one
// of the same name left behind (applyReplicationRate).
// A positive limit is checked against the release gate BEFORE the schedule is
// written (precheckReplicationRate), so a refused limit leaves no unlimited
// schedule behind, and written AFTER it (applyReplicationRate).

// precheckReplicationRate refuses a request's limit that can never be
// stored: below the minimum, or (a positive one) while the release gate
// refuses replication_rate, or while the cluster-policy table the limit is
// stored in is not writable here. It records nothing. A request with no
// limit, or a clear, asks no gate.
func (s *Server) precheckReplicationRate(ctx context.Context, bw *int64) error {
	if bw == nil || *bw == 0 {
		return nil
	}
	if *bw < pbsstore.MinRate {
		return status.Errorf(codes.InvalidArgument,
			"bandwidth limit %d B/s is below the minimum of 64KiB/s (use 0 for no limit)", *bw)
	}
	if err := s.ReleaseFeatureRefusal(ctx, capabilities.FeatureReplicationRate); err != nil {
		return err
	}
	if !s.db.MayWriteClusterPolicy() {
		return status.Errorf(codes.FailedPrecondition, "cannot store a bandwidth limit: %v", corrosion.ErrClusterPolicyGateClosed)
	}
	return nil
}

// scheduleRowLive reports whether the schedule row (schedule, repo) exists
// and is not deleted. A failed read counts as live, so nothing is cleared on
// a guess.
func (s *Server) scheduleRowLive(ctx context.Context, schedule, repo string) bool {
	rows, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return true
	}
	for _, r := range rows {
		if r.VMName == schedule && r.Repo == repo {
			return true
		}
	}
	return false
}

// applyReplicationRate stores the request's limit for the schedule row
// (schedule, repo), which has just been written. A clear is written only over
// a stored limit, so it never performs the feature's first use. On failure the
// schedule stands without a limit, and the error says so.
//
// existed is whether the row was live before this write. A new row given no
// limit drops a limit stored under its name: one a delete could not clear,
// or one that reached this node only after a delete elsewhere had looked for
// it. That clear is best effort and refuses nothing: the answer's limit
// shows one that stayed.
func (s *Server) applyReplicationRate(ctx context.Context, schedule, repo string, bw *int64, existed bool) error {
	if bw == nil {
		if !existed {
			if err := s.clearReplicationRate(ctx, schedule, repo); err != nil {
				slog.Warn("replication schedule: a limit left by a deleted schedule of the same name was not cleared",
					"schedule", schedule, "repo", repo, "error", err)
			}
		}
		return nil
	}
	var err error
	if *bw == 0 {
		err = s.clearReplicationRate(ctx, schedule, repo)
	} else {
		err = s.WithReleaseFeature(ctx, capabilities.FeatureReplicationRate,
			func(ctx context.Context, g capabilities.FeatureGrant) error {
				return corrosion.SetReplicationRate(ctx, s.db, g, schedule, repo, *bw, callerUsername(ctx))
			})
	}
	if err == nil {
		return nil
	}
	code := status.Code(err)
	switch {
	case errors.Is(err, corrosion.ErrClusterPolicyGateClosed):
		code = codes.FailedPrecondition
	case code == codes.Unknown || code == codes.OK:
		code = codes.Internal
	}
	if *bw == 0 {
		return status.Errorf(code, "the schedule was saved, but its bandwidth limit was not cleared: %v; re-run `lv replication schedule add` with --bwlimit 0", err)
	}
	return status.Errorf(code, "the schedule was saved without a bandwidth limit (it replicates unlimited until one is stored): %v; re-run `lv replication schedule add` with --bwlimit", err)
}

// clearReplicationRate empties the schedule row's limit, only when one is
// stored. The feature is then already used, so the gate is never a first use.
func (s *Server) clearReplicationRate(ctx context.Context, schedule, repo string) error {
	has, err := corrosion.HasReplicationRate(ctx, s.db, schedule, repo)
	if err != nil || !has {
		return err
	}
	return s.WithReleaseFeature(ctx, capabilities.FeatureReplicationRate,
		func(ctx context.Context, g capabilities.FeatureGrant) error {
			return corrosion.SetReplicationRate(ctx, s.db, g, schedule, repo, 0, callerUsername(ctx))
		})
}

// deleteScheduleRow deletes the backup_schedules row (schedule, repo), then
// clears its bandwidth limit when one is stored, so a later schedule of the
// same name never inherits it. It is the one caller of
// corrosion.DeleteBackupSchedule (TestReplicationRate_DeleteBackupScheduleHasOneCaller).
func (s *Server) deleteScheduleRow(ctx context.Context, schedule, repo string) error {
	if err := corrosion.DeleteBackupSchedule(ctx, s.db, schedule, repo); err != nil {
		return err
	}
	if err := s.clearReplicationRate(ctx, schedule, repo); err != nil {
		return fmt.Errorf("the schedule was deleted, but its bandwidth limit was not cleared: %w; adding the schedule again clears it (or sets the --bwlimit given)", err)
	}
	return nil
}

// replicationRateOf is the stored limit of the schedule row, 0 when none or
// when it cannot be read (a listing never fails over it).
func (s *Server) replicationRateOf(ctx context.Context, schedule, repo string) int64 {
	bps, _ := corrosion.GetReplicationRate(ctx, s.db, schedule, repo)
	return bps
}
