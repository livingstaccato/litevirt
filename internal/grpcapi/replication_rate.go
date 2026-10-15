package grpcapi

import (
	"context"
	"fmt"

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
// A request's bwlimit is optional: unset keeps the stored limit, 0 clears it.
// A positive limit is checked against the release gate BEFORE the schedule is
// written (precheckReplicationRate), so a refused limit leaves no unlimited
// schedule behind, and written AFTER it (applyReplicationRate).

// precheckReplicationRate refuses a request's limit that can never be
// stored: below the minimum, or (a positive one) while the release gate
// refuses replication_rate. It records nothing. A request with no limit, or
// a clear, asks no gate.
func (s *Server) precheckReplicationRate(ctx context.Context, bw *int64) error {
	if bw == nil || *bw == 0 {
		return nil
	}
	if *bw < pbsstore.MinRate {
		return status.Errorf(codes.InvalidArgument,
			"bandwidth limit %d B/s is below the minimum of 64KiB/s (use 0 for no limit)", *bw)
	}
	return s.ReleaseFeatureRefusal(ctx, capabilities.FeatureReplicationRate)
}

// applyReplicationRate stores the request's limit for the schedule row
// (schedule, repo), which has just been written. A clear is written only over
// a stored limit, so it never performs the feature's first use. On failure the
// schedule stands without a limit, and the error says so.
func (s *Server) applyReplicationRate(ctx context.Context, schedule, repo string, bw *int64) error {
	if bw == nil {
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
	if code == codes.Unknown || code == codes.OK {
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
		return fmt.Errorf("the schedule was deleted, but its bandwidth limit was not cleared (delete it again to retry): %w", err)
	}
	return nil
}

// replicationRateOf is the stored limit of the schedule row, 0 when none or
// when it cannot be read (a listing never fails over it).
func (s *Server) replicationRateOf(ctx context.Context, schedule, repo string) int64 {
	bps, _ := corrosion.GetReplicationRate(ctx, s.db, schedule, repo)
	return bps
}
