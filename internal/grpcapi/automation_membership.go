package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Automation and voter membership (F1 Task 5).
//
// The adoption order a voter follows is fixed: authenticated scope → adopted
// voter generation → readiness proof → conditional command → certified apply
// → execution eligibility. Membership is the second step, and no forced
// membership branch bypasses the third:
//
//   - an ordinary certified change carries this voter's automation authority
//     across, in the adoption transaction that imports the sealed old
//     majority's claim state (importFromSealedMajority →
//     corrosion.ImportClaimsAndAdoptAutomation);
//   - a forced generation adopts through the non-carrying import, and both
//     forcing it and signing it are refused while automation history exists
//     (refuseWithoutAutomationRecoveryProof);
//   - a reset is refused while automation history exists;
//   - a voter new to the electorate adopts the generation but holds no
//     authority, so it refuses every automation vote and reports
//     automation_import_absent until a complete prefix import exists for it.

// SetAutomationEnforce sets enforcement.automation: whether this node
// advertises automation_v1. It is not activation (the daemon's gate).
func (s *Server) SetAutomationEnforce(on bool) { s.enfAutomation.Store(on) }

// AutomationMembershipStatus is this voter's membership readiness for
// automation, the gate's membership component.
type AutomationMembershipStatus struct {
	Generation int64
	Voters     int
	// Imported: this voter holds automation authority at Generation.
	Imported bool
	// Durable: this voter commits promises durably and can sign
	// (VoterConfigReadiness).
	Durable bool
	// Code names the first unmet condition; "" when Imported and Durable.
	Code, Detail string
}

// AutomationMembershipStatus reads this voter's automation membership
// standing. Local reads only.
func (s *Server) AutomationMembershipStatus(ctx context.Context) AutomationMembershipStatus {
	var out AutomationMembershipStatus
	if s.db == nil {
		out.Code, out.Detail = "membership_unreadable", "no database"
		return out
	}
	st, err := s.db.AutomationMembershipStanding(ctx)
	if err != nil {
		out.Code, out.Detail = "membership_unreadable", err.Error()
		return out
	}
	out.Generation, out.Voters, out.Imported = st.Generation, st.Voters, st.Imported
	out.Durable, out.Detail = s.VoterConfigReadiness(ctx)
	switch {
	case !st.Imported:
		out.Code, out.Detail = "automation_import_absent", st.Detail
	case !out.Durable:
		out.Code = "voter_not_durable"
	default:
		out.Detail = ""
	}
	return out
}

// refuseWithoutAutomationRecoveryProof refuses a membership change that does
// not import from the old majority (forced, reset) while this node holds any
// automation state. Such a change cannot show that every chosen automation
// command survives it, and this build has no other recovery proof for
// automation, so the refusal is unconditional while the state exists.
// Unreadable state refuses too: it is not evidence of non-use.
func (s *Server) refuseWithoutAutomationRecoveryProof(ctx context.Context, change string) error {
	used, detail, err := s.db.AutomationUsed(ctx)
	if err != nil {
		return status.Errorf(codes.Unavailable, "%s refused: cannot tell whether %s holds automation state: %v",
			change, s.hostName, err)
	}
	if used {
		return status.Errorf(codes.FailedPrecondition,
			"%s refused: %s holds %s, and a %s imports nothing from the old voter majority, so nothing proves every "+
				"chosen automation command survives it; this build has no automation recovery proof for it",
			change, s.hostName, detail, change)
	}
	return nil
}

// importAutomationFromSealedMajority is the ordinary adoption's import: the
// claim merge plus the automation authority carry, in one transaction.
func (s *Server) importAutomationFromSealedMajority(ctx context.Context, newGen int64, from []string, states []corrosion.ClaimVoterState) (int, error) {
	n, err := s.db.ImportClaimsAndAdoptAutomation(ctx, newGen, from, states)
	// TODO(automation): this adoption is an automation authority writer. When
	// the native create producer lands (takeover/native-create-producer), call
	// WakeAutomationCreateContinuation here after a successful carry: its drain
	// backs off to 30s while authority is unavailable.
	return n, err
}

// SeedAutomationOriginLoop records the cluster's automation origin from the
// founder's genesis decision file (daemon seedAdminUser) once cluster_policies
// can be written, then removes the file. A node without the file — every node
// but a founder on its first start — returns at once.
func (s *Server) SeedAutomationOriginLoop(ctx context.Context, every time.Duration, decisionPath string) {
	b, err := os.ReadFile(decisionPath)
	if err != nil {
		return
	}
	founder := strings.TrimSpace(string(b))
	if founder == "" {
		founder = s.hostName
	}
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	warned := false
	for {
		// The file is removed only once a readable record exists: a failed
		// read is retried, never taken as done, since the founding moment
		// cannot be recreated. A record that exists but does not decode is
		// never overwritten either; the gate reports it as unreadable.
		_, have, err := corrosion.GetAutomationOrigin(ctx, s.db)
		switch {
		case have:
			_ = os.Remove(decisionPath)
			return
		case err != nil:
			if !warned {
				slog.Warn("automation: cannot read the cluster's automation origin record; retrying", "error", err)
				warned = true
			}
		default:
			wrote, err := corrosion.SeedAutomationOrigin(ctx, s.db, founder)
			if err != nil {
				slog.Warn("automation: could not record the cluster's automation origin", "error", err)
			} else if wrote {
				slog.Info("automation: recorded the cluster's automation origin (founded on this build)", "founder", founder)
				_ = os.Remove(decisionPath)
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
