package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// moveOutQuarantineRefusal refuses a move of a workload (what, e.g. "VM
// \"web\"") off this host to target while this host's replicated writes are
// refused (a rollback's WAL quarantine, release probation). A move's
// ownership commit is a write this host makes, after a cut-over that cannot
// be undone: refused, the workload would run on the target while every row
// names this host, and failover of this host would start a second copy.
// Called before the move does anything anywhere.
func (s *Server) moveOutQuarantineRefusal(what, target string) error {
	if s.sourceMoveGuardOffForTest.Load() {
		return nil
	}
	reason := s.stopQuarantineReason()
	if reason == "" {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s cannot move %s to %s: it is under write quarantine (%s), so the move's ownership commit cannot be recorded; %s, then retry",
		s.hostName, what, target, reason, s.quarantineRemedy())
}

// SetSourceMoveGuardOffForTest turns off this host's own refusal of a move
// out under write quarantine (moveOutQuarantineRefusal), as a build from
// before it behaves: a scenario's rolled-back source.
func (s *Server) SetSourceMoveGuardOffForTest(off bool) { s.sourceMoveGuardOffForTest.Store(off) }

// incomingMoveMethods are the ReserveHostCapacity methods that move a
// workload IN from the calling host, whose ownership commit that host makes.
var incomingMoveMethods = map[string]bool{"MigrateVM": true, "DrainHost": true, "MigrateContainer": true}

// incomingMoveSourceTimeout bounds the destination's Ping of a move's source.
const incomingMoveSourceTimeout = 5 * time.Second

// incomingMoveSourceRefusal is the destination's half of the refusal: a move
// IN from source, a host whose replicated writes are refused, is refused at
// its first contact (ReserveHostCapacity), so a source on a build without
// moveOutQuarantineRefusal (a rollback to an older binary) still cannot move
// a workload here and leave its row naming itself. The source answers for
// itself over Ping (wal_quarantined, release_probation). It fails CLOSED: a
// source that cannot be asked is refused, retryably.
func (s *Server) incomingMoveSourceRefusal(ctx context.Context, method, source string) error {
	if !incomingMoveMethods[method] || source == "" || source == s.hostName {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, incomingMoveSourceTimeout)
	defer cancel()
	c, closeConn, err := s.dialPeer(pctx, source)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"%s refuses the move from %s for now: it could not ask %s whether it can record the move's ownership commit (dial: %v); retry",
			s.hostName, source, source, err)
	}
	defer closeConn()
	resp, err := c.Ping(pctx, &pb.PingRequest{})
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"%s refuses the move from %s for now: it could not ask %s whether it can record the move's ownership commit (ping: %v); retry",
			s.hostName, source, source, err)
	}
	s.notePeerWALQuarantined(source, resp.GetWalQuarantined())
	state := ""
	switch {
	case resp.GetWalQuarantined():
		state = "WAL quarantine"
	case resp.GetReleaseProbation():
		state = "release probation"
	default:
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s refuses the move from %s: %s is in %s, so it cannot record the move's ownership commit; "+
			"upgrade %s's binary again or reseed it (docs/upgrades.md), or wait for its probation to lift, then retry",
		s.hostName, source, source, state, source)
}
