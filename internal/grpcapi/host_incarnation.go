package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/health"
)

// The host incarnation counter's operator side (corrosion/host_incarnation.go).
//
// A hosts write from a node that lags a re-admission carries the key of the
// row it holds, and every caught-up node refuses it as an earlier
// incarnation. Refused downstream, an operator's write would be lost silently,
// so the operator's hosts writes are refused HERE instead, on a node that is
// not caught up: `lv host rm`, `lv host config`, labels, drain and undrain,
// and isolation. FenceHost is exempt — a fence is incident tooling, and a
// lagging fence's writes are refused by the counter wherever they would
// overwrite a later incarnation.
//
// `lv host add` and `lv host rm` decide an incarnation, so they also pull the
// hosts table from a peer first, and need a live voter majority: only one side
// of a partition can re-add or remove a host.

// SetHostWriteCurrencyCheck turns on the caught-up check for the operator's
// hosts writes. The daemon turns it on; a server without it (a test, a tool)
// is not checked.
func (s *Server) SetHostWriteCurrencyCheck(on bool) { s.hostWriteCurrency.Store(on) }

// hostPullTimeout bounds the currency pull. A var so tests can shorten it.
var hostPullTimeout = 10 * time.Second

// hostTablePuller is the corrosion.AntiEntropy method the currency pull uses.
type hostTablePuller interface {
	PullTableNow(ctx context.Context, table, exclude string) (string, []string, error)
}

// quorumExcluder is the health.Checker method the voter-majority check uses.
type quorumExcluder interface {
	QuorumProofExcluding(ctx context.Context, exclude string) (health.QuorumState, int, int)
}

// hostOperatorWriteAllowed refuses an operator's write to name's hosts row on
// a node whose replica has not caught up since it started (the check
// AdmitHost's audit position already takes), and on name's own node while its
// own-row hold is engaged.
func (s *Server) hostOperatorWriteAllowed(ctx context.Context, action, name string) error {
	if err := s.db.OwnRowWritable(name); err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"%s cannot %s %s: %v. Run it against another node", s.hostName, action, name, err)
	}
	if !s.hostWriteCurrency.Load() {
		return nil
	}
	if ok, why := s.db.ReplicaCaughtUp(); !ok {
		alone, err := s.clusterOfOne(ctx)
		if err != nil {
			return status.Errorf(codes.Unavailable, "read this node's peers: %v", err)
		}
		if !alone {
			return status.Errorf(codes.Unavailable,
				"%s has not caught up with the cluster since it started (%s), so its write to %s could be refused "+
					"by every node that has. Run it against another node (`lv health` shows which have caught up), "+
					"or retry shortly", s.hostName, why, name)
		}
	}
	return nil
}

// requireVoterMajority refuses a decision about name's incarnation unless
// this node sees a live voter majority, counted over the voter set without
// name itself: a host being removed does not vote on its own removal, so a
// two-node cluster can still remove its dead peer. A cluster of one is its
// own majority. A server without a gate (a test, a tool) is not checked.
func (s *Server) requireVoterMajority(ctx context.Context, action, name string) error {
	gate := s.gateV()
	if gate == nil {
		return nil
	}
	var st health.QuorumState
	var live, needed int
	if q, ok := gate.(quorumExcluder); ok {
		st, live, needed = q.QuorumProofExcluding(ctx, name)
	} else {
		st, live, needed = gate.QuorumProof(ctx)
	}
	if st == health.QuorumYes {
		return nil
	}
	if alone, err := s.clusterOfOne(ctx); err == nil && alone {
		return nil
	}
	if st == health.QuorumUnknown {
		return status.Errorf(codes.Unavailable,
			"%s cannot %s %s yet: it has not finished counting the voters since it started; retry shortly",
			s.hostName, action, name)
	}
	return status.Errorf(codes.Unavailable,
		"%s cannot %s %s: that needs a live voter majority, and this node counts %d of the %d voters it needs. "+
			"Run it against a node in the majority (`lv health` shows the quorum on each node)",
		s.hostName, action, name, live, needed)
}

// pullHostsNow pulls the hosts table from a peer — a voter first, never name
// itself — before name's incarnation is read. A failed or timed-out pull
// refuses: the decision is never made on the unpulled row. When no peer can
// confirm (this node is alone with name, or the others are isolated), it
// proceeds and logs it: the voter-majority gate has decided whether this node
// may act. A server without anti-entropy wired (a test, a tool) skips it.
func (s *Server) pullHostsNow(ctx context.Context, action, name string) error {
	p, ok := s.antiEntropy.(hostTablePuller)
	if !ok || p == nil {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, hostPullTimeout)
	defer cancel()
	peer, skipped, err := p.PullTableNow(pctx, "hosts", name)
	if err != nil {
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return status.FromContextError(ctx.Err()).Err()
		}
		msg := fmt.Sprintf("%s could not confirm %s's row with a peer before it would %s it (%v)", s.hostName, name, action, err)
		if len(skipped) > 0 {
			msg += "; not asked: " + strings.Join(skipped, ", ")
		}
		return status.Error(codes.Unavailable, msg+"; retry, or run it against another node")
	}
	if peer == "" {
		slog.Info("no peer to confirm a host's row with before deciding its incarnation; proceeding on this replica",
			"host", name, "action", action, "not_asked", skipped)
	}
	return nil
}
