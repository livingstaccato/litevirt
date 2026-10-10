package grpcapi

// RestoreRelay: `lv cluster relay-restore <host>` (colonelpanik/litevirt#175).
//
// relay_health_v1 is mandatory and has no flag, because a flag would let one
// node elect a different relay set from its peers. This is its stand-down: an
// operator who sees a host demoted for a fault that is not its own — a bad
// observer, a monitoring network problem — clears the demotion at once, for
// the whole cluster, through the same replicated row, and with a hold keeps
// the failover lease holder from demoting it again while the cause is fixed.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// maxRelayHold bounds a restore's hold. A hold is meant to outlast an
// incident, not to switch the feature off for one host forever.
const maxRelayHold = 7 * 24 * time.Hour

// RestoreRelay clears host's relay demotion now and, with a hold, keeps the
// lease holder from demoting it again until the hold runs out. Admin only,
// audited, refused until relay_health_v1 has latched (before which nothing
// is ever demoted).
func (s *Server) RestoreRelay(ctx context.Context, req *pb.RestoreRelayRequest) (*pb.RestoreRelayResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	host := strings.TrimSpace(req.GetHost())
	if host == "" {
		return nil, status.Error(codes.InvalidArgument, "host is required")
	}
	hold := time.Duration(req.GetHoldSeconds()) * time.Second
	if hold < 0 || hold > maxRelayHold {
		return nil, status.Errorf(codes.InvalidArgument, "hold must be between 0 and %s", maxRelayHold)
	}
	if !s.db.MayWriteRelayDemotion() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"relay demotions are not in use until %s has latched on every host, so there is nothing to restore",
			capabilities.RelayHealthV1)
	}
	rows, err := corrosion.ListRelayRows(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read relay demotions: %v", err)
	}
	prev, hasRow := rows[host]
	if h, err := corrosion.GetHost(ctx, s.db, host); err != nil {
		return nil, status.Errorf(codes.Internal, "read host %s: %v", host, err)
	} else if h == nil && !hasRow {
		return nil, status.Errorf(codes.NotFound, "no host %q", host)
	}

	now := time.Now().UTC()
	user := callerUsername(ctx)
	d := corrosion.RelayDemotion{
		Demoted: false,
		Since:   now.Format(time.RFC3339),
		Reason:  "restored by " + user + " (lv cluster relay-restore)",
	}
	if hold > 0 {
		d.HoldUntil = now.Add(hold).Format(time.RFC3339)
	}
	if err := corrosion.SetRelayDemotion(ctx, s.db, host, d, user); err != nil {
		return nil, status.Errorf(codes.Internal, "restore relay %s: %v", host, err)
	}
	detail := fmt.Sprintf("relay demotion cleared (was demoted: %v)", hasRow && prev.Demoted)
	if d.HoldUntil != "" {
		detail += "; held until " + d.HoldUntil
	}
	s.audit(ctx, "cluster.relay_restore", host, detail, "ok")
	s.publish("cluster.relay_restore", host, detail)
	return &pb.RestoreRelayResponse{Host: host, WasDemoted: hasRow && prev.Demoted, HoldUntil: d.HoldUntil}, nil
}
