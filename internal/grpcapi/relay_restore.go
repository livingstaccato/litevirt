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
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

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
		// No username in the replicated reason, which any viewer can list:
		// the audit row names who.
		Reason: "restored by an operator (lv cluster relay-restore)",
	}
	// The hold first, in its own row: a demotion the lease holder writes in
	// the meantime then meets the hold on its re-read, and an evaluator's row
	// can never overwrite it.
	holds, err := corrosion.ListRelayHolds(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read relay holds: %v", err)
	}
	holdUntil := ""
	if prevHold, ok := holds[host]; hold > 0 || (ok && prevHold.Active(now)) {
		// A zero hold ends any earlier one.
		h := corrosion.RelayHold{Until: now.Add(hold).Format(time.RFC3339), Since: now.Format(time.RFC3339), By: user}
		if err := corrosion.SetRelayHold(ctx, s.db, host, h, user); err != nil {
			return nil, status.Errorf(codes.Internal, "hold relay %s: %v", host, err)
		}
		if hold > 0 {
			holdUntil = h.Until
		}
	}
	if err := corrosion.SetRelayDemotion(ctx, s.db, host, d, user); err != nil {
		return nil, status.Errorf(codes.Internal, "restore relay %s: %v", host, err)
	}
	detail := fmt.Sprintf("relay demotion cleared (was demoted: %v)", hasRow && prev.Demoted)
	if holdUntil != "" {
		detail += "; held until " + holdUntil
	}
	s.audit(ctx, "cluster.relay_restore", host, detail, "ok")
	s.publish("cluster.relay_restore", host, detail)
	return &pb.RestoreRelayResponse{Host: host, WasDemoted: hasRow && prev.Demoted, HoldUntil: holdUntil}, nil
}

// GetRelayHealth lists every host with a relay demotion row or an operator
// hold, as this host's replica holds them: `lv cluster relay-restore` with no
// argument. A restored row with no hold in force is listed too — it says when
// and by whom the last restore was made.
func (s *Server) GetRelayHealth(ctx context.Context, _ *emptypb.Empty) (*pb.RelayHealthStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rows, err := corrosion.ListRelayRows(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read relay demotions: %v", err)
	}
	holds, err := corrosion.ListRelayHolds(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read relay holds: %v", err)
	}
	now := time.Now()
	// Who set a hold is a username: shown to an admin, and to anyone else only
	// as "an operator", with the time.
	isAdmin := RequireRole(ctx, "admin") == nil
	by := map[string]*pb.RelayHealthEntry{}
	for host, d := range rows {
		by[host] = &pb.RelayHealthEntry{Host: host, Demoted: d.Demoted, Since: d.Since, Reason: d.Reason}
	}
	for host, h := range holds {
		if !h.Active(now) {
			continue
		}
		e := by[host]
		if e == nil {
			e = &pb.RelayHealthEntry{Host: host}
			by[host] = e
		}
		e.HoldUntil, e.HoldBy = h.Until, "an operator"
		if isAdmin {
			e.HoldBy = h.By
		}
	}
	out := &pb.RelayHealthStatus{Latched: s.db.MayWriteRelayDemotion()}
	for _, e := range by {
		out.Hosts = append(out.Hosts, e)
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].Host < out.Hosts[j].Host })
	return out, nil
}
