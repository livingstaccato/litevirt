package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// fenceConfirmLivenessWindow is how recent an observer's verdict that a host
// answered must be to refuse `lv host fence-confirm` of it. It matches the
// failover coordinator's healthFreshness: a healthy verdict is re-stamped every
// health.HeartbeatInterval, so a host that is up always has one this fresh
// (TestFenceConfirmLivenessWindowCoversTheHeartbeat).
const fenceConfirmLivenessWindow = 30 * time.Second

// hostAnswering reports why host is evidently up, or "" when nothing says so.
// It reads the evidence the failover coordinator reads before it resumes a
// recovery from a fence (failover answeredSince): an observer other than host
// whose latest host_health verdict, healthy or unready, is fresh. It also
// counts this node reaching host now. An unreadable host_health is an error.
func (s *Server) hostAnswering(ctx context.Context, host string) (string, error) {
	if host == s.hostName {
		return host + " is the node serving this request", nil
	}
	rows, err := s.db.Query(ctx,
		`SELECT observer, status, consecutive_failures, updated_at FROM host_health
		 WHERE target = ? AND deleted_at IS NULL`, host)
	if err != nil {
		return "", err
	}
	cutoff := time.Now().Add(-fenceConfirmLivenessWindow)
	var obs []string
	for _, r := range rows {
		o := r.String("observer")
		if o == host {
			continue
		}
		if r.Int("consecutive_failures") != 0 && r.String("status") != health.StatusUnready {
			continue
		}
		if upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at")); ok && upd.After(cutoff) {
			obs = append(obs, o)
		}
	}
	if len(obs) > 0 {
		sort.Strings(obs)
		return fmt.Sprintf("observer(s) %s saw it answer health probes within the last %v",
			strings.Join(obs, ","), fenceConfirmLivenessWindow), nil
	}
	if s.gateV() != nil && s.peerUp(ctx, host) {
		return s.hostName + " reaches it now", nil
	}
	return "", nil
}

// refuseFenceConfirmOfLiveHost is the precondition of a manual fence
// confirmation: the host must not be answering. Recording a live host as
// powered off lets the failover coordinator recover its workloads while they
// still run there.
func (s *Server) refuseFenceConfirmOfLiveHost(ctx context.Context, host string) error {
	why, err := s.hostAnswering(ctx, host)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot read host_health to show %s is down, so its power-off is not recorded: %v", host, err)
	}
	if why == "" {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"host %s is up (%s); fence-confirm records that it is powered off. Power it off first, "+
			"then run `lv host fence-confirm %s` again once it no longer answers", host, why, host)
}
