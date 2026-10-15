package grpcapi

import (
	"context"
	"log/slog"
	"sync"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// replicationRateThrottles holds one shared throttle per replication schedule
// with a bandwidth limit, keyed by the schedule row (vm_name and repo), so
// every run of the schedule on this host — a fan-out's VMs, two runs at once —
// moves at the limit in total.
type replicationRateThrottles struct {
	mu sync.Mutex
	m  map[string]*pbsstore.Throttle
	// wrap, set by tests only, wraps the limiter each run is handed.
	wrap func(key string, t *pbsstore.Throttle) pbsstore.RateLimiter
}

// throttle returns key's shared throttle at bps: the one held when its rate
// is still bps, else a new one in its place. bps <= 0 drops it and returns
// nil (no limit).
func (r *replicationRateThrottles) throttle(key string, bps int64) *pbsstore.Throttle {
	r.mu.Lock()
	defer r.mu.Unlock()
	if bps <= 0 {
		delete(r.m, key)
		return nil
	}
	want := pbsstore.NewThrottle(bps)
	if t, ok := r.m[key]; ok && t.Rate() == want.Rate() {
		return t
	}
	if r.m == nil {
		r.m = map[string]*pbsstore.Throttle{}
	}
	r.m[key] = want
	return want
}

// SetReplicationLimiterWrapForTest wraps the limiter every replication run is
// handed (key is the schedule row's corrosion.ReplicationRateKey), so a test
// can count what each run charges. Tests only.
func (s *Server) SetReplicationLimiterWrapForTest(fn func(key string, t *pbsstore.Throttle) pbsstore.RateLimiter) {
	s.replRateThrottles.mu.Lock()
	s.replRateThrottles.wrap = fn
	s.replRateThrottles.mu.Unlock()
}

// scheduleLimiter reads sched's stored bandwidth limit at the start of a run
// and returns the schedule's shared limiter, or nil when it has none. A fan-out
// run is charged to the schedule row it came from. A limit that cannot be
// read leaves the run unlimited rather than failing it: a run that does not
// happen ages the replica, which is worse than one that is not paced.
func (s *Server) scheduleLimiter(ctx context.Context, sched corrosion.BackupScheduleRecord) pbsstore.RateLimiter {
	row := sched.Origin
	if row == "" {
		row = sched.VMName
	}
	bps, err := corrosion.GetReplicationRate(ctx, s.db, row, sched.Repo)
	if err != nil {
		slog.Warn("replication: bandwidth limit unreadable; this run is not paced",
			"schedule", row, "repo", sched.Repo, "error", err)
		return nil
	}
	key := corrosion.ReplicationRateKey(row, sched.Repo)
	t := s.replRateThrottles.throttle(key, bps)
	if t == nil {
		return nil
	}
	s.replRateThrottles.mu.Lock()
	wrap := s.replRateThrottles.wrap
	s.replRateThrottles.mu.Unlock()
	if wrap != nil {
		return wrap(key, t)
	}
	return t
}

// containerReplicationLimiters are a container replication run's limiters:
// read paces the archive read, by the target repo's shared throttle; send
// paces the chunks sent, by that throttle and the schedule's shared one
// combined, so the lower rate wins. Never a per-run throttle: every run of the
// schedule on this host shares the schedule's.
func (s *Server) containerReplicationLimiters(ctx context.Context, sched corrosion.BackupScheduleRecord, repo string) (read, send pbsstore.RateLimiter) {
	repoLim := s.targetThrottle(ctx, repo)
	return pbsstore.CombineLimiters(repoLim), pbsstore.CombineLimiters(s.scheduleLimiter(ctx, sched), repoLim)
}

type replicationLimiterKey struct{}

// withReplicationLimiter carries a run's limiter to every leg that sends its
// data to a peer.
func withReplicationLimiter(ctx context.Context, l pbsstore.RateLimiter) context.Context {
	if l == nil {
		return ctx
	}
	return context.WithValue(ctx, replicationLimiterKey{}, l)
}

// replicationLimiter is the run's limiter, or nil.
func replicationLimiter(ctx context.Context) pbsstore.RateLimiter {
	l, _ := ctx.Value(replicationLimiterKey{}).(pbsstore.RateLimiter)
	return l
}

// chargeReplication charges n bytes about to be sent to a peer to the run's
// limiter, if it has one.
func chargeReplication(ctx context.Context, n int) error {
	if l := replicationLimiter(ctx); l != nil {
		return l.WaitN(ctx, n)
	}
	return nil
}
