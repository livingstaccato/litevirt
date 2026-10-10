package grpcapi

import (
	"context"
	"sync"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// backupBandwidth holds the per-target (per backup repo) bandwidth limits from
// daemon config `backup_bwlimits:`. Each target has ONE throttle, shared by
// every backup job this daemon runs into that repo — a scheduled fan-out of
// twenty VMs moves at the target's rate in total, not twenty times it.
type backupBandwidth struct {
	mu        sync.RWMutex
	throttles map[string]*pbsstore.Throttle // repo name -> shared throttle
}

// SetBackupBandwidthLimits installs the per-repo limits (bytes/s by logical
// repo name). Called once at startup from daemon config.
func (s *Server) SetBackupBandwidthLimits(limits map[string]int64) {
	th := make(map[string]*pbsstore.Throttle, len(limits))
	for name, bps := range limits {
		if t := pbsstore.NewThrottle(bps); t != nil {
			th[name] = t
		}
	}
	s.backupBW.mu.Lock()
	s.backupBW.throttles = th
	s.backupBW.mu.Unlock()
}

// targetThrottle returns the shared throttle of the repo a backup writes to.
// repo is what the job names it by: a logical name (the RPC's repo_path), or
// the resolved on-disk path (the scheduler), which is matched against the
// path each limited name resolves to.
func (s *Server) targetThrottle(ctx context.Context, repo string) *pbsstore.Throttle {
	s.backupBW.mu.RLock()
	defer s.backupBW.mu.RUnlock()
	if len(s.backupBW.throttles) == 0 || repo == "" {
		return nil
	}
	if t, ok := s.backupBW.throttles[repo]; ok {
		return t
	}
	for name, t := range s.backupBW.throttles {
		p, ok := s.backupRepos[name]
		if !ok && s.db != nil {
			if dp, err := corrosion.GetBackupRepoPath(ctx, s.db, name); err == nil && dp != "" {
				p, ok = dp, true
			}
		}
		if ok && p == repo {
			return t
		}
	}
	return nil
}

// targetRate is the target's limit in bytes/s (0 = none).
func (s *Server) targetRate(ctx context.Context, repo string) int64 {
	return s.targetThrottle(ctx, repo).Rate()
}

// backupRateLimit is the limiter a backup job into repo runs under: its own
// limit (jobBps, from the request) and the target's shared one. Either may
// be absent; nil means unlimited.
func (s *Server) backupRateLimit(ctx context.Context, repo string, jobBps int64) pbsstore.RateLimiter {
	return pbsstore.CombineLimiters(pbsstore.NewThrottle(jobBps), s.targetThrottle(ctx, repo))
}

// forwardRate is the job limit a repo sink hands the owning host for a remote
// backup: the lower of the job's own limit and this sink's limit for the
// target, since the owner does the reading and sending and does not know
// the sink's config.
func (s *Server) forwardRate(ctx context.Context, repo string, jobBps int64) int64 {
	return minPositive(jobBps, s.targetRate(ctx, repo))
}

// minPositive returns the smaller of two limits, where <= 0 means none.
func minPositive(a, b int64) int64 {
	switch {
	case a <= 0:
		if b < 0 {
			return 0
		}
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}
