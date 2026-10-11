package grpcapi

import (
	"sync"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A replication run whose copy was not point-in-time (pit_copy.go, layer 3)
// is retried at the scheduler's next tick rather than a full interval later,
// so a transient failure of the backup session or the snapshot leaves the
// newest replica not point-in-time for a minute, not a day.
//
// The retry is point-in-time or nothing: it does not take the -U copy again
// (that would copy the whole disk every minute while the cause lasts). A
// retry that fails leaves the schedule's own cron to run next, which may take
// the -U copy as main did. The set is node-local and in memory — the run
// happens on the VM's owner, and a restart only means the cron runs next.

// pitRetrySet holds the runs owed a point-in-time retry.
type pitRetrySet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (p *pitRetrySet) set(k string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]bool{}
	}
	p.m[k] = true
}

// take reports whether k was owed a retry and clears it.
func (p *pitRetrySet) take(k string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	owed := p.m[k]
	delete(p.m, k)
	return owed
}

func (p *pitRetrySet) has(k string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.m[k]
}

func (p *pitRetrySet) any() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m) > 0
}

// pitRetryKey names one VM's runs of one schedule (a fan-out row's run for
// each of its VMs apart).
func pitRetryKey(sched corrosion.BackupScheduleRecord) string {
	return replicaScheduleKey(sched) + "\x00" + sched.VMName + "\x00" + sched.TargetPool
}

// PointInTimeRetryDue reports whether sched's last run for its VM produced a
// copy that is not point-in-time, so the scheduler runs it again now
// (scheduler.PointInTimeRetrier).
func (s *Server) PointInTimeRetryDue(sched corrosion.BackupScheduleRecord) bool {
	return s.pitRetry.has(pitRetryKey(sched))
}

// AnyPointInTimeRetryDue is the scheduler's cheap check before it looks at
// schedules whose cron does not match.
func (s *Server) AnyPointInTimeRetryDue() bool { return s.pitRetry.any() }
