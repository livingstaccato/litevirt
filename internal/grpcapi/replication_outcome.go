package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
)

// Reporting a replication schedule's runs.
//
// A schedule runs on a cron, and a target that is down stays down for as long
// as it is down: reported per run, a */5 schedule against a host that is off
// for a weekend pages about 860 times and writes as many replicated audit rows.
// So a run's outcome is reported on a TRANSITION only: the first failure, a
// failure of another class, and the recovery. While a failure continues, the
// notification repeats at most hourly and writes no audit row. The previous
// state is this daemon's memory, seeded from the schedule row's last_run_err
// (what the scheduler recorded for the last run), so a restart does not re-page
// for a failure it already reported.

// replRenotifyEvery is how often a continuing failure is re-notified.
const replRenotifyEvery = time.Hour

// replSuspendGrace is how long a run on a workload's own replica target is
// skipped quietly: long enough for the move's own direction switch to arrive
// from the host that committed it (it replicates; this host may run first).
const replSuspendGrace = 15 * time.Minute

type replRunState struct {
	failing      bool
	class        string
	lastNotified time.Time
	// ownTargetSince is when runs first found the workload on its own replica
	// target (zero when they do not).
	ownTargetSince time.Time
	// notOwnerSince is when runs on this host began to be skipped because it
	// may not act as the VM's owner (zero when the last run was not), and
	// notOwnerLast and notOwnerNotified the latest such skip and alert.
	notOwnerSince, notOwnerLast, notOwnerNotified time.Time
}

// replNotOwnerGrace is how long runs may be skipped as not-owner before the
// skip is alerted: a host back from a fence warms up and catches up well
// inside it, and a VM that moved stops being dispatched here once the move
// replicates. A skip that lasts past it means the host the schedule sees as
// the VM's owner is still fenced or out of the cluster, and no replica is
// being taken. A var so a test can shorten it.
var replNotOwnerGrace = 15 * time.Minute

// replNotOwnerForget is the gap after which an earlier skip no longer counts
// toward the grace: the skips are separate episodes.
const replNotOwnerForget = 25 * time.Hour

// notOwnerSkip records one run of sched skipped because this host may not act
// as the VM's owner now (reason), and alerts `replication.skipped` (warn) once
// the skips have lasted replNotOwnerGrace, again at most hourly while they
// continue. Any run that is not skipped ends the episode (replicationOutcome).
func (s *Server) notOwnerSkip(ctx context.Context, sched corrosion.BackupScheduleRecord, name string, reason error) {
	st := s.replState(sched)
	now := time.Now()
	s.replRuns.mu.Lock()
	if st.notOwnerSince.IsZero() || now.Sub(st.notOwnerLast) > replNotOwnerForget {
		st.notOwnerSince, st.notOwnerNotified = now, time.Time{}
	}
	st.notOwnerLast = now
	since := st.notOwnerSince
	due := now.Sub(since) >= replNotOwnerGrace &&
		(st.notOwnerNotified.IsZero() || now.Sub(st.notOwnerNotified) >= replRenotifyEvery)
	if due {
		st.notOwnerNotified = now
	}
	s.replRuns.mu.Unlock()
	if !due {
		return
	}
	s.notify(ctx, notify.Notification{Kind: "replication.skipped", Severity: notify.SevWarn, Subject: name,
		Detail: fmt.Sprintf("%s has skipped vm %s's replication schedule since %s: %v. If the VM still runs on this host, "+
			"no replica of it is being taken; if it moved, this host's view has not caught up",
			s.hostName, name, since.UTC().Format(time.RFC3339), reason)})
}

type replRuns struct {
	mu sync.Mutex
	m  map[string]*replRunState
}

func replRunKey(sched corrosion.BackupScheduleRecord) string {
	return sched.Origin + "\x00" + sched.VMName + "\x00" + sched.Repo
}

// replState returns a schedule's reporting state, seeded on first sight from
// the row's last recorded outcome.
func (s *Server) replState(sched corrosion.BackupScheduleRecord) *replRunState {
	s.replRuns.mu.Lock()
	defer s.replRuns.mu.Unlock()
	if s.replRuns.m == nil {
		s.replRuns.m = map[string]*replRunState{}
	}
	k := replRunKey(sched)
	st, ok := s.replRuns.m[k]
	if !ok {
		st = &replRunState{failing: sched.LastRunErr != "", class: "previous"}
		if st.failing {
			// Already reported by whichever run recorded it: wait out the
			// re-notify interval rather than page again on the first tick.
			st.lastNotified = time.Now()
		}
		s.replRuns.m[k] = st
	}
	return st
}

// replTargetDownError is a run whose target host is not an active member, or
// cannot be reached.
type replTargetDownError struct {
	host string
	err  error
}

func (e *replTargetDownError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("replica target host %q cannot be reached: %v", e.host, e.err)
	}
	return fmt.Sprintf("replica target host %q is not active", e.host)
}

func (e *replTargetDownError) Unwrap() error { return e.err }

// replErrorClass groups failures that are the same condition, so a change of
// condition is reported and a repeat is not.
func replErrorClass(err error) (class string, sev notify.Severity) {
	var down *replTargetDownError
	var st interface{ GRPCStatus() *status.Status }
	switch {
	case errors.As(err, &down):
		return "target-down:" + down.host, notify.SevWarn
	case errors.Is(err, errReplicationSuspended):
		return "suspended", notify.SevWarn
	case errors.As(err, &st) && st.GRPCStatus().Code() == codes.Aborted:
		// The target's view says the workload is moving (replication_owner.go):
		// the owner's next run lands. A warning, not an error page.
		return "moving", notify.SevWarn
	case errors.As(err, &st):
		return "error:" + st.GRPCStatus().Code().String() + ":" + errShape(st.GRPCStatus().Message()), notify.SevError
	default:
		return "error:" + errShape(err.Error()), notify.SevError
	}
}

// errShape is an error message with its digits blanked and its length capped,
// so a repeat of one cause (another timestamp, another byte count) is the same
// class and another cause is not.
func errShape(msg string) string {
	b := []byte(msg)
	for i, c := range b {
		if c >= '0' && c <= '9' {
			b[i] = '#'
		}
	}
	if len(b) > 96 {
		b = b[:96]
	}
	return string(b)
}

// suspendedOnOwnTarget is the outcome of a run whose schedule targets the host
// the workload now runs on. It never replicates there: the replica would be lost
// with the workload. The move that put it here switches the schedule to the
// host it left; until that switch arrives the run is skipped (quietly, within
// replSuspendGrace), and after that it is reported as suspended.
func (s *Server) suspendedOnOwnTarget(sched corrosion.BackupScheduleRecord, kind, name string) error {
	st := s.replState(sched)
	s.replRuns.mu.Lock()
	if st.ownTargetSince.IsZero() {
		st.ownTargetSince = time.Now()
	}
	s.replRuns.mu.Unlock()
	return fmt.Errorf("%w: %s %s runs on its replica target %q, where a replica protects nothing; the move that put it there switches the schedule to the host it left, or re-target the schedule",
		errReplicationSuspended, kind, name, sched.TargetHost)
}

// replicationOutcome reports one run of a replication schedule (see above).
// detail describes a success.
func (s *Server) replicationOutcome(ctx context.Context, sched corrosion.BackupScheduleRecord, kind, name, project, target, repo, detail string, err error) {
	st := s.replState(sched)
	now := time.Now()
	auditAction := "ct.replicate"
	if kind == "vm" {
		auditAction = "vm.replicate"
	}
	s.replRuns.mu.Lock()
	// A run that was not skipped as not-owner ends any such episode.
	st.notOwnerSince, st.notOwnerNotified = time.Time{}, time.Time{}
	if err == nil {
		wasFailing := st.failing
		st.failing, st.class, st.ownTargetSince = false, "", time.Time{}
		s.replRuns.mu.Unlock()
		if wasFailing {
			msg := fmt.Sprintf("%s %s → %s@%s replicates again", kind, name, repo, target)
			if detail != "" {
				msg += ": " + detail
			}
			s.audit(ctx, auditAction, name, "project="+project+" recovered: "+msg, "ok")
			s.notify(ctx, notify.Notification{Kind: "replication.recovered", Severity: notify.SevInfo, Subject: name, Detail: msg})
		}
		return
	}
	class, sev := replErrorClass(err)
	if class == "suspended" && now.Sub(st.ownTargetSince) < replSuspendGrace {
		s.replRuns.mu.Unlock()
		slog.Debug("replication: workload on its own replica target; waiting for the direction switch", "kind", kind, "workload", name, "target", target)
		return
	}
	if class != "suspended" {
		st.ownTargetSince = time.Time{}
	}
	transition := !st.failing || (st.class != class && st.class != "previous")
	renotify := !transition && now.Sub(st.lastNotified) >= replRenotifyEvery
	if st.class == "previous" && st.failing {
		st.class = class // adopt the class of a failure recorded before this daemon started
	}
	st.failing = true
	st.class = class
	if transition || renotify {
		st.lastNotified = now
	}
	s.replRuns.mu.Unlock()

	msg := fmt.Sprintf("%s %s → %s@%s: %v", kind, name, repo, target, err)
	if transition {
		s.audit(ctx, auditAction, name, "project="+project+" "+msg, "error")
	}
	if transition || renotify {
		k := "replication.failed"
		if class == "suspended" {
			k = "replication.suspended"
		}
		s.notify(ctx, notify.Notification{Kind: k, Severity: sev, Subject: name, Detail: msg})
	}
}
