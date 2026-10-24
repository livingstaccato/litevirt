package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A start through the guard creates a guest with tap VLANs (or a guarded NIC
// that names no tap) paused, readies it, and resumes it. A daemon that dies
// in that window — or a libvirt connection that drops, so that neither the
// resume nor the destroy lands — leaves the domain created and paused, with
// no record that would ever resume it: no hand-over, no partition pause, no
// firmware hold (review NB-R1). Nothing leaks — ConvergeTapVLANs still puts
// its VLANs on — but the guest never runs, and nothing said so.
//
// ResumeStrandedStarts runs once at daemon start, before any start source
// and before the gRPC server: each such domain is readied (readyGuestHere,
// as the interrupted start would have) and resumed, or, when it cannot be,
// named by vm_start_stranded_paused. JudgeStrandedStarts resolves the
// condition on every later pass once the domain is no longer held that way.

// Health condition of a start left paused (subject vm/<name>@<host>).
const (
	StrandedStartEvaluator  = "start_guard"
	CondStrandedStartPaused = "vm_start_stranded_paused"
)

// strandedStart reports whether vm's domain here is a start left paused: the
// domain is paused for a user reason (libvirt's for a domain created paused),
// its row names this host and says it runs or is starting, and no record
// here holds it paused on purpose.
func (s *Server) strandedStart(ctx context.Context, vm string) bool {
	st, err := s.virt.DomainStateReason(vm)
	if err != nil || st.Reason != "paused" || (st.PausedReason != "user" && st.PausedReason != "starting-up") {
		return false
	}
	rec, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil || rec == nil || rec.HostName != s.hostName || (rec.State != "running" && rec.State != "starting") {
		return false
	}
	if _, paused, perr := health.ReadPauseRecord(s.dataDir, health.PauseKindVM, vm); paused || perr != nil {
		return false // partition pause's
	}
	if _, held, herr := s.getHeld(vm); held || herr != nil {
		return false // a hand-over's (resumeHeld)
	}
	if s.firmwareMoveHeld(vm) != nil {
		return false // a live firmware move's
	}
	return true
}

// ResumeStrandedStarts readies and resumes every start this host left
// paused, and names the ones it cannot. Call it once, at daemon start, after
// the start guard and the first firewall pass, before any start source and
// the gRPC server: nothing else can be starting a domain then.
func (s *Server) ResumeStrandedStarts(ctx context.Context) {
	for _, vm := range s.activeDomains() {
		if ctx.Err() != nil {
			return
		}
		if !s.strandedStart(ctx, vm) {
			continue
		}
		err := s.readyGuestHere(ctx, vm, startingHere)
		if err == nil {
			r, ok := s.virt.(interface{ ResumeDomain(string) error })
			if !ok {
				err = fmt.Errorf("this host cannot resume a domain")
			} else if rerr := r.ResumeDomain(vm); rerr != nil {
				err = fmt.Errorf("resume: %w", rerr)
			}
		}
		if err != nil {
			slog.Error("start guard: a start left paused by an interrupted daemon cannot be finished; it stays paused", "vm", vm, "error", err)
			s.judgeStrandedStart(ctx, vm, err)
			continue
		}
		slog.Warn("start guard: finished a start an interrupted daemon left paused: readied and resumed", "vm", vm)
		s.judgeStrandedStart(ctx, vm, nil)
	}
}

// JudgeStrandedStarts resolves vm_start_stranded_paused for each guest of
// this host it names that is no longer a start left paused (it runs, was
// stopped, or is gone). It never resumes anything.
func (s *Server) JudgeStrandedStarts(ctx context.Context) {
	if s.db == nil || s.virt == nil {
		return
	}
	conds, deleted, err := corrosion.ListHealthConditionsByCode(ctx, s.db, StrandedStartEvaluator, CondStrandedStartPaused)
	if err != nil {
		return
	}
	for i, c := range conds {
		if deleted[i] || c.Lifecycle == corrosion.ConditionResolved || c.SubjectKind != "vm" {
			continue
		}
		vm, host, ok := health.SplitAccessVLANSubject(c.SubjectID)
		if !ok || host != s.hostName || s.strandedStart(ctx, vm) {
			continue
		}
		s.judgeStrandedStart(ctx, vm, nil)
	}
}

// activeDomains is the domains active here (running or paused), sorted.
func (s *Server) activeDomains() []string {
	if s.virt == nil || s.db == nil {
		return nil
	}
	lister, ok := s.virt.(interface {
		RunningDomainTaps() (map[string]map[string]string, error)
	})
	if !ok {
		return nil
	}
	running, err := lister.RunningDomainTaps()
	if err != nil {
		slog.Warn("start guard: cannot list the domains active here", "error", err)
		return nil
	}
	names := make([]string, 0, len(running))
	for n := range running {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// judgeStrandedStart raises vm_start_stranded_paused for vm on this host
// while problem, and resolves it once problem is nil.
func (s *Server) judgeStrandedStart(ctx context.Context, vm string, problem error) {
	subject := health.AccessVLANSubject(vm, s.hostName)
	now := time.Now().UTC().Format(time.RFC3339)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, StrandedStartEvaluator, CondStrandedStartPaused, "vm", subject)
	if err != nil {
		return
	}
	if problem == nil {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.CleanCount++
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("start guard: resolve the stranded-start condition", "vm", vm, "error", err)
		}
		return
	}
	ev, _ := json.Marshal(map[string]any{"vm": vm, "host": s.hostName,
		"detail": fmt.Sprintf("VM %s's domain on %s was left paused by a start the daemon did not finish (it stopped between "+
			"creating the domain paused and resuming it), and it cannot be finished now: %v. Fix the cause and restart it "+
			"(`lv restart %s`), or stop it (`lv stop %s --force`)", vm, s.hostName, problem, vm, vm)})
	row = corrosion.HealthCondition{Evaluator: StrandedStartEvaluator, Code: CondStrandedStartPaused,
		SubjectKind: "vm", SubjectID: subject, Lifecycle: corrosion.ConditionConfirmed, FirstSeen: now, ConfirmedAt: now,
		LastSeen: now, ObserveCount: 1, Severity: corrosion.SeverityWarning, Reporter: s.hostName, Hosts: []string{s.hostName},
		Evidence: string(ev)}
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("start guard: raise the stranded-start condition", "vm", vm, "error", err)
	}
}
