package grpcapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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
// and before the gRPC server: each domain whose paused start is recorded here
// (markStartPaused) and that nothing else holds is readied (readyGuestHere,
// as the interrupted start would have) and resumed, or, when it cannot be,
// named by vm_start_stranded_paused. JudgeStrandedStarts resolves the
// condition on every later pass once the domain is no longer held that way.

// Health condition of a start left paused (subject vm/<name>@<host>).
const (
	StrandedStartEvaluator  = "start_guard"
	CondStrandedStartPaused = "vm_start_stranded_paused"
)

// strandedStart reports whether vm's domain here is a start this daemon left
// paused, safe to finish: a paused start of it is recorded here
// (markStartPaused), the domain is paused, its row names this host and says
// it runs or is starting, and nothing else holds it paused — no partition
// pause mark on the live domain, no partition pause record in any layer
// (memory, the reserve, the record directory), no hand-over, no firmware
// hold. Any of those that cannot be read holds it too (fail closed): the sweep
// never resumes a guest another part of litevirt may be holding, whatever its
// own record says (review R2-B1).
func (s *Server) strandedStart(ctx context.Context, vm string) bool {
	marked, err := s.startPausedMarked(vm)
	if err != nil || !marked {
		return false
	}
	st, err := s.virt.DomainStateReason(vm)
	if err != nil || st.Reason != "paused" || (st.PausedReason != "user" && st.PausedReason != "starting-up") {
		return false
	}
	rec, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil || rec == nil || rec.HostName != s.hostName || (rec.State != "running" && rec.State != "starting") {
		return false
	}
	marks, ok := s.virt.(interface {
		PartitionPauseMark(name string) (string, bool, error)
	})
	if !ok {
		return false
	}
	if _, marked, merr := marks.PartitionPauseMark(vm); marked || merr != nil {
		return false // partition pause's, or cannot be told apart from it
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

// ResumeStrandedStarts readies and resumes every start this daemon recorded
// as paused (markStartPaused) and did not finish, and names the ones it
// cannot. Call it once, at daemon start, after the start guard and the first
// firewall pass, before any start source and the gRPC server: nothing else
// can be starting a domain then. A record whose domain is no longer paused (it
// was resumed or stopped by other means, or is gone) is dropped. A domain
// paused without a record is never resumed here.
func (s *Server) ResumeStrandedStarts(ctx context.Context) {
	if s.virt == nil || s.db == nil {
		return
	}
	s.removeHalfWrittenStartRecords()
	for _, vm := range s.startPausedRecords() {
		if ctx.Err() != nil {
			return
		}
		st, err := s.virt.DomainStateReason(vm)
		switch {
		case err != nil && lv.IsNoDomain(err):
			// libvirt's own VIR_ERR_NO_DOMAIN, and nothing else: any other
			// error (a dropped connection, a driver's "not found") keeps the
			// record, since the domain may still be paused.
			s.unmarkStartPaused(vm) // no such domain here: nothing to finish
			continue
		case err == nil && st.Reason != "paused":
			s.unmarkStartPaused(vm) // it runs, or was stopped: the start ended
			continue
		}
		if row, rerr := corrosion.GetVM(ctx, s.db, vm); rerr == nil && (row == nil || row.HostName != s.hostName) {
			s.unmarkStartPaused(vm) // its VM is gone, or another host's now
			continue
		}
		// Something else holding it comes first: such a domain is left
		// paused, and is not reported as a stranded start (review M3).
		if !s.strandedStart(ctx, vm) {
			slog.Warn("start guard: a start this daemon left paused is held by something else, or cannot be judged; it stays paused",
				"vm", vm)
			continue
		}
		// The record's incarnation must be the domain's: a same-name domain
		// of another uuid (deleted and created again since) is not this
		// start's, and is never resumed by it. A record that holds no uuid
		// (the definition could not be read when the start was recorded)
		// cannot show the domain is that start's, and is not resumed either.
		want, rerr := s.startPausedUUID(vm)
		var refuse error
		switch {
		case rerr != nil:
			refuse = fmt.Errorf("its start record cannot be read: %w", rerr)
		case want == "":
			refuse = errors.New("its start record holds no readable domain uuid (the definition could not be read when the start was recorded), so the domain here cannot be shown to be that start's")
		case !s.domainIsUUID(vm, want):
			refuse = fmt.Errorf("its start record names another incarnation (uuid %s) than the domain here, or the domain's uuid cannot be read", want)
		}
		if refuse != nil {
			slog.Error("start guard: not finishing a paused start: "+refuse.Error(), "vm", vm)
			s.judgeStrandedStart(ctx, vm, refuse)
			continue
		}
		err = s.readyGuestHere(ctx, vm, startingHere)
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
		s.unmarkStartPaused(vm)
		slog.Warn("start guard: finished a start an interrupted daemon left paused: readied and resumed", "vm", vm)
		s.judgeStrandedStart(ctx, vm, nil)
	}
}

// startPausedRecords is the VM names with a paused start recorded here.
func (s *Server) startPausedRecords() []string {
	ents, err := os.ReadDir(filepath.Join(s.dataDir, startPausedDir))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("start guard: cannot read the records of paused starts", "error", err)
		}
		return nil
	}
	var names []string
	for _, e := range ents {
		b, err := hex.DecodeString(e.Name())
		if err != nil || e.IsDir() {
			continue // a temporary file, or not ours
		}
		names = append(names, string(b))
	}
	sort.Strings(names)
	return names
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

// domainIsUUID reports whether vm's domain here is the incarnation uuid.
func (s *Server) domainIsUUID(vm, uuid string) bool {
	x, err := s.virt.DumpXML(vm)
	if err != nil {
		return false
	}
	return strings.EqualFold(lv.UUIDFromXML(x), uuid)
}
