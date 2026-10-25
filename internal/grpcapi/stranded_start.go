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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hooks"
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

// strandedVerdict is what the sweep (and `lv start`) does with a recorded
// paused start (classifyStrandedStart).
type strandedVerdict int

const (
	// strandedDrop: the start has ended or can never be finished here (the
	// domain is gone or no longer paused, its VM is gone or another
	// host's): the record goes.
	strandedDrop strandedVerdict = iota
	// strandedHeld: something else holds the domain paused on purpose — a
	// partition pause (its mark or its record), a hand-over, a firmware
	// move — and reports it itself. Left paused, record kept, not named.
	strandedHeld
	// strandedRefuse: the start cannot be finished, and nothing else names
	// the guest: left paused, record kept, named by vm_start_stranded_paused.
	strandedRefuse
	// strandedFinish: this daemon's own start of this incarnation, held by
	// nothing: finish it (readyGuestHere, then resume).
	strandedFinish
)

// strandedRowStates are the row states a start's VM can be in while its
// paused start is unfinished: the reconciler's starts write starting (or keep
// running), an operator `lv start` writes running only once the domain is up
// (so the row is still stopped), and a restart-policy start leaves error
// (rc9 lab finding F1).
var strandedRowStates = map[string]bool{"running": true, "starting": true, "stopped": true, "error": true, "crashed": true}

// classifyStrandedStart judges vm's recorded paused start. why says why for
// strandedRefuse (the condition's text) and strandedHeld (a log line).
//
// Nothing is ever resumed here on a guess: a hold, or any of its evidence that
// cannot be read, keeps the domain paused; a record whose incarnation does not
// match the domain's, or holds none, keeps it paused (review NB-R14, M1-M3).
func (s *Server) classifyStrandedStart(ctx context.Context, vm string) (strandedVerdict, string) {
	marked, err := s.startPausedMarked(vm)
	switch {
	case err != nil:
		return strandedRefuse, fmt.Sprintf("its start record cannot be read: %v", err)
	case !marked:
		return strandedDrop, "no start record"
	}
	st, err := s.virt.DomainStateReason(vm)
	switch {
	case err != nil && lv.IsNoDomain(err):
		// libvirt's own VIR_ERR_NO_DOMAIN, and nothing else: any other error
		// (a dropped connection, a driver's "not found") keeps the record.
		return strandedDrop, "no such domain here"
	case err != nil:
		return strandedRefuse, fmt.Sprintf("its domain's state cannot be read: %v", err)
	case st.Reason != "paused":
		return strandedDrop, "its domain is not paused: the start ended"
	}
	row, err := corrosion.GetVM(ctx, s.db, vm)
	switch {
	case err != nil:
		return strandedRefuse, fmt.Sprintf("its VM row cannot be read: %v", err)
	case row == nil || row.HostName != s.hostName:
		return strandedDrop, "its VM is gone, or another host's now"
	}
	// Something else holding it paused comes first: it is left paused, and
	// not reported as a stranded start (review M3).
	marks, ok := s.virt.(interface {
		PartitionPauseMark(name string) (string, bool, error)
	})
	if !ok {
		return strandedRefuse, "this host cannot read the partition pause mark"
	}
	if _, pp, merr := marks.PartitionPauseMark(vm); pp {
		return strandedHeld, "partition pause holds it (its mark)"
	} else if merr != nil {
		return strandedRefuse, fmt.Sprintf("whether partition pause holds it cannot be read (its mark: %v)", merr)
	}
	if _, pp, perr := health.ReadPauseRecord(s.dataDir, health.PauseKindVM, vm); pp {
		return strandedHeld, "partition pause holds it (its record)"
	} else if perr != nil {
		return strandedRefuse, fmt.Sprintf("whether partition pause holds it cannot be read (its record: %v)", perr)
	}
	if _, held, herr := s.getHeld(vm); held {
		return strandedHeld, "a hand-over holds it"
	} else if herr != nil {
		return strandedRefuse, fmt.Sprintf("whether a hand-over holds it cannot be read: %v", herr)
	}
	if ferr := s.firmwareMoveHeld(vm); ferr != nil {
		return strandedHeld, ferr.Error()
	}
	if st.PausedReason != "user" && st.PausedReason != "starting-up" {
		return strandedRefuse, fmt.Sprintf("its domain is paused for another reason (%s) than a start", st.PausedReason)
	}
	if !strandedRowStates[row.State] {
		return strandedRefuse, fmt.Sprintf("its VM row is %s, which no unfinished start leaves", row.State)
	}
	// The record's incarnation must be the domain's.
	want, rerr := s.startPausedUUID(vm)
	switch {
	case rerr != nil:
		return strandedRefuse, fmt.Sprintf("its start record cannot be read: %v", rerr)
	case want == "":
		return strandedRefuse, "its start record holds no readable domain uuid (the definition could not be read when the start was recorded), so the domain here cannot be shown to be that start's"
	case !s.domainIsUUID(vm, want):
		return strandedRefuse, fmt.Sprintf("its start record names another incarnation (uuid %s) than the domain here, or the domain's uuid cannot be read", want)
	}
	return strandedFinish, ""
}

// finishStrandedStart finishes vm's recorded paused start: its NIC firewall
// and VLANs (readyGuestHere, as a start), then the resume; the record goes,
// and the condition resolves. An error leaves the guest paused, its record
// kept, and the condition raised.
func (s *Server) finishStrandedStart(ctx context.Context, vm string) error {
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
		s.judgeStrandedStart(ctx, vm, err)
		return err
	}
	s.unmarkStartPaused(vm)
	s.judgeStrandedStart(ctx, vm, nil)
	return nil
}

// ResumeStrandedStarts finishes every start this daemon recorded as paused
// (markStartPaused) and did not finish, and names every one it keeps without
// finishing, but for a guest something else holds (which that hold reports).
// Call it once, at daemon start, after the start guard and the first firewall
// pass, before any start source and the gRPC server: nothing else can be
// starting a domain then. A domain paused without a record is never resumed
// here.
func (s *Server) ResumeStrandedStarts(ctx context.Context) {
	if s.virt == nil || s.db == nil {
		return
	}
	s.removeHalfWrittenStartRecords()
	for _, vm := range s.startPausedRecords() {
		if ctx.Err() != nil {
			return
		}
		verdict, why := s.classifyStrandedStart(ctx, vm)
		switch verdict {
		case strandedDrop:
			s.unmarkStartPaused(vm)
		case strandedHeld:
			slog.Warn("start guard: a start this daemon left paused is held by something else; it stays paused", "vm", vm, "held_by", why)
		case strandedRefuse:
			slog.Error("start guard: not finishing a start an interrupted daemon left paused: "+why, "vm", vm)
			s.judgeStrandedStart(ctx, vm, errors.New(why))
		case strandedFinish:
			if err := s.finishStrandedStart(ctx, vm); err != nil {
				slog.Error("start guard: a start left paused by an interrupted daemon cannot be finished; it stays paused", "vm", vm, "error", err)
				continue
			}
			slog.Warn("start guard: finished a start an interrupted daemon left paused: readied and resumed", "vm", vm)
		}
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
		if !ok || host != s.hostName {
			continue
		}
		if v, _ := s.classifyStrandedStart(ctx, vm); v == strandedRefuse || v == strandedFinish {
			continue // still a start left paused
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

// finishStartLeftPaused is `lv start` of a VM whose domain a start of this
// host left paused (its start-paused record is there, the domain paused):
// that start is finished — its firewall and VLANs, then the resume — and the
// VM recorded running, instead of a second create libvirt would refuse. One
// that cannot be finished (something holds it, or it is not provably that
// start's) is refused, the record kept and the guest named. done says
// whether it handled the start; when not, the start goes on as any other.
func (s *Server) finishStartLeftPaused(ctx context.Context, vm *corrosion.VMRecord) (*pb.VM, bool, error) {
	if marked, err := s.startPausedMarked(vm.Name); err != nil || !marked {
		return nil, false, nil
	}
	verdict, why := s.classifyStrandedStart(ctx, vm.Name)
	switch verdict {
	case strandedDrop:
		s.unmarkStartPaused(vm.Name)
		return nil, false, nil
	case strandedHeld:
		return nil, true, status.Errorf(codes.FailedPrecondition,
			"VM %q is paused here by an unfinished start, and %s; it stays paused", vm.Name, why)
	case strandedRefuse:
		err := errors.New(why)
		s.judgeStrandedStart(ctx, vm.Name, err)
		return nil, true, status.Errorf(codes.FailedPrecondition,
			"VM %q is paused here by an unfinished start that cannot be finished: %s; stop it (`lv stop %s`) and start it again",
			vm.Name, why, vm.Name)
	}
	if err := s.finishStrandedStart(ctx, vm.Name); err != nil {
		return nil, true, status.Errorf(codes.FailedPrecondition,
			"VM %q is paused here by an unfinished start, and finishing it failed: %v; it stays paused", vm.Name, err)
	}
	slog.Warn("StartVM: finished a start an interrupted daemon left paused", "vm", vm.Name)
	s.noteVMStarted(vm.Name)
	if err := s.persistVMState(ctx, vm.Name, "running", "", corrosion.OpVMState); err != nil {
		slog.Error("StartVM: recording running state failed — reconciler will heal", "vm", vm.Name, "error", err)
	}
	s.recordVMEvent(ctx, vm.Name, "vm.started", "ok", "finished a start an interrupted daemon left paused")
	pbVM := &pb.VM{Name: vm.Name, HostName: vm.HostName, State: pb.VMState_VM_RUNNING}
	hooks.Run(ctx, hooks.PostStart, pbVM, vmHooks(vm))
	out, err := s.startedVMProto(ctx, vm.Name)
	return out, true, err
}
