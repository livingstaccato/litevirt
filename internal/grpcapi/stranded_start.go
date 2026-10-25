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
// (markStartPaused), whose row is running or starting here and that nothing
// else holds is readied (readyGuestHere, as the interrupted start would have)
// and resumed; every other one it keeps is named by vm_start_stranded_paused,
// but for one something else holds, which reports it. JudgeStrandedStarts resolves the
// condition on every later pass once the domain is no longer held that way.

// Health condition of a start left paused (subject vm/<name>@<host>).
const (
	StrandedStartEvaluator  = "start_guard"
	CondStrandedStartPaused = "vm_start_stranded_paused"
)

// strandedVerdict is what the sweep does with a recorded paused start
// (classifyStrandedStart). `lv start` and `lv stop` only read it: neither
// finishes such a start (startLeftPausedRefusal, stopLocked).
type strandedVerdict int

const (
	// strandedDrop: the start has ended (the domain is gone or no longer
	// paused) or its VM is gone: the record goes. A row naming another host
	// is strandedRefuse: that paused domain is kept and named (review m2).
	strandedDrop strandedVerdict = iota
	// strandedHeld: something else holds the domain paused on purpose — a
	// partition pause (its mark or its record), a hand-over, a firmware
	// move — and reports it itself. Left paused, record kept, not named.
	strandedHeld
	// strandedRefuse: the start cannot be finished, and nothing else names
	// the guest: left paused, record kept, named by vm_start_stranded_paused.
	strandedRefuse
	// strandedFinish: this daemon's own start of this incarnation, held by
	// nothing, its row running or starting here: the sweep finishes it
	// (readyGuestHere, then resume).
	strandedFinish
)

// strandedRowStates are the row states whose recorded paused start the sweep
// finishes: the reconciler's starts (failover, reschedule, onboot) write
// starting, or keep running. An operator `lv start` writes running only once
// the domain is up (its row is still stopped), and a restart-policy start
// leaves error or crashed: those are not finished here, but named (rc9 lab F1;
// finishing them with every gate they need is v1.10.1's).
var strandedRowStates = map[string]bool{"running": true, "starting": true}

// strandedReport is why a recorded paused start is not finished, and what
// the operator is told to do about it (strandedRemedy).
type strandedReport struct {
	why string
	// neverRan: proven, not inferred: the record names the domain's own
	// incarnation (its uuid), and QEMU reports the domain "prelaunch"
	// (query-status), which only a guest whose vCPUs never ran is. libvirt's
	// paused reason "user" is no proof: it reports the same for an operator's
	// suspend (review F7 I1).
	neverRan bool
	// rowHost: the VM's row names this other host.
	rowHost string
	// rowGone: the VM's row is gone (the VM was deleted).
	rowGone bool
}

func (r strandedReport) Error() string { return r.why }

// classifyStrandedStart judges vm's recorded paused start. The report says
// why for strandedRefuse (the condition's text) and strandedHeld (a log line).
//
// Nothing is ever resumed here on a guess: a hold, or any of its evidence that
// cannot be read, keeps the domain paused; a record whose incarnation does not
// match the domain's, or holds none, keeps it paused (review NB-R14, M1-M3).
// Nothing is killed here either.
func (s *Server) classifyStrandedStart(ctx context.Context, vm string) (strandedVerdict, strandedReport) {
	refuse := func(format string, a ...any) (strandedVerdict, strandedReport) {
		return strandedRefuse, strandedReport{why: fmt.Sprintf(format, a...)}
	}
	marked, err := s.startPausedMarked(vm)
	switch {
	case err != nil:
		return refuse("its start record cannot be read: %v", err)
	case !marked:
		return strandedDrop, strandedReport{why: "no start record"}
	}
	st, err := s.virt.DomainStateReason(vm)
	switch {
	case err != nil && lv.IsNoDomain(err):
		// libvirt's own VIR_ERR_NO_DOMAIN, and nothing else: any other error
		// (a dropped connection, a driver's "not found") keeps the record.
		return strandedDrop, strandedReport{why: "no such domain here"}
	case err != nil:
		return refuse("its domain's state cannot be read: %v", err)
	case st.Reason != "paused":
		return strandedDrop, strandedReport{why: "its domain is not paused: the start ended"}
	}
	row, err := corrosion.GetVM(ctx, s.db, vm)
	switch {
	case err != nil:
		return refuse("its VM row cannot be read: %v", err)
	}
	// Something else holding it paused comes first: it is left paused, and
	// not reported as a stranded start (review M3).
	marks, ok := s.virt.(interface {
		PartitionPauseMark(name string) (string, bool, error)
	})
	if !ok {
		return refuse("this host cannot read the partition pause mark")
	}
	if _, pp, merr := marks.PartitionPauseMark(vm); pp {
		return strandedHeld, strandedReport{why: "partition pause holds it (its mark)"}
	} else if merr != nil {
		return refuse("whether partition pause holds it cannot be read (its mark: %v)", merr)
	}
	if _, pp, perr := health.ReadPauseRecord(s.dataDir, health.PauseKindVM, vm); pp {
		return strandedHeld, strandedReport{why: "partition pause holds it (its record)"}
	} else if perr != nil {
		return refuse("whether partition pause holds it cannot be read (its record: %v)", perr)
	}
	if _, held, herr := s.getHeld(vm); held {
		return strandedHeld, strandedReport{why: "a hand-over holds it"}
	} else if herr != nil {
		return refuse("whether a hand-over holds it cannot be read: %v", herr)
	}
	if ferr := s.firmwareMoveHeld(vm); ferr != nil {
		return strandedHeld, strandedReport{why: ferr.Error()}
	}
	// Whether this is the start's own guest, and whether it never ran: the
	// record names the domain's incarnation, and QEMU reports it prelaunch.
	// QEMU is asked only for a domain that may be this start's.
	startPause := st.PausedReason == "user" || st.PausedReason == "starting-up"
	want, rerr := s.startPausedUUID(vm)
	own := rerr == nil && want != "" && s.domainIsUUID(vm, want)
	rep := strandedReport{}
	notProven := ""
	if startPause && own {
		rep.neverRan, notProven = s.qemuNeverRan(vm)
	}
	if row == nil {
		// A paused qemu of a deleted VM, holding its disks: kept as it is
		// and named, not dropped unseen (review F7 m2).
		rep.rowGone = true
		rep.why = "its VM row is gone (the VM was deleted)"
		return strandedRefuse, rep
	}
	if row.HostName != s.hostName {
		// Another copy may run there (one copy at every moment): this one is
		// kept as it is — never resumed, never killed — and named, so a
		// paused qemu here is never silent (review m2).
		rep.rowHost = row.HostName
		rep.why = fmt.Sprintf("its VM row names %s, not this host", row.HostName)
		return strandedRefuse, rep
	}
	switch {
	case !startPause:
		rep.why = fmt.Sprintf("its domain is paused for another reason (%s) than a start", st.PausedReason)
		return strandedRefuse, rep
	case rerr != nil:
		rep.why = fmt.Sprintf("its start record cannot be read: %v", rerr)
		return strandedRefuse, rep
	case want == "":
		rep.why = "its start record holds no readable domain uuid (the definition could not be read when the start was recorded), so the domain here cannot be shown to be that start's"
		return strandedRefuse, rep
	case !own:
		rep.why = fmt.Sprintf("its start record names another incarnation (uuid %s) than the domain here, or the domain's uuid cannot be read", want)
		return strandedRefuse, rep
	case !rep.neverRan:
		// libvirt's "user" is also an operator's suspend of a guest that ran,
		// with a record left from an earlier start: never resumed on it.
		rep.why = "it cannot be shown that its guest never ran: " + notProven
		return strandedRefuse, rep
	case !strandedRowStates[row.State]:
		rep.why = fmt.Sprintf("its VM row is %s (an operator `lv start`, or a restart-policy start), and only a start whose row is running or starting is finished automatically", row.State)
		return strandedRefuse, rep
	}
	return strandedFinish, rep
}

// strandedRemedy is what the operator is told to do about vm's start left
// paused on this host: the condition's text and `lv start`'s refusal say the
// same.
func (s *Server) strandedRemedy(vm string, rep strandedReport) string {
	destroyLost := "QEMU reports this copy never ran (prelaunch), so nothing is lost"
	if !rep.neverRan {
		destroyLost = "it cannot be shown that this copy never ran, so it discards whatever guest state it has not flushed " +
			"to disk; decide whether that matters before you run it"
	}
	switch {
	case rep.rowGone:
		return fmt.Sprintf("Its VM row is gone, but this paused domain is still on %[2]s, holding its disks; it is left as it is, "+
			"neither resumed nor killed. Stop it on %[2]s with `virsh destroy %[1]s` (%[3]s)", vm, s.hostName, destroyLost)
	case rep.rowHost != "" && rep.rowHost != s.hostName:
		return fmt.Sprintf("Its row names %[3]s, so another copy may run there: this domain on %[2]s is left as it is, "+
			"neither resumed nor killed. Check which host runs the VM (`lv inspect %[1]s`, and `virsh domstate %[1]s` on %[3]s); "+
			"if %[3]s runs it, stop this copy on %[2]s with `virsh destroy %[1]s` (%[4]s)", vm, s.hostName, rep.rowHost, destroyLost)
	case rep.neverRan:
		return fmt.Sprintf("QEMU reports the guest never ran (prelaunch), so `lv stop --force %[1]s` loses nothing; "+
			"then start it with `lv start %[1]s`", vm)
	}
	return fmt.Sprintf("It cannot be shown that the guest never ran: `lv stop --force %[1]s` discards any guest state not "+
		"flushed to disk, so decide whether that matters before you run it; then start it with `lv start %[1]s`", vm)
}

// qemuNeverRan reports whether QEMU proves vm's guest never ran: its
// query-status is "prelaunch". When not, why says what QEMU answered.
func (s *Server) qemuNeverRan(vm string) (bool, string) {
	q, ok := s.virt.(interface {
		DomainQEMUStatus(name string) (string, error)
	})
	if !ok {
		return false, "this host cannot ask QEMU for its run state"
	}
	st, err := q.DomainQEMUStatus(vm)
	switch {
	case err != nil:
		return false, fmt.Sprintf("QEMU's run state cannot be read (%v)", err)
	case st != lv.QEMUStatusPrelaunch:
		return false, fmt.Sprintf("QEMU reports it %q, not prelaunch, so its guest has run (an operator's suspend, a capture) and its start record is stale", st)
	}
	return true, ""
}

// finishStrandedStart finishes vm's recorded paused start: its NIC firewall
// and VLANs (readyGuestHere, as a start), then the resume; the record goes,
// and the condition resolves. An error leaves the guest paused, its record
// kept, and the condition raised.
func (s *Server) finishStrandedStart(ctx context.Context, vm string, rep strandedReport) error {
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
		rep.why = fmt.Sprintf("finishing it failed: %v", err)
		s.judgeStrandedStart(ctx, vm, rep)
		return err
	}
	s.unmarkStartPaused(vm)
	s.judgeStrandedStart(ctx, vm, nil)
	return nil
}

// ResumeStrandedStarts finishes every start this daemon recorded as paused
// (markStartPaused) and did not finish whose row is running or starting here
// (strandedRowStates), and names every one it keeps without finishing, but for
// a guest something else holds (which that hold reports). Call it once, at
// daemon start, after the start guard and the first firewall pass, before any
// start source and the gRPC server: nothing else can be starting a domain
// then. A domain paused without a record is never resumed here, and nothing
// is ever killed here.
func (s *Server) ResumeStrandedStarts(ctx context.Context) {
	if s.virt == nil || s.db == nil {
		return
	}
	s.removeHalfWrittenStartRecords()
	for _, vm := range s.startPausedRecords() {
		if ctx.Err() != nil {
			return
		}
		verdict, rep := s.classifyStrandedStart(ctx, vm)
		switch verdict {
		case strandedDrop:
			s.unmarkStartPaused(vm)
		case strandedHeld:
			slog.Warn("start guard: a start this daemon left paused is held by something else; it stays paused", "vm", vm, "held_by", rep.why)
		case strandedRefuse:
			slog.Error("start guard: not finishing a start an interrupted daemon left paused; it stays paused: "+rep.why, "vm", vm)
			s.judgeStrandedStart(ctx, vm, rep)
		case strandedFinish:
			if err := s.finishStrandedStart(ctx, vm, rep); err != nil {
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
	s.dropStaleStartRecords()
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

// dropStaleStartRecords drops each start record whose domain runs (active,
// not paused): its start ended, whatever did not remove the record (a
// destroy outside `lv stop --force`, a migration back in, a failed unmark).
// A start in flight is never running before it ends: its domain is shut off
// until its paused create, and paused until its resume (review F7 I1).
func (s *Server) dropStaleStartRecords() {
	for _, vm := range s.startPausedRecords() {
		s.dropStartRecordIfRunning(vm)
	}
}

// dropStartRecordIfRunning drops vm's start record when its domain here
// runs, unpaused: a stale record. Any other state, or one it cannot read,
// keeps it.
func (s *Server) dropStartRecordIfRunning(vm string) {
	st, err := s.virt.DomainStateReason(vm)
	if err != nil || st.Reason != "running" {
		return
	}
	if marked, merr := s.startPausedMarked(vm); merr != nil || !marked {
		return
	}
	slog.Info("start guard: dropped the start record of a domain that runs (stale)", "vm", vm)
	s.unmarkStartPaused(vm)
}

// dropStartRecordIfInactive drops vm's start record when its domain here is
// defined and shut off: nothing is paused, and the start guard lets a start
// go on over it (its Before). Any other state, a missing domain, or a state
// it cannot read keeps it.
func (s *Server) dropStartRecordIfInactive(vm string) {
	active, err := s.virt.DomainIsActive(vm)
	if err != nil || active {
		return
	}
	if marked, merr := s.startPausedMarked(vm); merr != nil || !marked {
		return
	}
	slog.Info("start guard: dropped the start record of a domain that is shut off (stale)", "vm", vm)
	s.unmarkStartPaused(vm)
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
	var rep strandedReport
	if !errors.As(problem, &rep) {
		rep = strandedReport{why: problem.Error()}
	}
	ev, _ := json.Marshal(map[string]any{"vm": vm, "host": s.hostName, "row_host": rep.rowHost, "never_ran": rep.neverRan,
		"detail": fmt.Sprintf("VM %s's domain on %s was left paused by a start the daemon did not finish (it stopped between "+
			"creating the guest paused and resuming it), and it is not finished automatically: %s. %s",
			vm, s.hostName, rep.why, s.strandedRemedy(vm, rep))})
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

// startLeftPausedRefusal is `lv start` of a VM whose domain here a start of
// this host has paused (its start-paused record is there, the domain paused):
// that start is not finished here (finishing an operator's or a
// restart-policy start, with every gate it needs, is v1.10.1's), and the VM is
// not started again over it. The start is refused, saying what to do, and the
// record kept: no start path deletes the record of a start it did not finish.
// nil when there is no such start (no record, or the domain is not paused or
// gone): the start goes on as any other.
func (s *Server) startLeftPausedRefusal(ctx context.Context, vm string) error {
	if st, err := s.virt.DomainStateReason(vm); (err == nil && st.Reason != "paused") || (err != nil && lv.IsNoDomain(err)) {
		return nil // a stale record of a domain that runs: the start guard drops it
	}
	if marked, err := s.startPausedMarked(vm); err == nil && !marked {
		return nil
	}
	verdict, rep := s.classifyStrandedStart(ctx, vm)
	switch verdict {
	case strandedDrop:
		return nil
	case strandedHeld:
		return status.Errorf(codes.FailedPrecondition,
			"VM %q is paused here by an unfinished start, and %s; it stays paused, and it was not started", vm, rep.why)
	}
	// Refused, and not named here: a start the reconciler has in flight
	// (a restart-policy start's row is error) looks exactly like this until
	// it resumes. A start left paused is named by the sweep (a daemon that
	// died) or by the start guard (a start that failed paused: PausedKept).
	why := rep.why
	if why == "" {
		why = "a start of this host, in flight or interrupted, has not resumed it"
	}
	return status.Errorf(codes.FailedPrecondition,
		"VM %q is paused here by a start that was not finished (%s), and `lv start` does not finish it; it was not started. %s",
		vm, why, s.strandedRemedy(vm, rep))
}

// pausedStopRefusal is the refusal of a plain `lv stop` of vm, whose domain
// here is paused for libvirtReason: why it is paused, as far as it is known,
// that a graceful stop is impossible, and that `lv stop --force` destroys it.
func (s *Server) pausedStopRefusal(ctx context.Context, vm, libvirtReason string) string {
	why := libvirtReason
	if why == "" {
		why = "reason unknown"
	}
	lost := "it discards any guest state not flushed to disk, so decide whether that matters before you run it"
	if marked, err := s.startPausedMarked(vm); err != nil || marked {
		switch verdict, rep := s.classifyStrandedStart(ctx, vm); {
		case verdict == strandedHeld:
			why += "; " + rep.why
		case rep.neverRan:
			why += "; a start of this host created it paused and was not finished, and QEMU reports the guest never ran (prelaunch)"
			lost = "the guest never ran, so nothing is lost"
		case verdict == strandedRefuse:
			why += "; a start of this host left it paused (" + rep.why + ")"
		}
	}
	return fmt.Sprintf("VM %[1]q is paused (%[2]s), so a graceful stop is impossible, and it was not stopped. "+
		"`lv stop --force %[1]s` destroys it (%[3]s); or let it resume first and stop it then (a partition pause resumes "+
		"when the partition heals; a guest held for its NIC guards: `lv firewall nic-guard resume %[1]s`)", vm, why, lost)
}

// startLeftPausedGuardRefusal is the start guard's refusal of a start of vm
// over the start this host left paused (its record is there, its domain
// active): what holds it, or what to do.
func (s *Server) startLeftPausedGuardRefusal(ctx context.Context, vm string) error {
	verdict, rep := s.classifyStrandedStart(ctx, vm)
	if verdict == strandedHeld {
		return fmt.Errorf("a start of %s this host left paused is not finished (its start-paused record is there), and %s; "+
			"it is not started again over it", vm, rep.why)
	}
	return fmt.Errorf("a start of %s this host left paused is not finished (its start-paused record is there), and it is not "+
		"started again over it. %s", vm, s.strandedRemedy(vm, rep))
}

// strandedStartKept names vm at once when a start of it failed after its
// paused create and its domain may still be paused, its record kept
// (libvirt.StartGuard.PausedKept): not only at the next daemon start (review
// F7 m5). A domain something else holds is that hold's to report.
func (s *Server) strandedStartKept(ctx context.Context, vm string, startErr error) {
	verdict, rep := s.classifyStrandedStart(ctx, vm)
	switch verdict {
	case strandedDrop, strandedHeld:
		return
	}
	if verdict == strandedFinish || rep.why == "" {
		rep.why = fmt.Sprintf("a start failed (%v) after creating it paused, and its domain could not be stopped", startErr)
	} else {
		rep.why = fmt.Sprintf("a start failed (%v) after creating it paused, and %s", startErr, rep.why)
	}
	slog.Error("start guard: a failed start left the domain paused; its record is kept and the guest named", "vm", vm, "error", startErr)
	s.judgeStrandedStart(ctx, vm, rep)
}

// startRecordRefusal refuses an operation that would start vm's domain
// again (a snapshot restore) while a start of this host has left a record
// for it: the start guard would refuse that start only after the operation
// had torn the domain down (review F7 m1). A record whose domain runs is
// stale, and dropped; so is one whose domain is shut off (a destroy outside
// `lv stop --force`), which holds no paused guest and which the start guard
// does not refuse a start over either (review r8-m1). The restore holds the
// VM's lock, and its start lease before it starts anything.
func (s *Server) startRecordRefusal(op, vm string) error {
	s.dropStartRecordIfRunning(vm)
	s.dropStartRecordIfInactive(vm)
	marked, err := s.startPausedMarked(vm)
	switch {
	case err != nil:
		return status.Errorf(codes.FailedPrecondition, "%s of VM %q refused: whether a start of it was left paused here cannot be read: %v", op, vm, err)
	case !marked:
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%[1]s of VM %[2]q refused, and nothing was changed: a start of it on this host was left paused (its start-paused record "+
			"is there), and the %[1]s would start the domain again over it. Run `lv stop --force %[2]s` first (it destroys the "+
			"paused guest and removes the record; `lv stop %[2]s` says whether the guest ran), then the %[1]s", op, vm)
}
