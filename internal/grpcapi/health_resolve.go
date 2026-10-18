package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// ResolveHealthCondition marks one open dual-run condition resolved on an
// admin's word (`lv health resolve`).
//
// The detector resolves its own conditions only on proof: two complete clean
// scans under a valid gate. A condition that proof can never reach — one its
// evaluator can no longer see, or one stranded by a fault in the evaluator —
// would otherwise refuse admission to the hosts it names for good, with no way
// out. This is that way out, and it proves nothing: it records who resolved
// what and why, in the audit log and as an ha.condition.resolved event.
//
// It is refused until the detector has LOOKED and not seen the condition: a
// scan recorded after the row was last seen, which completely probed every
// host the row names (dualRunScanCleared). Without that a resolve opens
// admission while the detector still sees the condition, or onto a host it
// cannot see at all, where nothing would raise it again.
//
// It is limited to the dual-run detector's conditions. Those are the only ones
// that gate admission, and the detector re-derives every finding from scratch
// each pass, so a condition that still holds is raised again — observed, and
// gating admission again — on its next pass. Other evaluators write on their
// own transitions and could leave a still-true condition resolved.
//
// Admin only (cluster.health.resolve), and never a peer: a peer certificate
// authorizes as admin, and a node must not be able to clear evidence that
// names it.
func (s *Server) ResolveHealthCondition(ctx context.Context, req *pb.ResolveHealthConditionRequest) (*pb.ResolveHealthConditionResponse, error) {
	if callerPrincipalKind(ctx) == principalKindPeer {
		return nil, status.Error(codes.PermissionDenied,
			"resolving a health condition is an operator's decision and not peer-callable")
	}
	if err := s.RequirePerm(ctx, "/", "cluster.health.resolve", "admin"); err != nil {
		return nil, err
	}
	code, kind, id := req.GetCode(), req.GetSubjectKind(), req.GetSubjectId()
	if code == "" || kind == "" || id == "" {
		return nil, status.Error(codes.InvalidArgument, "code, subject kind and subject id are all required")
	}
	open, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read health conditions: %v", err)
	}
	var matches []corrosion.HealthCondition
	for _, h := range open {
		if h.Code != code || h.SubjectKind != kind || h.SubjectID != id {
			continue
		}
		if ev := req.GetEvaluator(); ev != "" && h.Evaluator != ev {
			continue
		}
		matches = append(matches, h)
	}
	switch {
	case len(matches) == 0:
		return nil, status.Errorf(codes.NotFound,
			"no open condition %s on %s/%s; `lv health` lists the open ones", code, kind, id)
	case len(matches) > 1:
		evs := make([]string, 0, len(matches))
		for _, h := range matches {
			evs = append(evs, h.Evaluator)
		}
		return nil, status.Errorf(codes.InvalidArgument,
			"%d evaluators hold an open %s on %s/%s (%s); name one with --evaluator",
			len(matches), code, kind, id, strings.Join(evs, ", "))
	}
	row := matches[0]
	if row.Evaluator == health.MoveUnresolvedEvaluator && row.Code == health.MoveUnresolvedCode {
		return s.resolveMoveConditionByHand(ctx, req, row)
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok && (len(md.Get(MoveAcceptMDKey)) > 0 || len(md.Get(MoveForceMDKey)) > 0) {
		return nil, status.Errorf(codes.InvalidArgument,
			"--accept applies only to %s, as does --force; %s on %s/%s takes neither", health.MoveUnresolvedCode, code, kind, id)
	}
	if row.Evaluator != dualRunEvaluator {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s on %s/%s is evaluator %q's: only the dual-run detector's conditions can be resolved by hand, "+
				"since it re-raises one that still holds on its next pass; remove the cause and %s resolves it",
			code, kind, id, row.Evaluator, row.Evaluator)
	}

	scanAt, why := s.dualRunScanCleared(ctx, row)
	if why != "" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"refusing to resolve %s on %s/%s: %s", code, kind, id, why)
	}

	prior := row.Lifecycle
	now := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt = corrosion.ConditionResolved, now
	row.ObserveCount, row.CleanCount = 0, 0
	row.Reporter = s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.Unavailable, "record the resolution: %v", err)
	}

	target := strings.Join([]string{row.Evaluator, code, kind, id}, "/")
	detail := fmt.Sprintf("resolved by hand on %s (was %s, last seen %s, hosts %s; detector scan %s did not see it)",
		s.hostName, prior, row.LastSeen, strings.Join(row.Hosts, ","), scanAt)
	if r := strings.TrimSpace(req.GetReason()); r != "" {
		detail += ": " + r
	}
	s.audit(ctx, "health.condition.resolve", target, detail, "ok")
	s.publish("ha.condition.resolved", code+":"+kind+"/"+id, detail)
	s.notify(ctx, notify.Notification{
		Kind: notifyKindForCondition(code), Severity: notify.SevInfo, Subject: id, Detail: detail,
	})
	return &pb.ResolveHealthConditionResponse{Condition: healthConditionToPB(row)}, nil
}

// dualRunScanCleared reports the dual-run detector scan that clears row for a
// hand resolution, or why none does: the scan must be later than the row's
// last_seen (a pass that sees a finding refreshes last_seen with its own scan
// time, so a later scan did not see it), and must have completely probed
// every host the row names with both DB indexes readable.
func (s *Server) dualRunScanCleared(ctx context.Context, row corrosion.HealthCondition) (string, string) {
	sts, err := corrosion.ListHealthEvaluatorStatus(ctx, s.db)
	if err != nil {
		return "", "the detector's scan status is unreadable: " + err.Error()
	}
	var st *corrosion.HealthEvaluatorStatus
	for i := range sts {
		if sts[i].Evaluator == dualRunEvaluator {
			st = &sts[i]
		}
	}
	if st == nil {
		return "", "no dual-run detector scan is recorded; no node has held the detector lease"
	}
	scan, err1 := time.Parse(time.RFC3339, st.LastScan)
	seen, err2 := time.Parse(time.RFC3339, row.LastSeen)
	if err1 != nil || err2 != nil {
		return "", fmt.Sprintf("cannot order the last scan (%q) against the condition's last sighting (%q)",
			st.LastScan, row.LastSeen)
	}
	if !scan.After(seen) {
		return "", fmt.Sprintf("the detector last saw it at %s and has not scanned since (last scan %s): "+
			"it still sees it, or its next pass is pending (one a minute while a node holds the detector lease)",
			row.LastSeen, st.LastScan)
	}
	if st.Coverage == corrosion.CoverageComplete {
		return st.LastScan, ""
	}
	blind, indexesOK, ok := parseCoverageDetail(st.Detail)
	switch {
	case !ok:
		return "", fmt.Sprintf("the last scan (%s) was %s and its coverage detail %q is unreadable", st.LastScan, st.Coverage, st.Detail)
	case !indexesOK:
		return "", fmt.Sprintf("the last scan (%s) could not read the VM or container index", st.LastScan)
	case len(row.Hosts) == 0:
		return "", fmt.Sprintf("the condition names no host and the last scan (%s) was %s", st.LastScan, st.Coverage)
	}
	var missing []string
	for _, h := range row.Hosts {
		if why, ok := blind[h]; ok {
			missing = append(missing, h+" ("+why+")")
		}
	}
	if len(missing) > 0 {
		return "", fmt.Sprintf("the last scan (%s) did not completely probe %s, which it names, so it cannot show "+
			"the condition is gone there; bring the host back, or remove it with `lv host rm`",
			st.LastScan, strings.Join(missing, ", "))
	}
	return st.LastScan, ""
}

// MoveAcceptMDKey is the gRPC metadata key carrying `lv health resolve
// --accept <path>` for vm.move_unresolved, once per disk: the file of a move
// the operator accepts as the VM's data, which that disk's row is pointed at.
// Carried as metadata so the request message is unchanged.
const MoveAcceptMDKey = "x-litevirt-move-accept"

// MoveForceMDKey is the gRPC metadata key carrying `lv health resolve
// --force` for vm.move_unresolved: keep the file a forked history's owner
// wrote although the copy was modified after it. Carried as metadata so the
// request message is unchanged.
const MoveForceMDKey = "x-litevirt-move-force"

// moveForce reports whether the call carries --force.
func moveForce(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	return ok && slices.Contains(md.Get(MoveForceMDKey), "true")
}

// moveAccepts returns the --accept paths the call carries.
func moveAccepts(ctx context.Context) []string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}
	var out []string
	for _, v := range md.Get(MoveAcceptMDKey) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// moveRowChange is one disk row a hand resolution points at a move's file:
// written only while the row is still cur, and undone the same way.
type moveRowChange struct {
	m          health.UnresolvedMove
	cur, after corrosion.DiskRecord
}

// resolveMoveConditionByHand resolves an unresolved volume move
// (vm.move_unresolved) on an admin's word, with a reason, under the VM's
// lock and with no move of its disks in flight here.
//
// The host holding the move's record settles it itself when it can, so the
// hand resolution is refused unless it runs on that host (its records are
// then removed too) or that host is proven powered off
// (corrosion.SharedDiskOwnerProvedOff: fenced or removed over a proof-grade
// fence of its last life).
//
// It proves nothing about which file holds the VM's data, so it never picks
// one the cluster has not proven (planMoveHandResolve): every move the disk
// row does not settle needs --accept naming the file to keep, and on the
// VM's owner the persistent config, which `lv start` boots, must name the file
// the row is left on, and a running domain's row is never changed.
//
// The rows are written first, each as a compare-and-set, then the resolution;
// a failure undoes the rows written and is audited.
func (s *Server) resolveMoveConditionByHand(ctx context.Context, req *pb.ResolveHealthConditionRequest, row corrosion.HealthCondition) (*pb.ResolveHealthConditionResponse, error) {
	vm := row.SubjectID
	reason := strings.TrimSpace(req.GetReason())
	if reason == "" {
		return nil, status.Errorf(codes.InvalidArgument,
			"resolving %s on vm/%s chooses which file the VM boots: say why with --reason", row.Code, vm)
	}
	accepts := moveAccepts(ctx)
	unlock, err := s.lockVMForStart(ctx, vm)
	if err != nil {
		return nil, err
	}
	defer unlock()
	cur, ev, open, everr := health.OpenMoveCondition(ctx, s.db, vm)
	if everr != nil && !open {
		return nil, status.Errorf(codes.Unavailable, "read the %s condition of vm/%s: %v", row.Code, vm, everr)
	}
	if !open {
		return nil, status.Errorf(codes.NotFound, "no open condition %s on vm/%s: it was resolved meanwhile", row.Code, vm)
	}
	row = cur
	for _, m := range ev.Moves {
		if health.MoveInFlight(vm, m.Disk) {
			return nil, status.Errorf(codes.Unavailable, "a volume move of vm/%s's disk %s is in progress on %s; retry once it ends", vm, m.Disk, s.hostName)
		}
	}
	holder := ev.Host
	why := ""
	var handDisks []string
	switch {
	case everr != nil:
		if handDisks, err = s.unreadableMoveGate(ctx, vm, row.Code); err != nil {
			return nil, err
		}
		why = "its evidence is unreadable"
	case holder == s.hostName:
		why = "this host holds the record"
	default:
		h, provedOff, err := corrosion.SharedDiskOwnerProvedOff(ctx, s.db, holder)
		if ok, whyNot := corrosion.SharedDiskOwnerVerdict(holder, h, provedOff, err); !ok {
			return nil, status.Errorf(codes.FailedPrecondition,
				"refusing to resolve %s on vm/%s: %s holds the move's record, and %s. It settles the move itself: start the "+
					"VM or retry `lv move-volume` there, or run this command against it (LV_HOST=%s), also once it has "+
					"rejoined after the VM failed over. From another host it is accepted only once %s is proven powered off "+
					"(an IPMI fence, or `lv host fence-confirm %s`)",
				row.Code, vm, holder, whyNot, holder, holder, holder)
		}
		why = holder + " is proven powered off"
	}
	var changes []moveRowChange
	var forks []string
	if everr != nil {
		if len(accepts) > 0 {
			return nil, status.Errorf(codes.FailedPrecondition, "--accept: the evidence of vm/%s cannot be read to match %s against", vm, strings.Join(accepts, ", "))
		}
	} else if changes, forks, err = s.planMoveHandResolve(ctx, vm, holder, ev, accepts, moveForce(ctx)); err != nil {
		return nil, err
	}

	var moves []string
	for _, m := range ev.Moves {
		d := fmt.Sprintf("%s: %s → %s (live=%v pivoted=%v catch_up=%v)", m.Disk, m.Src, m.Dst, m.Live, m.Pivoted, m.CatchUp)
		if m.Error != "" {
			d += ", error: " + m.Error
		}
		moves = append(moves, d)
	}
	for _, c := range changes {
		why += fmt.Sprintf("; the disk row of %s now names %s (was %s)", c.m.Disk, c.after.Path, c.cur.Path)
	}
	for _, f := range forks {
		why += "; forked history: " + f
	}
	target := strings.Join([]string{row.Evaluator, row.Code, row.SubjectKind, vm}, "/")
	detail := fmt.Sprintf("resolved by hand on %s (was %s; %s; moves %s): %s", s.hostName, row.Lifecycle, why, strings.Join(moves, "; "), reason)

	if len(changes) > 0 {
		// Rows replicate as they are written: a process that dies before the
		// resolution below still leaves this record of them.
		s.audit(ctx, "health.condition.resolve", target, detail+"; writing the disk rows", "pending")
	}
	applied, err := s.applyMoveRowChanges(ctx, vm, changes)
	if err != nil {
		s.audit(ctx, "health.condition.resolve", target, detail+"; not resolved: "+err.Error(), "failed")
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen = corrosion.ConditionResolved, now, now
	row.ObserveCount, row.CleanCount = 0, 0
	row.Reporter = s.hostName
	if everr == nil {
		ev.Hand = true
	} else {
		// Nothing in it can be matched against: mark the disks, so a holder
		// returning with a record of a move begun before now drops it.
		ev = health.MoveUnresolvedEvidence{Hand: true, HandDisks: handDisks, HandAt: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	if b, merr := json.Marshal(ev); merr == nil {
		row.Evidence = string(b)
	}
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		undone := s.undoMoveRowChanges(ctx, applied)
		s.audit(ctx, "health.condition.resolve", target, detail+"; not resolved, recording it failed: "+err.Error()+undone, "failed")
		return nil, status.Errorf(codes.Unavailable, "record the resolution: %v%s", err, undone)
	}
	for _, c := range applied {
		if c.after.Path == c.m.Dst {
			if info, ierr := qcow2.Info(c.after.Path); ierr == nil && info.BackingFile == "" {
				if cerr := corrosion.ClearDiskBacking(ctx, s.db, vm, c.m.Disk, c.after.Path); cerr != nil {
					slog.Warn("health resolve: clearing the accepted copy's backing record failed", "vm", vm, "disk", c.m.Disk, "error", cerr)
				}
			}
		}
	}
	if holder == s.hostName || everr != nil {
		if err := health.ClearUnresolvedMovesOf(s.dataDir, vm); err != nil {
			slog.Warn("health resolve: removing this host's move records failed; the next start drops them", "vm", vm, "error", err)
			detail += "; this host's records could not be removed (" + err.Error() + ")"
		}
	}
	for _, f := range forks {
		slog.Warn("health resolve: a forked move history was resolved by hand; the other file is kept on disk", "vm", vm, "detail", f)
		s.audit(ctx, "health.condition.hand_diverged", target, "resolved by hand on "+s.hostName+": "+f+": "+reason, "ok")
	}
	s.audit(ctx, "health.condition.resolve", target, detail, "ok")
	s.publish("ha.condition.resolved", row.Code+":"+row.SubjectKind+"/"+vm, detail)
	s.notify(ctx, notify.Notification{
		Kind: notifyKindForCondition(row.Code), Severity: notify.SevInfo, Subject: vm, Detail: detail,
	})
	return &pb.ResolveHealthConditionResponse{Condition: healthConditionToPB(row)}, nil
}

// unreadableMoveGate admits a hand resolution of a condition whose evidence
// cannot be read, so the host holding the move is not known: only on the VM's
// owner, with its domain not active (or the VM gone), and with its persistent
// config, which `lv start` boots, naming each disk row's file. The disk rows
// are kept. It returns the VM's disks, which the resolution marks.
func (s *Server) unreadableMoveGate(ctx context.Context, vm, code string) ([]string, error) {
	rec, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read vm/%s: %v", vm, err)
	}
	if rec == nil {
		return nil, nil
	}
	if rec.HostName != s.hostName {
		return nil, status.Errorf(codes.FailedPrecondition,
			"refusing to resolve %s on vm/%s: its evidence cannot be read, so which host holds the move is not known; "+
				"run this against the VM's owner %s (LV_HOST=%s) with its domain shut off", code, vm, rec.HostName, rec.HostName)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read vm/%s's disk rows: %v", vm, err)
	}
	names := make([]string, 0, len(disks))
	for _, d := range disks {
		names = append(names, d.DiskName)
	}
	if s.virt == nil {
		return names, nil
	}
	active, aerr := s.virt.DomainIsActive(vm)
	switch {
	case aerr != nil && libvirt.IsNoDomain(aerr):
		return names, nil
	case aerr != nil:
		return nil, status.Errorf(codes.Unavailable, "read the state of vm/%s's domain: %v", vm, aerr)
	case active:
		return nil, status.Errorf(codes.FailedPrecondition,
			"refusing to resolve %s on vm/%s: its evidence cannot be read, and its domain is active on %s; `lv stop %s` first",
			code, vm, s.hostName, vm)
	}
	x, xerr := s.virt.DumpXMLInactive(vm)
	if xerr != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"refusing to resolve %s on vm/%s: its evidence cannot be read, and its persistent config cannot be read (%v); "+
				"make it readable (virsh dumpxml --inactive %s) and retry", code, vm, xerr, vm)
	}
	for _, d := range disks {
		if d.Path == "" {
			continue
		}
		// The config names the row's file when the cutover's own rule
		// rewrites it (Src), not when it names anything else (an error).
		n, nerr := health.MovedDiskNames(x, health.UnresolvedMove{VM: vm, Disk: d.DiskName, TargetDev: d.TargetDev,
			Src: d.Path, Dst: d.Path + ".not-the-disk-row"})
		if nerr != nil || n != d.Path {
			return nil, status.Errorf(codes.FailedPrecondition,
				"refusing to resolve %s on vm/%s: its evidence cannot be read, and its persistent config on %s does not name "+
					"%s, the file the disk row of %s names; `lv start` boots the config and a rebuild boots the row, so they "+
					"must name the same file. Point the config at it (virsh edit %s) and retry", code, vm, s.hostName, d.Path, d.DiskName, vm)
		}
	}
	return names, nil
}

// planMoveHandResolve decides, per move ev lists, the file vm's disk row is
// left on, and returns the rows to change. A move whose row names neither of
// its files no longer describes the disk and is left alone (an --accept for
// it is refused). Otherwise the file kept is the --accept for that disk, or
// the row's, and the resolution is refused when:
//   - the move proves another file holds every write (pivoted or caught up:
//     the copy), so the one kept lacks some, unless the history forked after
//     it: the VM changed hands and may have run on the source since, and the
//     source is accepted (forkedHistory; a row on the copy is then pointed
//     at the source);
//   - on the VM's owner with its domain defined: the persistent config (what
//     `lv start` boots) does not name the file kept; the domain is active and
//     the row would change; or, on the holder that owns the VM, the domain is
//     active at all;
//   - no --accept names the file of a move the row does not settle (a live
//     move with no pivot recorded: nothing in the cluster knows which file the
//     guest wrote last), except the holder that owns the VM whose config and
//     row name the source: the cutover names the copy in the config before the
//     pivot and never the source after one;
//   - the row would change anywhere but on the owner (the holder cannot read
//     the owner's domain), or the owner does not read the accepted file as
//     the holder does: here, a regular file on the host that is owner and
//     holder; otherwise a file on a shared pool both define alike.
func (s *Server) planMoveHandResolve(ctx context.Context, vm, holder string, ev health.MoveUnresolvedEvidence, accepts []string, force bool) ([]moveRowChange, []string, error) {
	chosen := map[string]string{}
	for _, a := range accepts {
		var hit *health.UnresolvedMove
		for i := range ev.Moves {
			if ev.Moves[i].Src == a || ev.Moves[i].Dst == a {
				hit = &ev.Moves[i]
			}
		}
		if hit == nil {
			return nil, nil, status.Errorf(codes.InvalidArgument, "--accept %s: it is neither file of a move recorded for vm/%s", a, vm)
		}
		if prev, ok := chosen[hit.Disk]; ok && prev != a {
			return nil, nil, status.Errorf(codes.InvalidArgument, "--accept %s and --accept %s: both name disk %s of vm/%s; name the one file to keep", prev, a, hit.Disk, vm)
		}
		chosen[hit.Disk] = a
	}
	rec, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "read vm/%s: %v", vm, err)
	}
	if rec == nil {
		if len(accepts) > 0 {
			return nil, nil, status.Errorf(codes.NotFound, "--accept: vm %q not found", vm)
		}
		return nil, nil, nil
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "read vm/%s's disk rows: %v", vm, err)
	}
	here, owner := s.hostName, rec.HostName
	// On the VM's owner, its domain here is what a start boots: read whether
	// it is active and what its persistent config names.
	xml, config, active, noDomain := "", false, false, false
	if owner == here && s.virt != nil {
		act, aerr := s.virt.DomainIsActive(vm)
		switch {
		case aerr != nil && libvirt.IsNoDomain(aerr):
			// No domain: a start rebuilds it from the disk rows.
			noDomain = true
		case aerr != nil:
			return nil, nil, status.Errorf(codes.Unavailable, "read the state of vm/%s's domain: %v", vm, aerr)
		case act && holder == here:
			return nil, nil, status.Errorf(codes.FailedPrecondition,
				"refusing to resolve %s on vm/%s: its domain is active on %s. A hand resolution is accepted here only while "+
					"it is shut off, so the file it was writing is the file it boots: with a block-copy mirror still running, "+
					"finish it first (`virsh blockjob %s <disk> --pivot` or `--abort`, as a start's refusal says), then `lv stop %s` and retry",
				health.MoveUnresolvedCode, vm, here, vm, vm)
		default:
			active = act
			x, xerr := s.virt.DumpXMLInactive(vm)
			if xerr != nil {
				return nil, nil, status.Errorf(codes.FailedPrecondition,
					"refusing to resolve %s on vm/%s: its persistent config cannot be read (%v); make it readable "+
						"(virsh dumpxml --inactive %s) and retry", health.MoveUnresolvedCode, vm, xerr, vm)
			}
			xml, config = x, true
		}
	}
	var out []moveRowChange
	var forks []string
	for _, m := range ev.Moves {
		var row *corrosion.DiskRecord
		for i := range disks {
			if disks[i].DiskName == m.Disk {
				row = &disks[i]
			}
		}
		a, accepted := chosen[m.Disk]
		if row == nil || (row.Path != m.Src && row.Path != m.Dst) {
			if accepted {
				now := "is gone"
				if row != nil {
					now = "names " + row.Path
				}
				return nil, nil, status.Errorf(codes.FailedPrecondition,
					"--accept %s: the disk row of vm/%s's disk %s %s, neither file of the move; it is not changed", a, vm, m.Disk, now)
			}
			continue
		}
		keep := row.Path
		if accepted {
			keep = a
		}
		path, proven := health.MoveCompleteFile(m)
		if proven && path != "" && keep != path {
			f, ferr := forkedHistory(here, owner, holder, rec, m, row.Path, keep, path, accepted, config, noDomain, force, xml)
			if ferr != nil {
				return nil, nil, ferr
			}
			if f == "" {
				return nil, nil, status.Errorf(codes.FailedPrecondition,
					"refusing to resolve %s on vm/%s: the guest was moved onto %s (or the config named it before the move), so "+
						"%s lacks the writes made since; for disk %s only `--accept %s` is accepted",
					health.MoveUnresolvedCode, vm, m.Dst, keep, m.Disk, m.Dst)
			}
			// The writes made since the VM changed hands are in keep; the
			// other file holds the holder's and stays on disk. A row on the
			// copy (a replica that received the holder's commit) is pointed
			// at keep below, under the same gates as any other change.
			forks = append(forks, f)
			if keep == row.Path {
				continue
			}
		}
		if active && keep != row.Path {
			return nil, nil, status.Errorf(codes.FailedPrecondition,
				"refusing to resolve %s on vm/%s: this would point the disk row of %s at %s while its domain is active on %s, "+
					"writing the file it opened. Stop it first (`lv stop %s`), or pass --accept %s to keep the file the row names",
				health.MoveUnresolvedCode, vm, m.Disk, keep, here, vm, row.Path)
		}
		names := ""
		if config {
			n, nerr := health.MovedDiskNames(xml, m)
			if nerr != nil {
				return nil, nil, status.Errorf(codes.FailedPrecondition,
					"refusing to resolve %s on vm/%s: its persistent config names neither %s nor %s for disk %s (%v); name "+
						"the file to keep in it (virsh edit %s) and retry", health.MoveUnresolvedCode, vm, m.Src, m.Dst, m.Disk, nerr, vm)
			}
			if names = n; names != keep {
				return nil, nil, status.Errorf(codes.FailedPrecondition,
					"refusing to resolve %s on vm/%s: its persistent config on %s names %s for disk %s, and this would leave "+
						"the disk row on %s; `lv start` boots the config and a rebuild boots the row, so they must name the "+
						"same file. Pass --accept %s to keep the file the config names, or point the config at %s (virsh edit %s) and retry",
					health.MoveUnresolvedCode, vm, here, names, m.Disk, keep, names, keep, vm)
			}
		}
		// A move the row does not settle needs --accept. The one exception
		// is the holder's own config naming the source: the cutover redefines
		// it to the copy before the pivot and never back after one, so it
		// proves no pivot happened. A config naming the copy proves only that
		// the define ran.
		configProvesSrc := config && holder == here && names == m.Src && keep == m.Src
		if !accepted && !(proven && (path == "" || row.Path == path)) && !configProvesSrc {
			return nil, nil, status.Errorf(codes.FailedPrecondition,
				"refusing to resolve %s on vm/%s: the live move of disk %s on %s recorded no pivot, so whether the guest's "+
					"last writes are in %s or %s is not known, and the disk row (%s) is no evidence of it, nor is a persistent "+
					"config naming the copy (the move names it before the pivot). Name the file to keep with --accept, once "+
					"for each such disk: nothing in the cluster records it; judge it from %s's persistent config, or from the "+
					"two files themselves (the later modification time, `qemu-img compare %s %s`)",
				health.MoveUnresolvedCode, vm, m.Disk, holder, m.Src, m.Dst, row.Path, holder, m.Src, m.Dst)
		}
		if keep == row.Path {
			continue
		}
		typ, pool := m.SrcType, m.SrcPool
		if keep == m.Dst {
			typ, pool = m.DstType, m.DstPool
		}
		var reads bool
		switch {
		case here == owner && here == holder:
			fi, lerr := os.Lstat(keep)
			reads = lerr == nil && fi.Mode().IsRegular()
		case here == owner:
			reads = health.SharedPoolHolds(ctx, s.db, s.dataDir, here, holder, pool, typ, keep)
		case here == holder:
			// The owner's domain cannot be read from here: its row stays.
			return nil, nil, status.Errorf(codes.FailedPrecondition,
				"refusing to resolve %s on vm/%s: %s holds the move's record, but the VM is on its owner %s, whose domain this host "+
					"cannot read, so the disk row of %s is not pointed at %s from here. Keep the file the row names "+
					"(--accept %s), or point the row on the owner (LV_HOST=%s), once %s is %s, with its domain shut off",
				health.MoveUnresolvedCode, vm, here, owner, m.Disk, keep, row.Path, owner, here, "proven powered off (an IPMI fence, or `lv host fence-confirm "+here+"`)")
		default:
			return nil, nil, status.Errorf(codes.FailedPrecondition,
				"--accept points the disk row at a file: run it on the VM's owner %s (LV_HOST=%s), or on the move's holder %s", owner, owner, holder)
		}
		if !reads {
			return nil, nil, status.Errorf(codes.FailedPrecondition, "--accept %s: %s does not read that file as %s does (it is not "+
				"here as a regular file, or not on a mounted shared pool %s and %s define alike)", keep, here, holder, here, holder)
		}
		after := *row
		after.HostName, after.Path, after.StorageType, after.StorageVolume = owner, keep, typ, pool
		if keep == m.Src && (m.SrcBackingDisk != "" || m.SrcBackingImage != "") {
			// The commit cleared the backing record for the flattened copy:
			// the source is still the overlay it was.
			after.BackingDisk, after.BackingImage = m.SrcBackingDisk, m.SrcBackingImage
		}
		out = append(out, moveRowChange{m: m, cur: *row, after: after})
	}
	return out, forks, nil
}

// forkedHistory describes the forked history of move m that a hand resolution
// keeps keep of ("" when it is not one): after the holder pivoted the guest
// onto other, the VM changed hands (health.OwnerChangedSince) and was run on
// keep, the source: here, on the file its disk row names, or on a host whose
// row named the source while this host's names the copy (a replica that
// received the holder's commit). Taken only with --accept of keep, on the
// owner that does not hold the move (the holder is proven powered off), whose
// persistent config, which `lv start` boots, names keep, or which has no
// domain of the VM (a start rebuilds it from the row). It is refused when
// other was modified after keep, which shows nothing was written to keep
// since the holder's last write to other, unless force. other is never
// deleted; a row naming other is pointed at keep by the caller.
func forkedHistory(here, owner, holder string, rec *corrosion.VMRecord, m health.UnresolvedMove, rowPath, keep, other string, accepted, config, noDomain, force bool, xml string) (string, error) {
	if !accepted || (!config && !noDomain) || here != owner || here == holder || !health.OwnerChangedSince(rec, m) {
		return "", nil
	}
	if config {
		if names, err := health.MovedDiskNames(xml, m); err != nil || names != keep {
			return "", nil
		}
	}
	facts := health.MoveFileFacts(keep) + "; " + health.MoveFileFacts(other)
	forced := ""
	if health.ModifiedLater(other, keep) {
		if !force {
			return "", status.Errorf(codes.FailedPrecondition,
				"refusing to resolve %s on vm/%s with --accept %s: %s was modified after it (%s). After the pivot %s wrote "+
					"only %s, so nothing was written to %s here since %s's last write, and keeping it would discard %s's "+
					"writes after the pivot. Check whether the VM ran here since it changed hands (`lv audit ls --target "+
					"%s --action vm.start`); keep %s with `--accept %s`, or, if %s does hold writes to keep, pass --force "+
					"with --reason saying why",
				health.MoveUnresolvedCode, rec.Name, keep, other, facts, holder, other, keep, holder, holder,
				rec.Name, other, other, keep)
		}
		forced = fmt.Sprintf("; taken with --force although %s was modified after it", other)
	}
	ran := fmt.Sprintf("which %s has run", here)
	if keep != rowPath {
		ran = fmt.Sprintf("on which the VM may have run elsewhere (the disk row here named %s)", rowPath)
	}
	return fmt.Sprintf("disk %s keeps %s, %s since the VM changed hands after the move began (owner %s at "+
		"generation %d then, %s at %d now); %s, onto which %s pivoted the guest, holds its writes after the pivot and is "+
		"kept on disk (%s)%s", m.Disk, keep, ran, m.Owner, m.OwnerEpoch, rec.HostName, rec.OwnerEpoch, other, holder,
		facts, forced), nil
}

// applyMoveRowChanges writes changes, each only while its row is still the
// one read. On a failure it undoes those it wrote and says so in the error.
func (s *Server) applyMoveRowChanges(ctx context.Context, vm string, changes []moveRowChange) ([]moveRowChange, error) {
	var applied []moveRowChange
	for _, c := range changes {
		ok, err := corrosion.ReplaceDiskRowIfStill(ctx, s.db, c.cur, c.after)
		if err == nil && !ok {
			return nil, status.Errorf(codes.Aborted, "the disk row of vm/%s's disk %s changed while it was being resolved; it is "+
				"not written%s. Retry", vm, c.m.Disk, s.undoMoveRowChanges(ctx, applied))
		}
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "point the disk row of vm/%s's disk %s at %s: %v%s",
				vm, c.m.Disk, c.after.Path, err, s.undoMoveRowChanges(ctx, applied))
		}
		applied = append(applied, c)
	}
	return applied, nil
}

// undoMoveRowChanges points rows written back at what they named, each only
// while it is still what was written, and describes the outcome.
func (s *Server) undoMoveRowChanges(ctx context.Context, applied []moveRowChange) string {
	out := ""
	for _, c := range applied {
		ok, err := corrosion.ReplaceDiskRowIfStill(ctx, s.db, c.after, c.cur)
		switch {
		case err != nil:
			out += fmt.Sprintf("; the disk row of %s could not be pointed back at %s (%v): it names %s", c.m.Disk, c.cur.Path, err, c.after.Path)
		case !ok:
			out += fmt.Sprintf("; the disk row of %s changed again and was not pointed back at %s", c.m.Disk, c.cur.Path)
		default:
			out += fmt.Sprintf("; the disk row of %s was pointed back at %s", c.m.Disk, c.cur.Path)
		}
	}
	return out
}
