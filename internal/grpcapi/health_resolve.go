package grpcapi

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/notify"
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
// --accept <path>` for vm.move_unresolved: the file of the move the operator
// accepts as the VM's data, which the disk row is pointed at. Carried as
// metadata so the request message is unchanged.
const MoveAcceptMDKey = "x-litevirt-move-accept"

// resolveMoveConditionByHand resolves an unresolved volume move
// (vm.move_unresolved) on an admin's word, with a reason. The host holding the
// move's record settles it itself when it can, so the hand resolution is
// refused unless it runs on that host (its records are then removed too) or
// that host is proven powered off (corrosion.SharedDiskOwnerProvedOff: fenced
// or removed over a proof-grade fence of its last life). It proves nothing
// about which file holds the VM's data: without --accept a start boots the
// file the disk row names; with it, the row is first pointed at the accepted
// file, one of the move's two, on the VM's owner and only where that host
// reads the same file.
func (s *Server) resolveMoveConditionByHand(ctx context.Context, req *pb.ResolveHealthConditionRequest, row corrosion.HealthCondition) (*pb.ResolveHealthConditionResponse, error) {
	vm := row.SubjectID
	reason := strings.TrimSpace(req.GetReason())
	if reason == "" {
		return nil, status.Errorf(codes.InvalidArgument,
			"resolving %s on vm/%s chooses which file the VM boots: say why with --reason", row.Code, vm)
	}
	accept := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(MoveAcceptMDKey); len(v) > 0 {
			accept = strings.TrimSpace(v[0])
		}
	}
	_, ev, open, everr := health.OpenMoveCondition(ctx, s.db, vm)
	if everr != nil && !open {
		return nil, status.Errorf(codes.Unavailable, "read the %s condition of vm/%s: %v", row.Code, vm, everr)
	}
	holder := ev.Host
	why := ""
	switch {
	case everr != nil:
		why = "its evidence is unreadable"
	case holder == s.hostName:
		why = "this host holds the record"
	default:
		h, provedOff, err := corrosion.SharedDiskOwnerProvedOff(ctx, s.db, holder)
		if ok, whyNot := corrosion.SharedDiskOwnerVerdict(holder, h, provedOff, err); !ok {
			return nil, status.Errorf(codes.FailedPrecondition,
				"refusing to resolve %s on vm/%s: %s holds the move's record, and %s. It settles the move itself: start the "+
					"VM or retry `lv move-volume` there, or run this command against it (LV_HOST=%s). From another host it "+
					"is accepted only once %s is proven powered off (`lv host fence-confirm %s`)",
				row.Code, vm, holder, whyNot, holder, holder, holder)
		}
		why = holder + " is proven powered off"
	}
	if accept != "" {
		if everr != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "--accept: the evidence of vm/%s cannot be read to match %s against", vm, accept)
		}
		if err := s.acceptMovedFile(ctx, vm, holder, ev, accept); err != nil {
			return nil, err
		}
		why += "; the disk row now names " + accept
	}
	if holder == s.hostName || everr != nil {
		if err := health.ClearUnresolvedMovesOf(s.dataDir, vm); err != nil {
			return nil, status.Errorf(codes.Internal, "remove this host's records of vm/%s: %v", vm, err)
		}
	}
	prior := row.Lifecycle
	now := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen = corrosion.ConditionResolved, now, now
	row.ObserveCount, row.CleanCount = 0, 0
	row.Reporter = s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.Unavailable, "record the resolution: %v", err)
	}
	var moves []string
	for _, m := range ev.Moves {
		d := fmt.Sprintf("%s: %s → %s (live=%v pivoted=%v)", m.Disk, m.Src, m.Dst, m.Live, m.Pivoted)
		if m.Error != "" {
			d += ", error: " + m.Error
		}
		moves = append(moves, d)
	}
	target := strings.Join([]string{row.Evaluator, row.Code, row.SubjectKind, vm}, "/")
	detail := fmt.Sprintf("resolved by hand on %s (was %s; %s; moves %s): %s", s.hostName, prior, why, strings.Join(moves, "; "), reason)
	s.audit(ctx, "health.condition.resolve", target, detail, "ok")
	s.publish("ha.condition.resolved", row.Code+":"+row.SubjectKind+"/"+vm, detail)
	s.notify(ctx, notify.Notification{
		Kind: notifyKindForCondition(row.Code), Severity: notify.SevInfo, Subject: vm, Detail: detail,
	})
	return &pb.ResolveHealthConditionResponse{Condition: healthConditionToPB(row)}, nil
}

// acceptMovedFile points vm's disk row at accept, one of a recorded move's two
// files, on the VM's owner, where that host reads the same file the move's
// host wrote: its own file on the holder, a file on a shared pool both define
// alike elsewhere.
func (s *Server) acceptMovedFile(ctx context.Context, vm, holder string, ev health.MoveUnresolvedEvidence, accept string) error {
	var m *health.UnresolvedMove
	for i := range ev.Moves {
		if ev.Moves[i].Src == accept || ev.Moves[i].Dst == accept {
			m = &ev.Moves[i]
		}
	}
	if m == nil {
		return status.Errorf(codes.InvalidArgument, "--accept %s: it is neither file of a move recorded for vm/%s", accept, vm)
	}
	rec, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read vm/%s: %v", vm, err)
	}
	if rec == nil {
		return status.Errorf(codes.NotFound, "vm %q not found", vm)
	}
	if rec.HostName != s.hostName {
		return status.Errorf(codes.FailedPrecondition, "--accept points the disk row at a file: run it on the VM's owner %s (LV_HOST=%s)", rec.HostName, rec.HostName)
	}
	typ, pool := m.SrcType, m.SrcPool
	if accept == m.Dst {
		typ, pool = m.DstType, m.DstPool
	}
	reads := false
	if holder == s.hostName {
		fi, lerr := os.Lstat(accept)
		reads = lerr == nil && fi.Mode().IsRegular()
	} else {
		reads = health.SharedPoolHolds(ctx, s.db, s.dataDir, s.hostName, holder, pool, typ, accept)
	}
	if !reads {
		return status.Errorf(codes.FailedPrecondition, "--accept %s: %s does not read that file (it is not here as a regular file, "+
			"or not on a shared pool %s and %s define alike)", accept, s.hostName, s.hostName, holder)
	}
	if err := corrosion.UpdateDiskPlacement(ctx, s.db, vm, m.Disk, s.hostName, accept, typ, pool); err != nil {
		return status.Errorf(codes.Unavailable, "point the disk row of vm/%s at %s: %v", vm, accept, err)
	}
	return nil
}
