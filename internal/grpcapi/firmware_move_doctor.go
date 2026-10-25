package grpcapi

// `lv doctor firmware-move <vm>` (spec §17 D-5): an operator's view and
// resolution of a parked live firmware move. Without an action it shows each
// host's records of the move — the source marker, the target hold, owed
// discards, quarantines, retained bundles — with the VM's domain on that host
// and every hash and path. With one it resolves the move by the D-5 action
// table, on the host whose record it acts on: the source, when a marker names
// the VM there; the target, when only a hold is left.
//
// Every action keeps one copy of the VM at every moment: the target's copy is
// discarded (quarantined) before the source's guest runs again, and the
// source's state is kept until the target's copy is the owner. An action
// that would roll the TPM back to a copy that may be older needs
// --acknowledge-rollback (I6). Each one is audited (vm.firmware-move).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/safename"
)

// fwDoctorVerb is the RBAC verb and the audit action of the doctor.
const fwDoctorVerb = "vm.firmware-move"

// Timing of the doctor; vars so tests can shorten them.
var (
	// fwDoctorStopWait bounds how long --stop-target waits for the held guest
	// to shut off.
	fwDoctorStopWait = 2 * time.Minute
	fwDoctorStopPoll = 500 * time.Millisecond
	// fwDoctorReadTimeout bounds one host's answer to a read of its records;
	// fwDoctorActTimeout one host's action.
	fwDoctorReadTimeout = 30 * time.Second
	fwDoctorActTimeout  = 10 * time.Minute
)

// fwDoctorFlag names an action as the operator spells it.
var fwDoctorFlag = map[pb.FirmwareMoveDoctorAction]string{
	pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_UNSPECIFIED:          "show",
	pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_TARGET:        "--accept-target",
	pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE:        "--accept-source",
	pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ADOPT_TARGET_COPY:    "--adopt-target-copy",
	pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET:       "--discard-target",
	pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_CONFIRM_TARGET_NVRAM: "--confirm-target-nvram",
	pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_PUSH_SOURCE_NVRAM:    "--push-source-nvram",
	pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_REVERIFY:             "--reverify",
	pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_RESOLVE_CONDITION:    "--resolve",
}

func fwDoctorFlagOf(a pb.FirmwareMoveDoctorAction) string {
	if f, ok := fwDoctorFlag[a]; ok {
		return f
	}
	return a.String()
}

// FirmwareMoveDoctor shows or resolves vm's live firmware move. Admin only
// (vm.firmware-move on the cluster root); every action is audited under the
// operator's name, also when another node carries it out.
func (s *Server) FirmwareMoveDoctor(ctx context.Context, req *pb.FirmwareMoveDoctorRequest) (*pb.FirmwareMoveDoctorResponse, error) {
	vm := req.GetVmName()
	if err := safename.ValidateVMName(vm); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if _, ok := fwDoctorFlag[req.GetAction()]; !ok {
		return nil, status.Errorf(codes.InvalidArgument, "firmware-move action %v is not one this host knows", req.GetAction())
	}
	if err := s.RequirePerm(ctx, "/", fwDoctorVerb, "admin"); err != nil {
		s.audit(ctx, fwDoctorVerb, vm, "permission denied", "denied")
		return nil, err
	}
	actor := s.repairActor(ctx)
	action := req.GetAction()
	switch host := req.GetHost(); {
	case host != "" && host != s.hostName:
		return s.forwardFirmwareMoveDoctor(ctx, host, req, actor)
	case host == s.hostName && action == pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_UNSPECIFIED:
		return &pb.FirmwareMoveDoctorResponse{Hosts: []*pb.FirmwareMoveHostRecords{s.localFirmwareMoveRecords(ctx, vm)}}, nil
	case host == s.hostName:
		outcome, err := s.firmwareMoveDoctorAct(ctx, req, actor)
		s.auditFirmwareMoveDoctor(ctx, actor, req, outcome, err)
		_ = grpc.SetTrailer(ctx, metadata.Pairs(fwDoctorAuditedMD, "1"))
		if err != nil {
			return nil, err
		}
		return &pb.FirmwareMoveDoctorResponse{Outcome: outcome}, nil
	}

	report := s.gatherFirmwareMoveRecords(ctx, vm, actor)
	switch action {
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_UNSPECIFIED:
		return report, nil
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_RESOLVE_CONDITION:
		outcome, err := s.resolveFirmwareMoveConditionForOperator(ctx, req)
		s.auditFirmwareMoveDoctor(ctx, actor, req, outcome, err)
		if err != nil {
			return nil, err
		}
		report.Outcome = outcome
		return report, nil
	}
	exec, err := firmwareMoveDoctorHost(report, vm, action)
	if err != nil {
		s.auditFirmwareMoveDoctor(ctx, actor, req, "", err)
		return nil, err
	}
	fwd := &pb.FirmwareMoveDoctorRequest{VmName: vm, Action: action, AcknowledgeRollback: req.GetAcknowledgeRollback(),
		StopTarget: req.GetStopTarget(), AcceptNvramHash: req.GetAcceptNvramHash(), Host: exec}
	var outcome string
	if exec == s.hostName {
		outcome, err = s.firmwareMoveDoctorAct(ctx, fwd, actor)
		s.auditFirmwareMoveDoctor(ctx, actor, fwd, outcome, err)
	} else {
		var resp *pb.FirmwareMoveDoctorResponse
		var audited bool
		resp, audited, err = s.forwardFirmwareMoveDoctorAudited(ctx, exec, fwd, actor)
		outcome = resp.GetOutcome()
		if err != nil && !audited {
			// The host that acts did not audit it (unreachable, a deadline,
			// an older build): audited here.
			s.auditFirmwareMoveDoctor(ctx, actor, fwd, "", err)
		}
	}
	if err != nil {
		return nil, err
	}
	after := s.gatherFirmwareMoveRecords(ctx, vm, actor)
	after.Outcome = outcome
	return after, nil
}

// auditFirmwareMoveDoctor records one action, on the host that acted.
func (s *Server) auditFirmwareMoveDoctor(ctx context.Context, actor string, req *pb.FirmwareMoveDoctorRequest, outcome string, err error) {
	detail, result := fmt.Sprintf("%s on %s: %s", fwDoctorFlagOf(req.GetAction()), s.hostName, outcome), "ok"
	if err != nil {
		detail, result = fmt.Sprintf("%s on %s refused: %s", fwDoctorFlagOf(req.GetAction()), s.hostName, status.Convert(err).Message()), "error"
	}
	if req.GetAcknowledgeRollback() {
		detail += " (--acknowledge-rollback)"
	}
	s.auditAs(ctx, actor, fwDoctorVerb, req.GetVmName(), detail, result)
}

// forwardFirmwareMoveDoctor carries req to host, with the operator's name.
func (s *Server) forwardFirmwareMoveDoctor(ctx context.Context, host string, req *pb.FirmwareMoveDoctorRequest, actor string) (*pb.FirmwareMoveDoctorResponse, error) {
	client, closer, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
	}
	defer closer()
	d := fwDoctorActTimeout
	if req.GetAction() == pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_UNSPECIFIED {
		d = fwDoctorReadTimeout
	}
	cctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor), d)
	defer cancel()
	return client.FirmwareMoveDoctor(cctx, req)
}

// fwDoctorAuditedMD is the trailer a host that acted on a forwarded action
// sets once it audited it.
const fwDoctorAuditedMD = "litevirt-fwdoctor-audited"

// forwardFirmwareMoveDoctorAudited is forwardFirmwareMoveDoctor for an
// action, also saying whether the host that answered audited it.
func (s *Server) forwardFirmwareMoveDoctorAudited(ctx context.Context, host string, req *pb.FirmwareMoveDoctorRequest, actor string) (*pb.FirmwareMoveDoctorResponse, bool, error) {
	client, closer, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, false, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
	}
	defer closer()
	cctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor), fwDoctorActTimeout)
	defer cancel()
	var tr metadata.MD
	resp, err := client.FirmwareMoveDoctor(cctx, req, grpc.Trailer(&tr))
	return resp, len(tr.Get(fwDoctorAuditedMD)) > 0, err
}

// gatherFirmwareMoveRecords reads vm's records on every host in the cluster
// (a removed one excepted): no host's record is taken to be the only one
// (D2-12c re-review: a VM's condition row may name another host's move).
func (s *Server) gatherFirmwareMoveRecords(ctx context.Context, vm, actor string) *pb.FirmwareMoveDoctorResponse {
	resp, _, _ := s.gatherFirmwareMoveRecordsChecked(ctx, vm, actor)
	return resp
}

// gatherFirmwareMoveRecordsChecked is gatherFirmwareMoveRecords that also
// returns, as data rather than text, the names of the hosts that did not
// answer and the error of a host list that could not be read (then no other
// host was asked).
func (s *Server) gatherFirmwareMoveRecordsChecked(ctx context.Context, vm, actor string) (*pb.FirmwareMoveDoctorResponse, []string, error) {
	resp := &pb.FirmwareMoveDoctorResponse{Hosts: []*pb.FirmwareMoveHostRecords{s.localFirmwareMoveRecords(ctx, vm)}}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if hostListHook != nil {
		err = hostListHook(s.hostName, err)
	}
	if err != nil {
		resp.Unreachable = append(resp.Unreachable, fmt.Sprintf("(the host list cannot be read here: %v)", err))
		return resp, nil, err
	}
	var unreachable []string
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, h := range hosts {
		if h.Name == s.hostName || h.State == "removed" {
			continue
		}
		wg.Add(1)
		go func(h corrosion.HostRecord) {
			defer wg.Done()
			r, err := s.forwardFirmwareMoveDoctor(ctx, h.Name, &pb.FirmwareMoveDoctorRequest{VmName: vm, Host: h.Name}, actor)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || len(r.GetHosts()) != 1 {
				resp.Unreachable = append(resp.Unreachable, fmt.Sprintf("%s (%s): %v", h.Name, h.State, err))
				unreachable = append(unreachable, h.Name)
				return
			}
			resp.Hosts = append(resp.Hosts, r.GetHosts()[0])
		}(h)
	}
	wg.Wait()
	sort.Slice(resp.Hosts, func(i, j int) bool { return resp.Hosts[i].GetHost() < resp.Hosts[j].GetHost() })
	sort.Strings(resp.Unreachable)
	sort.Strings(unreachable)
	return resp, unreachable, nil
}

// hostListHook, when set, replaces the host list read's error on the named
// host; test-only.
var hostListHook func(host string, err error) error

// firmwareMoveDoctorHost is the host an action runs on: the one whose marker
// names the VM (the move's source drives every action it has a record for),
// else the one whose hold does.
func firmwareMoveDoctorHost(report *pb.FirmwareMoveDoctorResponse, vm string, action pb.FirmwareMoveDoctorAction) (string, error) {
	var markers, holds, owedTo, leftovers []string
	for _, h := range report.GetHosts() {
		if h.GetLeftoverJson() != "" {
			leftovers = append(leftovers, h.GetHost())
		}
		if h.GetMarkerJson() != "" {
			markers = append(markers, h.GetHost())
		}
		if h.GetHoldJson() != "" {
			holds = append(holds, h.GetHost())
		}
		for _, j := range h.GetOwedDiscards() {
			var o fwmig.OwedDiscard
			if json.Unmarshal([]byte(j), &o) == nil && o.VM == vm && !slices.Contains(owedTo, o.Target) {
				owedTo = append(owedTo, o.Target)
			}
		}
	}
	if len(markers) == 0 && len(holds) == 0 && len(owedTo) == 1 &&
		action == pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET {
		// An owed DISCARD whose target holds no hold any more: the discard
		// of the leftover runs on that target.
		return owedTo[0], nil
	}
	if len(markers) == 0 && len(holds) == 0 && len(leftovers) == 1 {
		// A leftover record with no move left to drive: every action goes to
		// the host that keeps it, which runs --discard-target or the
		// --adopt-target-copy of its own domain, and refuses every other
		// action naming the record.
		return leftovers[0], nil
	}
	switch {
	case len(markers) == 1:
		return markers[0], nil
	case len(markers) > 1:
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: hosts %s each hold a live firmware move marker; resolve the moves one host at a time",
			vm, strings.Join(markers, ", "))
	case len(holds) == 1:
		return holds[0], nil
	case len(holds) > 1:
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: hosts %s each hold a live firmware move hold; resolve them one host at a time",
			vm, strings.Join(holds, ", "))
	}
	unreach := ""
	if u := report.GetUnreachable(); len(u) > 0 {
		unreach = fmt.Sprintf("; these hosts did not answer, and may hold one: %s", strings.Join(u, "; "))
	}
	return "", status.Errorf(codes.FailedPrecondition, "VM %q: no host that answered holds a live firmware move marker or hold%s", vm, unreach)
}

// fwRecordNameRe is <vm>-<attempt> with its suffix, the attempt a UUID, or
// <vm>-reconciled-<unix> (a quarantine the reconciler made of a leftover).
var fwRecordNameRe = regexp.MustCompile(`^(.+)-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|reconciled-[0-9]+)(\.tar)?$`)

// localFirmwareMoveRecords is this host's records of vm, the VM's domain here
// and its state's hashes now. Whatever cannot be read is named in Error.
func (s *Server) localFirmwareMoveRecords(ctx context.Context, vm string) *pb.FirmwareMoveHostRecords {
	out := &pb.FirmwareMoveHostRecords{Host: s.hostName, Hashes: map[string]string{}, Paths: map[string]string{}}
	var errs []string
	recs := s.fwRecords()
	uuid := ""
	if m, ok, err := recs.GetMarker(vm); err != nil {
		errs = append(errs, "marker: "+err.Error())
	} else if ok {
		out.MarkerJson, uuid = fwDoctorJSON(m), m.UUID
	}
	if h, ok, err := recs.GetHold(vm); err != nil {
		errs = append(errs, "hold: "+err.Error())
	} else if ok {
		out.HoldJson = fwDoctorJSON(h)
		if uuid == "" {
			uuid = h.UUID
		}
	}
	if l, ok, err := recs.GetLeftover(vm); err != nil {
		errs = append(errs, "leftover: "+err.Error())
	} else if ok {
		out.LeftoverJson = fwDoctorJSON(l)
		if uuid == "" {
			uuid = l.UUID
		}
	}
	if owed, err := recs.ListOwedDiscards(); err != nil {
		errs = append(errs, "owed discards: "+err.Error())
	} else {
		for _, o := range owed {
			if o.VM == vm {
				out.OwedDiscards = append(out.OwedDiscards, fwDoctorJSON(o))
			}
		}
	}
	dataDir := s.fw().DataDir
	for _, sub := range []struct {
		dir string
		tar bool
		add func(string)
	}{
		{fwmig.QuarantineDir, false, func(p string) { out.Quarantines = append(out.Quarantines, p) }},
		{fwmig.RetainedDir, true, func(p string) { out.Retained = append(out.Retained, p) }},
	} {
		dir := filepath.Join(dataDir, sub.dir)
		ents, err := os.ReadDir(dir)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, sub.dir+": "+err.Error())
			}
			continue
		}
		for _, e := range ents {
			// A stage (<vm>-reconciling-<uuid>, <vm>-restoring-<uuid>) is
			// matched first: the attempt pattern below would read it as a
			// quarantine of VM "<vm>-reconciling".
			if svm, _, _, ok := fwmig.ParseStageName(e.Name()); ok {
				if svm == vm && !sub.tar {
					sub.add(filepath.Join(dir, e.Name()))
				}
				continue
			}
			m := fwRecordNameRe.FindStringSubmatch(e.Name())
			if m != nil && m[1] == vm && (m[3] == ".tar") == sub.tar {
				sub.add(filepath.Join(dir, e.Name()))
			}
		}
	}
	if td, err := s.targetDomain(vm); err != nil {
		errs = append(errs, "domain: "+err.Error())
	} else {
		out.Domain = td
	}
	if uuid == "" && s.db != nil {
		if row, err := corrosion.GetVM(ctx, s.db, vm); err == nil && row != nil {
			uuid = parseFirmwareSpec(row.Spec).UUID
		}
	}
	fw := s.fw()
	if uuid != "" {
		out.Paths["swtpm"] = fw.SwtpmDir(uuid)
		out.Hashes["permall_now"] = fwDoctorHash(fw.PermallSHA256(uuid))
	}
	out.Paths["nvram"] = fw.NvramPath(vm)
	out.Hashes["nvram_now"] = fwDoctorHash(fw.NvramSHA256(vm))
	out.Paths["records"] = dataDir
	out.Error = strings.Join(errs, "; ")
	return out
}

func fwDoctorJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(b)
}

// fwDoctorHash is a hash as the report shows it: absent, or why it cannot be
// read.
func fwDoctorHash(sum string, err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "absent"
	case err != nil:
		return "unreadable: " + err.Error()
	}
	return sum
}

// inspectFirmwareMoveHost reads vm's records on host.
func (s *Server) inspectFirmwareMoveHost(ctx context.Context, host, vm string) (*pb.FirmwareMoveHostRecords, error) {
	if host == s.hostName {
		return s.localFirmwareMoveRecords(ctx, vm), nil
	}
	resp, err := s.forwardFirmwareMoveDoctor(ctx, host, &pb.FirmwareMoveDoctorRequest{VmName: vm, Host: host}, s.hostName)
	if err != nil {
		return nil, err
	}
	if len(resp.GetHosts()) != 1 {
		return nil, fmt.Errorf("%s answered %d host records", host, len(resp.GetHosts()))
	}
	return resp.GetHosts()[0], nil
}

// holdOf is the hold a host's records carry, nil when none.
func holdOf(r *pb.FirmwareMoveHostRecords) *fwmig.Hold {
	if r.GetHoldJson() == "" {
		return nil
	}
	var h fwmig.Hold
	if json.Unmarshal([]byte(r.GetHoldJson()), &h) != nil {
		return nil
	}
	return &h
}

// markerOf is the marker a host's records carry, nil when none.
func markerOf(r *pb.FirmwareMoveHostRecords) *fwmig.Marker {
	if r.GetMarkerJson() == "" {
		return nil
	}
	var m fwmig.Marker
	if json.Unmarshal([]byte(r.GetMarkerJson()), &m) != nil {
		return nil
	}
	return &m
}

// resolveFirmwareMoveConditionForOperator is --resolve: the exit of the two
// conditions no move resolves, firmware_migration_unverified (the move ended
// with the source's copy current) and firmware_migration_quarantine. Nothing
// it names is touched: the quarantine stays on disk.
func (s *Server) resolveFirmwareMoveConditionForOperator(ctx context.Context, req *pb.FirmwareMoveDoctorRequest) (string, error) {
	code := ""
	switch c := strings.TrimPrefix(req.GetResolveCondition(), "firmware_migration_"); c {
	case "unverified":
		code = condFwmigUnverified
	case "quarantine":
		code = condFwmigQuarantine
	default:
		return "", status.Errorf(codes.InvalidArgument, "--resolve takes unverified or quarantine, not %q", req.GetResolveCondition())
	}
	vm := req.GetVmName()
	c, found, err := corrosion.GetHealthCondition(ctx, s.db, firmwareMigrationEvaluator, code, "vm", vm)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "read %s of VM %q: %v", code, vm, err)
	}
	if !found || c.Lifecycle == corrosion.ConditionResolved {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q has no open %s", vm, code)
	}
	if err := s.resolveFirmwareMigrationCondition(ctx, code, vm); err != nil {
		return "", status.Errorf(codes.Internal, "resolve %s of VM %q: %v", code, vm, err)
	}
	return fmt.Sprintf("%s of VM %q resolved; nothing it names was touched (a quarantine stays on disk until removed by hand)", code, vm), nil
}

// ── Acting ──

// firmwareMoveDoctorAct runs an action on this host, under the VM's lock: a
// move, its recovery or another action holding it makes the action wait for
// the next try.
func (s *Server) firmwareMoveDoctorAct(ctx context.Context, req *pb.FirmwareMoveDoctorRequest, actor string) (string, error) {
	vm := req.GetVmName()
	unlock, ok := s.tryLockVM(vm)
	if !ok {
		return "", status.Errorf(codes.Unavailable,
			"VM %q is held on %s by a move, its recovery or another action; run this again in a minute", vm, s.hostName)
	}
	defer unlock()
	ctx = context.WithoutCancel(ctx)
	// An action that settled the VM's row (adopted on the target, returned
	// or stopped here) settles a vm.migration_unresolved failover or a drain
	// raised for it, at once rather than on the next minute's sweep.
	defer s.resolveMigrationUnresolvedIfSettled(ctx, vm)
	recs := s.fwRecords()
	m, ok, err := recs.GetMarker(vm)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: its firmware move marker on %s cannot be read: %v", vm, s.hostName, err)
	}
	if ok {
		return s.doctorSourceAct(ctx, m, req, actor)
	}
	h, ok, err := recs.GetHold(vm)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: its firmware move hold on %s cannot be read: %v", vm, s.hostName, err)
	}
	if ok {
		return s.doctorTargetLocalAct(ctx, h, req, actor)
	}
	if req.GetAction() == pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET {
		return s.doctorDiscardOwedLeftover(ctx, vm, actor, req.GetStopTarget())
	}
	if l, ok, err := recs.GetLeftover(vm); err == nil && ok {
		if req.GetAction() == pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ADOPT_TARGET_COPY {
			return s.doctorAdoptOwnLeftover(ctx, l, actor, req.GetAcknowledgeRollback())
		}
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: %s keeps the leftover of attempt %s from %s under a leftover record; %s does not resolve it: `lv doctor firmware-move %s --discard-target` "+
			"(or --adopt-target-copy, once the VM's row names %s for the leftover's incarnation)",
			vm, s.hostName, l.Attempt, l.Source, fwDoctorFlagOf(req.GetAction()), vm, s.hostName)
	}
	return "", status.Errorf(codes.FailedPrecondition, "VM %q: no live firmware move record names it on %s", vm, s.hostName)
}

// fwProgress is the progress phase of m: its own, or the one it was parked
// from.
func fwProgress(m fwmig.Marker) fwmig.Phase {
	if m.Phase.Parked() {
		return m.ParkedFrom
	}
	return m.Phase
}

// fwPreCutover: the source's copy is still the current one.
func fwPreCutover(p fwmig.Phase) bool {
	return p == fwmig.PhasePreparing || p == fwmig.PhasePrepared || p == fwmig.PhaseMigrating
}

// fwPostCommit: the row names the target.
func fwPostCommit(p fwmig.Phase) bool {
	return p == fwmig.PhaseCommitted || p == fwmig.PhaseReleased || p == fwmig.PhaseCleaning
}

// fwDescribe names m's state for operator text.
func fwDescribe(m fwmig.Marker) string {
	if m.Phase.Parked() {
		return fmt.Sprintf("parked %s (from %s)", m.Phase, m.ParkedFrom)
	}
	return string(m.Phase)
}

// doctorRefuse is the refusal of an action the move's state has no row for.
func doctorRefuse(m fwmig.Marker, action pb.FirmwareMoveDoctorAction, why string) error {
	return status.Errorf(codes.FailedPrecondition, "VM %q: live firmware migration %s to %s is %s; %s does not resolve it: %s",
		m.VM, m.Attempt, m.Target, fwDescribe(m), fwDoctorFlagOf(action), why)
}

// doctorSourceAct is an action on the move's source (the marker's host).
func (s *Server) doctorSourceAct(ctx context.Context, m fwmig.Marker, req *pb.FirmwareMoveDoctorRequest, actor string) (string, error) {
	switch a := req.GetAction(); a {
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_TARGET:
		return s.doctorAcceptTarget(ctx, m)
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_REVERIFY:
		return s.doctorReverify(ctx, m)
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ADOPT_TARGET_COPY:
		return s.doctorAdopt(ctx, m, actor)
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE:
		return s.doctorAcceptSource(ctx, m, req)
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET:
		return s.doctorDiscardTarget(ctx, m, req)
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_CONFIRM_TARGET_NVRAM:
		return s.doctorConfirmNvram(ctx, m, req)
	case pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_PUSH_SOURCE_NVRAM:
		return s.doctorPushNvram(ctx, m, req)
	default:
		return "", status.Errorf(codes.InvalidArgument, "%s is not an action on a move's source", fwDoctorFlagOf(a))
	}
}

// doctorRun is m's move as the doctor carries it on: the recovery's run, with
// the VFs the move detached.
func (s *Server) doctorRun(ctx context.Context, m fwmig.Marker) *liveFirmwareRun {
	r := s.recoveredFirmwareRun(ctx, m)
	vfs, err := s.recoveredMoveVFs(ctx, m.VM)
	if err != nil {
		slog.Warn("firmware-move doctor: the VFs detached for the move cannot be read; none are put back", "vm", m.VM, "error", err)
	}
	r.vfs = vfs
	return r
}

// unparkedRun is doctorRun from m's park, the marker set to phase p: a step
// that ends unanswered keeps the park (as a recovery retry does).
func (s *Server) unparkedRun(ctx context.Context, m fwmig.Marker, p fwmig.Phase) (*liveFirmwareRun, error) {
	r := s.doctorRun(ctx, m)
	r.marker.Phase, r.marker.ParkedFrom, r.marker.Detail = p, "", ""
	if err := s.putLiveFirmwareMarker(r, p); err != nil {
		return nil, err
	}
	if m.Phase.Parked() {
		// putLiveFirmwareMarker cleared it: a step that ends where the move
		// was parked keeps that park (D2-10 m-7).
		r.parked = m
	}
	return r, nil
}

// doctorOutcome says where m's move stands after an action: done (no marker),
// or the phase it is in now.
func (s *Server) doctorOutcome(ctx context.Context, m fwmig.Marker, did string) (string, error) {
	cur, ok, err := s.fwRecords().GetMarker(m.VM)
	switch {
	case err != nil:
		return "", status.Errorf(codes.Internal, "VM %q: %s; its marker cannot be read now: %v", m.VM, did, err)
	case !ok:
		return fmt.Sprintf("VM %q: %s; live firmware migration %s is resolved", m.VM, did, m.Attempt), nil
	case cur.Phase.Parked():
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: %s, and the move parked again as %s: %s",
			m.VM, did, cur.Phase, cur.Detail)
	}
	return fmt.Sprintf("VM %q: %s; live firmware migration %s is %s here", m.VM, did, m.Attempt, cur.Phase), nil
}

// sourceDomainInactive refuses unless this host's domain of m's VM is known
// to be inactive (or not defined).
func (s *Server) sourceDomainInactive(m fwmig.Marker, action pb.FirmwareMoveDoctorAction) error {
	if s.virt == nil {
		return status.Errorf(codes.Unavailable, "VM %q: no libvirt connection on %s", m.VM, s.hostName)
	}
	active, err := s.virt.DomainIsActive(m.VM)
	switch {
	case lv.IsNoDomain(err):
		return nil
	case err != nil:
		return status.Errorf(codes.Unavailable, "VM %q: whether its domain on %s is active cannot be read: %v", m.VM, s.hostName, err)
	case active:
		return doctorRefuse(m, action, fmt.Sprintf("the source domain on %s is active; it needs the source guest shut off", s.hostName))
	}
	return nil
}

// moveRow is the VM's row and whether it is m's incarnation.
func (s *Server) moveRow(ctx context.Context, m fwmig.Marker) (*corrosion.VMRecord, bool, error) {
	row, err := corrosion.GetVM(ctx, s.db, m.VM)
	if err != nil {
		return nil, false, status.Errorf(codes.Unavailable, "VM %q: its row cannot be read: %v", m.VM, err)
	}
	ours := row != nil && m.Binding.SameIncarnation(fwmig.Binding{UUID: parseFirmwareSpec(row.Spec).UUID, CreatedAt: row.CreatedAt})
	return row, ours, nil
}

// requireRowOn refuses unless the row names host for m's incarnation.
func (s *Server) requireRowOn(ctx context.Context, m fwmig.Marker, host string, action pb.FirmwareMoveDoctorAction) (*corrosion.VMRecord, error) {
	row, ours, err := s.moveRow(ctx, m)
	if err != nil {
		return nil, err
	}
	if !ours || row.HostName != host {
		return nil, doctorRefuse(m, action, fmt.Sprintf("it needs the VM's row on %s for the move's incarnation, and the row is on %s", host, rowHost(row)))
	}
	return row, nil
}

// targetRecords reads m's target, which must answer.
func (s *Server) targetRecords(ctx context.Context, m fwmig.Marker, action pb.FirmwareMoveDoctorAction) (*pb.FirmwareMoveHostRecords, *fwmig.Hold, error) {
	tr, err := s.inspectFirmwareMoveHost(ctx, m.Target, m.VM)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "VM %q: %s needs %s to answer, and it does not: %v", m.VM, fwDoctorFlagOf(action), m.Target, err)
	}
	h := holdOf(tr)
	if h != nil && h.Attempt != m.Attempt {
		h = nil
	}
	return tr, h, nil
}

// sourceStateHashes are this host's hashes of m's state now.
func (s *Server) sourceStateHashes(m fwmig.Marker) (permall, nvram string, err error) {
	fw := s.fw()
	if m.TPM {
		if permall, err = fw.PermallSHA256(m.UUID); err != nil {
			return "", "", fmt.Errorf("the source's TPM state cannot be read: %w", err)
		}
	}
	if m.UEFI {
		if nvram, err = fw.NvramSHA256(m.VM); err != nil {
			return "", "", fmt.Errorf("the source's NVRAM cannot be read: %w", err)
		}
	}
	return permall, nvram, nil
}

// sourceStateSinceCutover says, by the marker's hashes, whether m's source
// state is what the cutover recorded: for an operator's record.
func (s *Server) sourceStateSinceCutover(m fwmig.Marker) string {
	permall, nvram, err := s.sourceStateHashes(m)
	switch {
	case err != nil:
		return "whose hashes cannot be read now (" + err.Error() + ")"
	case permall != m.SrcPermallSHA256 || nvram != m.SrcNvramSHA256:
		return "changed after the cutover"
	}
	return "as the cutover left it"
}

// requireSourceStateRecorded refuses unless the source's state is what the
// cutover recorded.
func (s *Server) requireSourceStateRecorded(m fwmig.Marker, action pb.FirmwareMoveDoctorAction) error {
	permall, nvram, err := s.sourceStateHashes(m)
	if err != nil {
		return doctorRefuse(m, action, err.Error())
	}
	if permall != m.SrcPermallSHA256 || nvram != m.SrcNvramSHA256 {
		return doctorRefuse(m, action, fmt.Sprintf("the source's state is permall %s nvram %s now, not the permall %s nvram %s recorded at cutover",
			orNone(permall), orNone(nvram), orNone(m.SrcPermallSHA256), orNone(m.SrcNvramSHA256)))
	}
	return nil
}

// unmarkByOperator removes m's marker after an action resolved the move,
// resolves the conditions its parks and its cleanup raised, and records it.
func (s *Server) unmarkByOperator(ctx context.Context, m fwmig.Marker, did string) error {
	if err := s.fwRecords().RemoveMarker(m.VM); err != nil {
		return status.Errorf(codes.Internal, "VM %q: %s, but its marker cannot be removed: %v", m.VM, did, err)
	}
	s.resolveFirmwareMoveParkConditions(ctx, m.VM)
	s.resolveOwnFirmwareMoveCondition(ctx, condFwmigCleanupFailed, m.VM)
	s.recordVMEvent(ctx, m.VM, "vm.migrate.firmware", "ok", fmt.Sprintf("live firmware migration %s to %s: %s", m.Attempt, m.Target, did))
	slog.Warn("firmware-move doctor: move resolved by an operator", "vm", m.VM, "attempt", m.Attempt, "target", m.Target, "how", did)
	return nil
}

// ── --accept-target, --reverify ──

// doctorAcceptTarget takes the target's verified copy (spec §17 D-5):
//   - verified, the commit failing (C1): the commit on this host under the
//     VM's lock, then Release; the target's hold verified, its guest paused;
//   - source_state_missing parked from committed (V6 after the commit): the
//     source's final NVRAM hashed again and Release resent;
//   - released, parked (the row names another host, or the target is
//     fenced): the source cleanup, its state retained 24 h;
//   - cleaning (a cleanup the source state's change stopped): the source
//     state quarantined here, never wiped, and the marker removed.
//
// Every marker before verified is refused.
func (s *Server) doctorAcceptTarget(ctx context.Context, m fwmig.Marker) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_TARGET
	from := fwProgress(m)
	switch {
	case m.Phase == fwmig.PhaseVerified:
		if _, ours, err := s.moveRow(ctx, m); err != nil {
			return "", err
		} else if !ours {
			return "", doctorRefuse(m, action, "the VM's row is not the move's incarnation")
		}
		tr, h, err := s.targetRecords(ctx, m, action)
		if err != nil {
			return "", err
		}
		if h == nil || h.State != fwmig.HoldVerified || tr.GetDomain().GetState() != "paused" {
			return "", doctorRefuse(m, action, fmt.Sprintf("it needs %s to hold the attempt verified with its guest paused, and it holds %s with the domain %s",
				m.Target, holdWord(h), domainWord(tr.GetDomain())))
		}
		if err := s.sourceDomainInactive(m, action); err != nil {
			return "", err
		}
		s.recoverFirmwareMoveVerified(ctx, s.doctorRun(ctx, m))
		return s.doctorOutcome(ctx, m, "the verified move was committed and released by an operator")
	case m.Phase == fwmig.PhaseSourceStateMissing && from == fwmig.PhaseCommitted:
		if _, err := s.requireRowOn(ctx, m, m.Target, action); err != nil {
			return "", err
		}
		if err := s.sourceDomainInactive(m, action); err != nil {
			return "", err
		}
		nvram := m.SrcNvramSHA256
		if m.UEFI {
			sum, err := s.fw().NvramSHA256(m.VM)
			if err != nil {
				return "", doctorRefuse(m, action, fmt.Sprintf("the source's final NVRAM cannot be read: %v", err))
			}
			if nvram != "" && sum != nvram {
				return "", doctorRefuse(m, action, fmt.Sprintf("the source's NVRAM is %s, not the %s recorded at cutover", sum, nvram))
			}
			nvram = sum
		}
		m2 := m
		m2.SrcNvramSHA256 = nvram
		r, err := s.unparkedRun(ctx, m2, fwmig.PhaseCommitted)
		if err != nil {
			return "", err
		}
		r.parked = m
		s.recoverFirmwareMoveCommitted(ctx, r, false)
		s.settleRetriedPark(ctx, m)
		return s.doctorOutcome(ctx, m, "the source's final NVRAM was hashed again and Release resent")
	case from == fwmig.PhaseReleased && (m.Phase == fwmig.PhaseReleased || m.Phase.Parked()):
		if row, ours, err := s.moveRow(ctx, m); err != nil {
			return "", err
		} else if ours && row.HostName == s.hostName {
			return "", doctorRefuse(m, action, fmt.Sprintf("the VM's row names %s for the move's incarnation", s.hostName))
		}
		if err := s.sourceDomainInactive(m, action); err != nil {
			return "", err
		}
		r, err := s.unparkedRun(ctx, m, fwmig.PhaseReleased)
		if err != nil {
			return "", err
		}
		s.releaseSourceVFsAfterCutover(ctx, m.VM, r.vfs)
		cerr := s.fwmigCleanupSourceAs(ctx, r.marker, true)
		s.settleRetriedPark(ctx, m)
		if cerr != nil {
			return "", status.Errorf(codes.FailedPrecondition, "VM %q: the source cleanup stopped: %v", m.VM, cerr)
		}
		return s.doctorOutcome(ctx, m, "the released move's source state was retained for 24 h and cleaned up")
	case m.Phase == fwmig.PhaseCleaning:
		if row, ours, err := s.moveRow(ctx, m); err != nil {
			return "", err
		} else if ours && row.HostName == s.hostName {
			return "", doctorRefuse(m, action, fmt.Sprintf("the VM's row names %s for the move's incarnation", s.hostName))
		}
		if err := s.sourceDomainInactive(m, action); err != nil {
			return "", err
		}
		dir, err := s.quarantineFirmwareMoveSource(ctx, m,
			"an operator took the target's copy (lv doctor firmware-move --accept-target); the source's state, "+s.sourceStateSinceCutover(m)+", is kept here")
		if err != nil {
			return "", err
		}
		if err := s.unmarkByOperator(ctx, m, "an operator took the target's copy; the source's state was quarantined in "+dir); err != nil {
			return "", err
		}
		return fmt.Sprintf("VM %q: the source's state of live firmware migration %s is quarantined in %s on %s; nothing was deleted", m.VM, m.Attempt, dir, s.hostName), nil
	}
	return "", doctorRefuse(m, action, "it takes a move verified on the target (the commit failing), the V6 park after the commit, "+
		"a released move, or a stopped source cleanup; never a move parked before verified")
}

// holdWord names a hold for operator text.
func holdWord(h *fwmig.Hold) string {
	if h == nil {
		return "no hold of the attempt"
	}
	return "hold " + string(h.State)
}

// quarantineFirmwareMoveSource is the cleaning row of --accept-target: the
// leftover definition undefined (its state kept), the source state moved into
// <data_dir>/fwmig-quarantine/<vm>-<attempt>/ with the marker and a reason
// beside it. Nothing is deleted.
func (s *Server) quarantineFirmwareMoveSource(ctx context.Context, m fwmig.Marker, why string) (string, error) {
	if err := s.undefineLiveFirmwareLeftover(m); err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: undefine the source's leftover definition: %v", m.VM, err)
	}
	dir, err := s.fwRecords().QuarantinePath(m.VM, m.Attempt)
	if err != nil {
		return "", status.Errorf(codes.Internal, "VM %q: %v", m.VM, err)
	}
	// Each part is hashed on its own: a missing NVRAM leaves the TPM
	// state's hash recorded (lab2-D2-proof F6).
	var permall, nvram string
	if m.TPM {
		permall, _ = s.fw().PermallSHA256(m.UUID)
	}
	if m.UEFI {
		nvram, _ = s.fw().NvramSHA256(m.VM)
	}
	if err := s.fw().QuarantineFirmwareMoveSourceForOperator(m.VM, m.UUID, m.Attempt, dir); err != nil {
		return "", status.Errorf(codes.Internal, "VM %q: quarantine the source's state: %v", m.VM, err)
	}
	mj, _ := json.MarshalIndent(m, "", "  ")
	reason := fmt.Sprintf("vm: %s\nuuid: %s\ncreated_at: %s\nattempt: %s\nsource: %s\ntarget: %s\nphase: %s\nquarantined_at: %s\n"+
		"reason: %s\n"+
		"src_permall_sha256: %s\nsrc_nvram_sha256: %s\nquarantined_permall: %s\nquarantined_nvram: %s\n",
		m.VM, m.UUID, m.CreatedAt, m.Attempt, s.hostName, m.Target, m.Phase, time.Now().UTC().Format(time.RFC3339), why,
		orNone(m.SrcPermallSHA256), orNone(m.SrcNvramSHA256), orNone(permall), orNone(nvram))
	for name, data := range map[string][]byte{"marker.json": mj, "reason.txt": []byte(reason)} {
		if err := writeFileDurable(filepath.Join(dir, name), data); err != nil {
			return "", status.Errorf(codes.Internal, "VM %q: quarantine %s: %v", m.VM, name, err)
		}
	}
	if err := s.raiseQuarantineCondition(ctx, fwmigCondition{
		Code: condFwmigQuarantine, VM: m.VM, Attempt: m.Attempt, Source: s.hostName, Target: m.Target,
		Hashes: map[string]string{"src_permall_sha256": m.SrcPermallSHA256, "src_nvram_sha256": m.SrcNvramSHA256,
			"quarantined_permall": orNone(permall), "quarantined_nvram": orNone(nvram)},
		Paths:  []string{dir},
		Detail: fmt.Sprintf("an operator took the target's copy; the source's firmware state of attempt %s on %s is quarantined in %s", m.Attempt, s.hostName, dir),
		Action: "inspect it and remove the directory by hand when it is no longer needed; `lv doctor firmware-move <vm> --resolve quarantine` closes this",
	}); err != nil {
		slog.Warn("firmware-move doctor: raise the quarantine condition", "vm", m.VM, "error", err)
	}
	return dir, nil
}

// doctorReverify is the re-Verify of a move parked source_state_missing from
// cutover with its source state present (V6 before the commit, D2-12b m-5):
// the source's final state hashed again, Verify sent, and on MATCH the
// commit and Release.
func (s *Server) doctorReverify(ctx context.Context, m fwmig.Marker) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_REVERIFY
	if m.Phase != fwmig.PhaseSourceStateMissing || m.ParkedFrom != fwmig.PhaseCutover {
		return "", doctorRefuse(m, action, "it takes only a move parked source_state_missing from cutover")
	}
	if _, err := s.requireRowOn(ctx, m, s.hostName, action); err != nil {
		return "", err
	}
	if err := s.sourceDomainInactive(m, action); err != nil {
		return "", err
	}
	permall, nvram, err := s.sourceStateHashes(m)
	if err != nil {
		return "", doctorRefuse(m, action, err.Error()+"; --adopt-target-copy takes a move whose source state is missing")
	}
	if (m.SrcPermallSHA256 != "" && permall != m.SrcPermallSHA256) || (m.SrcNvramSHA256 != "" && nvram != m.SrcNvramSHA256) {
		return "", doctorRefuse(m, action, fmt.Sprintf("the source's state is permall %s nvram %s, not the permall %s nvram %s recorded at cutover",
			orNone(permall), orNone(nvram), orNone(m.SrcPermallSHA256), orNone(m.SrcNvramSHA256)))
	}
	m2 := m
	m2.SrcPermallSHA256, m2.SrcNvramSHA256 = permall, nvram
	r, err := s.unparkedRun(ctx, m2, fwmig.PhaseCutover)
	if err != nil {
		return "", err
	}
	r.parked = m
	if err := s.verifyLiveFirmwareMove(ctx, r); err == nil {
		s.recoverFirmwareMoveVerified(ctx, r)
	}
	s.settleRetriedPark(ctx, m)
	return s.doctorOutcome(ctx, m, "the source's final state was hashed again and Verify resent")
}

// ── --adopt-target-copy ──

// doctorAdopt takes the target's copy as the VM's (spec §17 D-5, the hold
// transition): the target moves its hold to verified (a paused guest, its
// verified permall the current one) or resuming (a guest that runs), recording
// the operator, the hashes and the reason; then the normal commit (when the
// row still names this host) and Release. The source's domain must be
// inactive. Refused where the source's copy is current and runs (a park
// before cutover), and where the source's final state is present and was
// never compared (V6 before the commit: --reverify).
func (s *Server) doctorAdopt(ctx context.Context, m fwmig.Marker, actor string) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ADOPT_TARGET_COPY
	from := fwProgress(m)
	switch m.Phase {
	case fwmig.PhaseSourceStateSuspect:
	case fwmig.PhaseSourcePaused:
		// Only a target guest that runs ran after the source paused: its
		// copy is the newer one, taken once the source's domain is shut off.
		tr, th, err := s.targetRecords(ctx, m, action)
		if err != nil {
			return "", err
		}
		td := tr.GetDomain()
		if !td.GetPresent() || !(td.GetState() == "running" || (td.GetState() == "paused" && th != nil && th.State != fwmig.HoldPrepared)) {
			return "", doctorRefuse(m, action, fmt.Sprintf("the target's guest is %s on %s (%s) and never ran: the source's copy is current; --accept-source",
				domainWord(td), m.Target, holdWord(th)))
		}
	case fwmig.PhaseTargetRan:
		if fwPreCutover(from) {
			return "", doctorRefuse(m, action, "the source's guest runs and its copy is current: `lv doctor firmware-move <vm> --discard-target --stop-target`")
		}
	case fwmig.PhaseSourceStateMissing:
		if from == fwmig.PhaseCommitted {
			return "", doctorRefuse(m, action, "the move committed: `lv doctor firmware-move <vm> --accept-target`")
		}
		if _, _, err := s.sourceStateHashes(m); err == nil && from == fwmig.PhaseCutover {
			// V6 before the commit: the source's final state is there and was
			// never compared (D2-12b m-5).
			return "", doctorRefuse(m, action, "the source's final state is present here: --reverify, or --accept-source")
		}
	default:
		return "", doctorRefuse(m, action, "it takes a move parked source_state_suspect, source_state_missing or target_ran after cutover, or source_paused with its source shut off")
	}
	if err := s.sourceDomainInactive(m, action); err != nil {
		return "", err
	}
	if _, ours, err := s.moveRow(ctx, m); err != nil {
		return "", err
	} else if !ours {
		return "", doctorRefuse(m, action, "the VM's row is not the move's incarnation")
	}
	resp, err := s.doctorTargetOp(ctx, m, &pb.FirmwareMoveDoctorTargetRequest{
		Op: pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_ADOPT, Operator: actor,
		Reason: fmt.Sprintf("parked %s from %s: %s", m.Phase, from, m.Detail)})
	if err != nil {
		return "", err
	}
	m2 := m
	if m.UEFI && !sha256HexRe.MatchString(m.SrcNvramSHA256) {
		// The source's final NVRAM is not known: Release confirms the target's
		// against its own, which the operator adopted.
		m2.SrcNvramSHA256 = resp.GetNvramSha256()
	}
	r, err := s.unparkedRun(ctx, m2, fwmig.PhaseVerified)
	if err != nil {
		return "", err
	}
	r.parked = m
	s.recoverFirmwareMoveVerified(ctx, r)
	s.settleRetriedPark(ctx, m)
	did := fmt.Sprintf("the target's copy was adopted (hold %s) and the move committed and released", resp.GetHoldState())
	if cur, ok, err := s.fwRecords().GetMarker(m.VM); err == nil && ok && cur.Attempt == m.Attempt && cur.Phase == fwmig.PhaseCleaning {
		// The source's state an adopted move leaves (missing, partial or
		// suspect) is not the one the cutover recorded, so the cleanup cannot
		// retain it: it is quarantined here instead, never wiped.
		dir, err := s.quarantineFirmwareMoveSource(ctx, cur,
			"an operator adopted the target's copy (lv doctor firmware-move --adopt-target-copy); what is left of the source's state is kept here")
		if err != nil {
			return "", err
		}
		did += "; what is left of the source's state is quarantined in " + dir
		if err := s.unmarkByOperator(ctx, cur, did); err != nil {
			return "", err
		}
	}
	return s.doctorOutcome(ctx, m, did)
}

// ── --accept-source ──

// fwDoctorAfterReturnHook, when set, runs right after the return writer
// landed; an error ends the action there, as a crash would. Test-only.
var fwDoctorAfterReturnHook func() error

// doctorAcceptSource takes the source's copy (spec §17 D-5):
//   - source_paused (M1p with a target domain that never ran): the target's
//     copy discarded, the source guest resumed (a running one is left
//     running), the marker removed; no acknowledgement;
//   - after cutover, before the commit (source_state_suspect, target_ran,
//     V6 source_state_missing with the recorded state present): the target's
//     copy discarded, the row stopped here, the marker removed;
//     --acknowledge-rollback;
//   - after the commit (the target proved off, or answering with the
//     attempt's hold): the owed DISCARD recorded, the return writer, the
//     target's copy discarded when it answers, the row stopped here, the
//     marker removed; never for a storage copy, whose commit deleted the
//     source's disks; --acknowledge-rollback. A run interrupted after the
//     return is taken up again where it stopped.
//
// The source's own copy must be there first: a target copy is never
// discarded for a source that has none.
func (s *Server) doctorAcceptSource(ctx context.Context, m fwmig.Marker, req *pb.FirmwareMoveDoctorRequest) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE
	from := fwProgress(m)
	switch {
	case m.Phase == fwmig.PhaseSourcePaused:
		return s.doctorAcceptSourcePaused(ctx, m)
	case m.Phase == fwmig.PhaseNvramUnconfirmed:
		// With the target proved off its guest runs no more, and the
		// source's older state is the only copy left to start: it is
		// returned as after a commit, acknowledged (lab-2 D2 re-review I-3).
		if _, off, err := s.fwTargetProvedOff(ctx, m.Target); err != nil || !off {
			return "", doctorRefuse(m, action, fmt.Sprintf("the guest runs on the target: --confirm-target-nvram --accept-nvram-hash=<sha256>, "+
				"or --push-source-nvram --acknowledge-rollback once it is powered off; with %s proved off (`lv host fence-confirm %s`), "+
				"--accept-source --acknowledge-rollback returns the VM here from the source's older state", m.Target, m.Target))
		}
	case m.Phase == fwmig.PhaseSourceStateMissing && fwPreCutover(from):
		// The guest left the source: its copy is incomplete, and the target's
		// may be the only complete one (lab2-D2-proof F7).
		return "", doctorRefuse(m, action, "the source's final state is missing, so the target's copy may be the only complete one: "+
			"--adopt-target-copy takes it; with the state back in place, the minute retry takes the move on")
	case fwPreCutover(from):
		return "", doctorRefuse(m, action, "before cutover the source's copy is current: `lv doctor firmware-move <vm> --discard-target`")
	}
	switch m.Phase {
	case fwmig.PhaseSourceStateSuspect, fwmig.PhaseTargetRan:
	case fwmig.PhaseSourceStateMissing:
		if from != fwmig.PhaseCutover {
			return "", doctorRefuse(m, action, "the source's final state is missing: --adopt-target-copy takes the target's")
		}
	case fwmig.PhaseTargetUnreachable, fwmig.PhaseDiscardPending, fwmig.PhaseCommitted, fwmig.PhaseReleased, fwmig.PhaseCleaning,
		fwmig.PhaseNvramUnconfirmed:
		// A stopped source cleanup (cleaning) is a released move: the
		// target's copy is the committed one, and the source's state is
		// still its own until the wipe (lab2-D2-proof F3).
		if !fwPostCommit(from) {
			if !m.BeforeCutover() && m.SrcStopReason != fwmig.StopReasonMigrated {
				// The fence resolution leaves this park (fenceResolves): the
				// source may hold stale TPM state (I6).
				return "", doctorRefuse(m, action, fmt.Sprintf("no `lv` command handles it yet: after the cutover the source stopped with reason %q, "+
					"not as a completed migration, so a fence of %s does not resolve it either. It is retried each minute and settles once %s answers: "+
					"the move finishes there when %s holds the guest, and parks as source_state_suspect when it holds none, which this action then takes",
					m.SrcStopReason, m.Target, m.Target, m.Target))
			}
			return "", doctorRefuse(m, action, "it is retried each minute, and resolved by fence when the target is proved off")
		}
	default:
		return "", doctorRefuse(m, action, "it takes source_paused, source_state_suspect, target_ran, the V6 park before the commit, "+
			"or a committed move (its source cleanup stopped or not) whose target is proved off or lost its held domain")
	}
	if !req.GetAcknowledgeRollback() {
		return "", doctorRefuse(m, action, fwAckReason(m)+": add --acknowledge-rollback")
	}
	if !fwPostCommit(from) {
		return s.doctorAcceptSourceBeforeCommit(ctx, m, req)
	}
	return s.doctorAcceptSourceAfterCommit(ctx, m, req)
}

// fwAckReason says why taking the source's copy of m's move may roll the
// guest back.
func fwAckReason(m fwmig.Marker) string {
	switch m.Phase {
	case fwmig.PhaseSourceStateSuspect:
		return "the source's state is suspect (its guest stopped for a reason other than the migration, or ran again after the cutover), and the target's copy may be the newer one"
	case fwmig.PhaseTargetRan:
		return "the target's guest ran, so its copy is newer than the source's"
	case fwmig.PhaseNvramUnconfirmed:
		if m.TPM {
			return "the guest ran on the target after the release, so its NVRAM and TPM state there are newer than the source's"
		}
		return "the guest ran on the target after the release, so its NVRAM there is newer than the source's"
	case fwmig.PhaseSourceStateMissing:
		return "the source's final state was never compared with the target's copy"
	}
	return "the target's copy is the committed one, and may be newer than the source's"
}

// requireSourceCopy refuses unless the source's own firmware state is there
// to take (C-1): readable, and, for a move parked source_state_missing, the
// state the cutover recorded, with a recorded hash for every part the VM has.
func (s *Server) requireSourceCopy(m fwmig.Marker, action pb.FirmwareMoveDoctorAction) error {
	permall, nvram, err := s.sourceStateHashes(m)
	if err != nil {
		return doctorRefuse(m, action, err.Error()+": the source has no copy to take; --adopt-target-copy takes the target's")
	}
	if m.Phase == fwmig.PhaseSourceStateMissing &&
		((m.TPM && m.SrcPermallSHA256 == "") || (m.UEFI && m.SrcNvramSHA256 == "") ||
			permall != m.SrcPermallSHA256 || nvram != m.SrcNvramSHA256) {
		return doctorRefuse(m, action, fmt.Sprintf("the source's state is permall %s nvram %s, and the cutover recorded permall %s nvram %s: "+
			"it is not the source's final state; --adopt-target-copy takes the target's",
			orNone(permall), orNone(nvram), orNone(m.SrcPermallSHA256), orNone(m.SrcNvramSHA256)))
	}
	return nil
}

// doctorAcceptSourcePaused is the source_paused row: the source's copy is
// current only while the target's guest never ran, so a target guest that
// runs (or ran: any active state but paused) is refused, --stop-target or
// not. Otherwise the target's copy is discarded first, and only then does the
// source guest run again, through its own entry point; a source guest already
// running (D2-12b re-review m-B) or shut off is left as it is.
func (s *Server) doctorAcceptSourcePaused(ctx context.Context, m fwmig.Marker) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE
	if s.virt == nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: no libvirt connection on %s", m.VM, s.hostName)
	}
	active, err := s.virt.DomainIsActive(m.VM)
	if err != nil && !lv.IsNoDomain(err) {
		return "", doctorRefuse(m, action, fmt.Sprintf("whether the source domain is active cannot be read (%v); run this again once libvirt answers", err))
	}
	paused := false
	srcWord := "shut off"
	if active {
		st, err := s.virt.DomainStateReason(m.VM)
		if err != nil {
			return "", doctorRefuse(m, action, fmt.Sprintf("the source domain's state cannot be read (%v); run this again once libvirt answers", err))
		}
		paused = st.Reason == "paused"
		srcWord = st.State
		if paused {
			srcWord = "paused"
		}
	}
	tr, h, err := s.targetRecords(ctx, m, action)
	if err != nil {
		return "", err
	}
	td := tr.GetDomain()
	ran := ""
	switch {
	case !td.GetPresent() || td.GetState() == "shutoff":
	case td.GetState() == "running":
		ran = "runs"
	case td.GetState() == "paused" && (h == nil || h.State != fwmig.HoldPrepared):
		ran = fmt.Sprintf("is paused under %s, so it may have run", holdWord(h))
	case td.GetState() != "paused":
		return "", doctorRefuse(m, action, fmt.Sprintf("the target's guest is %s on %s; no doctor action takes a target guest in that state", td.GetState(), m.Target))
	}
	if ran != "" {
		exit := "then --adopt-target-copy"
		if active {
			exit = fmt.Sprintf("shut the source's %s domain off outside litevirt (virsh destroy %s keeps its state), then --adopt-target-copy", srcWord, m.VM)
		}
		return "", doctorRefuse(m, action, fmt.Sprintf("the target's guest %s on %s: it ran after the source paused, so its copy is the newer one and is not discarded; %s",
			ran, m.Target, exit))
	}
	if err := s.doctorDiscardTargetCopy(ctx, m, false, action); err != nil {
		return "", err
	}
	if paused {
		if err := s.virt.ResumeFirmwareMoveSourceForOperator(m.VM, m.UUID, m.Attempt); err != nil {
			return "", status.Errorf(codes.Internal, "VM %q: the target's copy is discarded, and the source guest's resume failed: %v; run this again", m.VM, err)
		}
	}
	r := s.doctorRun(ctx, m)
	s.reattachVFsOnSource(ctx, m.VM, r.vfs, len(r.vfs) > 0)
	s.noteSourceVFs(ctx, r)
	did := "an operator accepted the source's copy; the target's copy was discarded"
	if st, err := s.sourceDomainState(m.VM); err == nil && st == "running" {
		s.restoreRecoveredFirmwareRow(ctx, r, did)
	} else if !active {
		s.stopRowByOperator(ctx, m, did)
	}
	if err := s.unmarkByOperator(ctx, m, did); err != nil {
		return "", err
	}
	return fmt.Sprintf("VM %q: %s, and its guest runs on %s from its own state", m.VM, did, s.hostName), nil
}

// stopRowByOperator records the VM stopped here, with its firmware state, when
// the row is still the move's on this host.
func (s *Server) stopRowByOperator(ctx context.Context, m fwmig.Marker, did string) {
	row, ours, err := s.moveRow(ctx, m)
	if err != nil || !ours || row.HostName != s.hostName {
		return
	}
	detail := fmt.Sprintf("%s (live firmware migration %s to %s); the VM is stopped here with its firmware state: `lv start`", did, m.Attempt, m.Target)
	if err := corrosion.UpdateVMState(ctx, s.db, m.VM, "stopped", detail); err != nil {
		s.noteStateWriteFail(corrosion.OpVMState, err)
	}
}

// doctorAcceptSourceBeforeCommit: the row still names this host. The
// source's own copy must be there (C-1); the target's copy is discarded
// (--stop-target stops a guest that runs there first), the row stopped here
// (or running, for a source guest that runs again), the marker removed.
func (s *Server) doctorAcceptSourceBeforeCommit(ctx context.Context, m fwmig.Marker, req *pb.FirmwareMoveDoctorRequest) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE
	if _, err := s.requireRowOn(ctx, m, s.hostName, action); err != nil {
		return "", err
	}
	if st, err := s.sourceDomainState(m.VM); err != nil || st != "running" {
		if err := s.sourceDomainInactive(m, action); err != nil {
			return "", err
		}
	}
	if err := s.requireSourceCopy(m, action); err != nil {
		return "", err
	}
	if err := s.doctorDiscardTargetCopy(ctx, m, req.GetStopTarget(), action); err != nil {
		return "", err
	}
	r := s.doctorRun(ctx, m)
	s.reattachVFsOnSource(ctx, m.VM, r.vfs, len(r.vfs) > 0)
	did := "an operator accepted the source's copy (--acknowledge-rollback); the target's copy was discarded"
	if st, err := s.sourceDomainState(m.VM); err == nil && st == "running" {
		s.restoreRecoveredFirmwareRow(ctx, r, did)
	} else {
		s.stopRowByOperator(ctx, m, did)
	}
	if err := s.unmarkByOperator(ctx, m, did); err != nil {
		return "", err
	}
	return fmt.Sprintf("VM %q: %s; start it here with `lv start %s`", m.VM, did, m.VM), nil
}

// returnDisks are the disk rows the return writer moves back, as its guard
// expects them: the commit's own (recorded in the marker), or, for a marker
// an earlier build wrote, the rows now, each on the target (or kept by its
// owner) and on shared storage. Every row now must be on shared storage.
func (s *Server) returnDisks(ctx context.Context, m fwmig.Marker, action pb.FirmwareMoveDoctorAction) ([]corrosion.DiskRecord, error) {
	now, err := corrosion.GetVMDisks(ctx, s.db, m.VM)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "VM %q: its disks cannot be read: %v", m.VM, err)
	}
	for _, d := range now {
		if !corrosion.DiskOnSharedStorage(ctx, s.db, d, m.Target, s.hostName) {
			return nil, doctorRefuse(m, action, fmt.Sprintf("disk %s (%s on %s) is not on shared storage, so the source cannot take the VM back", d.DiskName, d.Path, d.HostName))
		}
	}
	if len(m.CommitDisks) > 0 {
		if !sameCommitDisks(commitDisksOf(now), m.CommitDisks) {
			return nil, doctorRefuse(m, action, "the VM's disk rows changed since the commit; nothing was written")
		}
		out := make([]corrosion.DiskRecord, 0, len(m.CommitDisks))
		for _, d := range m.CommitDisks {
			out = append(out, corrosion.DiskRecord{VMName: m.VM, DiskName: d.Disk, HostName: d.Host, Path: d.Path,
				StorageType: d.StorageType, StorageVolume: d.StorageVolume})
		}
		return out, nil
	}
	for _, d := range now {
		if d.HostName == m.Target {
			continue
		}
		if keep, _ := corrosion.SharedRowKeepsOwner(ctx, s.db, d, m.Target, s.hostName); !keep {
			return nil, doctorRefuse(m, action, fmt.Sprintf("disk %s's row names %s, not %s, and the marker holds no record of the commit's disks", d.DiskName, d.HostName, m.Target))
		}
	}
	return now, nil
}

// rowState is a row's state, for operator text.
func rowState(row *corrosion.VMRecord) string {
	if row == nil {
		return "gone"
	}
	return row.State
}

// requireDisksReturned refuses unless every disk row of m's VM names this
// host, or is a shared row its owner keeps: the return writer's disks.
func (s *Server) requireDisksReturned(ctx context.Context, m fwmig.Marker, action pb.FirmwareMoveDoctorAction) error {
	disks, err := corrosion.GetVMDisks(ctx, s.db, m.VM)
	if err != nil {
		return status.Errorf(codes.Unavailable, "VM %q: its disks cannot be read: %v", m.VM, err)
	}
	for _, d := range disks {
		if d.HostName == s.hostName {
			continue
		}
		if keep, _ := corrosion.SharedRowKeepsOwner(ctx, s.db, d, m.Target, s.hostName); !keep {
			return doctorRefuse(m, action, fmt.Sprintf("the VM's row is here, and disk %s's row names %s", d.DiskName, d.HostName))
		}
	}
	return nil
}

// sameCommitDisks: a and b hold the same disk rows, in any order.
func sameCommitDisks(a, b []fwmig.CommitDisk) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(d fwmig.CommitDisk) string {
		return d.Disk + "\x00" + d.Host + "\x00" + d.Path + "\x00" + d.StorageType + "\x00" + d.StorageVolume
	}
	seen := map[string]int{}
	for _, d := range a {
		seen[key(d)]++
	}
	for _, d := range b {
		if seen[key(d)] == 0 {
			return false
		}
		seen[key(d)]--
	}
	return true
}

// doctorAcceptSourceAfterCommit returns a committed VM to this host. The
// target must be proved off, or answer with the attempt's hold, so its copy
// can be discarded through the move (I-6); a guest that runs there must be
// stopped first (--stop-target, under the hold). The owed DISCARD is
// recorded before the return writer moves the VM and disk rows back, then
// sent; a target that takes it drops the record. A run that stopped after
// the return (the row here for the incarnation, the owed record there)
// takes up from there.
func (s *Server) doctorAcceptSourceAfterCommit(ctx context.Context, m fwmig.Marker, req *pb.FirmwareMoveDoctorRequest) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_ACCEPT_SOURCE
	if m.Route == fwmig.RouteStorageCopy {
		return "", doctorRefuse(m, action, fmt.Sprintf("the VM's disks are on %s: the commit of a storage copy deleted the source's copies", m.Target))
	}
	row, ours, err := s.moveRow(ctx, m)
	if err != nil {
		return "", err
	}
	_, owedFound, oerr := s.fwRecords().GetOwedDiscardFor(m.VM, m.Binding)
	if oerr != nil && !errors.Is(oerr, fwmig.ErrOtherIncarnation) {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: its owed-discard record cannot be read: %v", m.VM, oerr)
	}
	owedHere := owedFound && oerr == nil
	sourceRuns := false
	if m.Phase == fwmig.PhaseSourceStateSuspect {
		// The source guest ran again after the cutover: the operator keeps it.
		st, err := s.sourceDomainState(m.VM)
		sourceRuns = err == nil && st == "running"
	}
	returned := false
	switch {
	case ours && row.HostName == m.Target:
	case ours && row.HostName == s.hostName && (row.State == "stopped" || (sourceRuns && row.State == "running")):
		// An earlier run's return landed: the disk rows must have come
		// with it.
		if err := s.requireDisksReturned(ctx, m, action); err != nil {
			return "", err
		}
		returned = true
	default:
		return "", doctorRefuse(m, action, fmt.Sprintf("it needs the VM's row on %s for the move's incarnation, and the row is %s on %s", m.Target, rowState(row), rowHost(row)))
	}
	if !sourceRuns {
		if err := s.sourceDomainInactive(m, action); err != nil {
			return "", err
		}
	}
	if fwProgress(m) == fwmig.PhaseCleaning && !returned {
		// The cleanup undefines the source's leftover definition before it
		// wipes the state: without one, there is nothing here to start.
		if _, err := s.virt.DomainIsActive(m.VM); lv.IsNoDomain(err) {
			return "", doctorRefuse(m, action, fmt.Sprintf("the source cleanup already undefined the VM's domain on %s, so it cannot be started here; "+
				"its firmware state is kept, and the VM's copy is on %s: bring %s back", s.hostName, m.Target, m.Target))
		}
	}
	if err := s.requireSourceCopy(m, action); err != nil {
		return "", err
	}
	if m.Phase != fwmig.PhaseSourceStateSuspect && m.Phase != fwmig.PhaseTargetRan {
		if err := s.requireSourceStateRecorded(m, action); err != nil {
			return "", err
		}
	}
	// Every check that can still refuse runs before the target's guest is
	// stopped: the disks the return takes. The owed DISCARD is recorded
	// just before the return; a refusal after it removes the record again.
	recs := s.fwRecords()
	var disks []corrosion.DiskRecord
	owedPut := false
	if !returned {
		if disks, err = s.returnDisks(ctx, m, action); err != nil {
			return "", err
		}
	}
	landed := false
	defer func() {
		if landed {
			return
		}
		if owedPut {
			if rerr := recs.RemoveOwedDiscard(m.VM, m.Attempt); rerr != nil {
				slog.Warn("firmware-move doctor: a refused return leaves its owed-discard record", "vm", m.VM, "error", rerr)
				return
			}
		}
		// An owed-discard retry may have raised discard_owed on the record
		// while the action ran; with no record of the VM left, it goes too.
		if owed, err := recs.ListOwedDiscards(); err == nil && !slices.ContainsFunc(owed, func(o fwmig.OwedDiscard) bool { return o.VM == m.VM }) {
			_ = s.resolveFirmwareMigrationCondition(ctx, condFwmigDiscardOwed, m.VM)
		}
	}()
	_, off, err := s.fwTargetProvedOff(ctx, m.Target)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "VM %q: whether %s is proved off cannot be read: %v", m.VM, m.Target, err)
	}
	if !off {
		tr, h, err := s.targetRecords(ctx, m, action)
		if err != nil {
			return "", status.Errorf(codes.Unavailable, "%s; bring it back, or once it is powered off fence it (`lv host fence-confirm %s`) and run this again",
				status.Convert(err).Message(), m.Target)
		}
		td := tr.GetDomain()
		switch {
		case returned && h == nil:
			// An earlier run's return landed; its DISCARD may have too.
		case fwProgress(m) == fwmig.PhaseCleaning:
			// The target released the guest: its copy is the VM's.
			dom := "not defined"
			if td.GetPresent() {
				dom = td.GetState()
			}
			return "", doctorRefuse(m, action, fmt.Sprintf("%s answers, and its domain of the VM is %s: the VM's copy is there, and the source cleanup is retried each minute; "+
				"if %s must not take the VM, once it is powered off, `lv host fence-confirm %s`, and run this again", m.Target, dom, m.Target, m.Target))
		case h == nil:
			return "", doctorRefuse(m, action, fmt.Sprintf("%s holds no hold of the attempt, so its copy cannot be discarded through the move: "+
				"once %s is powered off, `lv host fence-confirm %s`, and run this again", m.Target, m.Target, m.Target))
		case !returned && m.Phase != fwmig.PhaseTargetRan && m.Phase != fwmig.PhaseSourceStateSuspect && td.GetPresent():
			// The committed/released row takes a target proved off; a
			// target that answers takes it only with its held domain gone
			// (held_domain_absent).
			return "", doctorRefuse(m, action, fmt.Sprintf("%s answers and holds the committed copy (domain %s): the move is retried each minute; "+
				"if %s must not take the VM, once it is powered off, `lv host fence-confirm %s`, and run this again", m.Target, td.GetState(), m.Target, m.Target))
		}
		if h != nil && td.GetPresent() && td.GetState() != "shutoff" && td.GetState() != "paused" {
			if !req.GetStopTarget() {
				return "", doctorRefuse(m, action, fmt.Sprintf("its guest is %s on %s: add --stop-target", td.GetState(), m.Target))
			}
			if err := s.doctorStopTarget(ctx, m); err != nil {
				return "", err
			}
		}
	}
	if !returned && m.Phase == fwmig.PhaseCleaning {
		// Out of cleaning before the return: the cleanup takes only a
		// cleaning marker, and a run that stops between the return and its
		// unmark must not leave it one to take (review I1). A re-run resumes
		// from this park.
		pm, perr := m.Park(fwmig.PhaseTargetUnreachable)
		if perr == nil {
			pm.Detail = fmt.Sprintf("an operator is returning the VM to %s (--accept-source --acknowledge-rollback); run it again if it did not finish", s.hostName)
			perr = recs.PutMarker(pm)
		}
		if perr != nil {
			return "", status.Errorf(codes.Internal, "VM %q: take the marker out of cleaning before the return: %v; nothing was returned", m.VM, perr)
		}
	}
	if !returned {
		// Recorded just before the return, so a run that stops before it
		// leaves no record of a DISCARD nothing owes (re-review 2, m-D).
		if err := recs.PutOwedDiscard(fwmig.OwedDiscard{VM: m.VM, Binding: m.Binding, Target: m.Target,
			CreatedStubs: m.CreatedStubs, Since: time.Now().UTC()}); err != nil {
			return "", status.Errorf(codes.Internal, "VM %q: record the DISCARD owed to %s: %v; nothing was returned", m.VM, m.Target, err)
		}
		owedPut = true
		ok, err := corrosion.ReturnMigratedVM(ctx, s.db, m.VM, m.Target, s.hostName, m.UUID, m.CreatedAt, "stopped", disks)
		if err != nil {
			// Whether it landed is not known: the owed record stays, and a
			// target refuses its DISCARD while the row names it.
			landed = true
			return "", status.Errorf(codes.Unavailable, "VM %q: return it to %s: %v; run this again", m.VM, s.hostName, err)
		}
		if !ok {
			return "", doctorRefuse(m, action, "the VM's row or disk rows changed since the commit; nothing was written")
		}
		landed = true
		if h := fwDoctorAfterReturnHook; h != nil {
			if err := h(); err != nil {
				return "", err
			}
		}
	} else if !owedHere {
		// An earlier run's DISCARD landed and dropped its record, or the run
		// stopped between the two: the record again; a target with nothing
		// left of the attempt drops it.
		if err := recs.PutOwedDiscard(fwmig.OwedDiscard{VM: m.VM, Binding: m.Binding, Target: m.Target,
			CreatedStubs: m.CreatedStubs, Since: time.Now().UTC()}); err != nil {
			return "", status.Errorf(codes.Internal, "VM %q: record the DISCARD owed to %s: %v", m.VM, m.Target, err)
		}
	}
	owed := ""
	discarded := false
	if !off {
		d, derr := s.sendLiveFirmwareAbort(ctx, m.Target, m.VM, m.Binding, pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED, m.CreatedStubs)
		discarded = derr == nil && !d.GetRefused() && !d.GetTargetDomain().GetPresent()
	}
	if discarded {
		if err := recs.RemoveOwedDiscard(m.VM, m.Attempt); err != nil {
			slog.Warn("firmware-move doctor: the discard landed, and its owed record stays for the next pass", "vm", m.VM, "error", err)
		}
	} else {
		if cerr := s.raiseFirmwareMigrationCondition(ctx, fwmigCondition{
			Code: condFwmigDiscardOwed, VM: m.VM, Attempt: m.Attempt, Source: s.hostName, Target: m.Target,
			Detail: fmt.Sprintf("an operator returned the VM to %s; the DISCARD of %s's copy is sent when it answers", s.hostName, m.Target),
			Action: "nothing: it is sent each interval, and dropped when the host is removed",
		}); cerr != nil {
			slog.Warn("firmware-move doctor: raise the condition", "vm", m.VM, "code", condFwmigDiscardOwed, "error", cerr)
		}
		owed = fmt.Sprintf("; the DISCARD of %s's copy is owed and sent each minute", m.Target)
	}
	did := fmt.Sprintf("an operator returned the VM to %s from %s after the commit (--acknowledge-rollback)", s.hostName, m.Target)
	if sourceRuns {
		s.restoreSourceStateAfterFailedMigration(ctx, m.VM, did, did)
	} else {
		s.stopRowByOperator(ctx, m, did)
	}
	if cur, err := corrosion.GetVM(ctx, s.db, m.VM); err == nil && cur != nil {
		s.convergeMovedGuest(ctx, cur, m.Target, s.hostName, sourceRuns)
	}
	r := s.doctorRun(ctx, m)
	s.reattachVFsOnSource(ctx, m.VM, r.vfs, len(r.vfs) > 0)
	if err := s.unmarkByOperator(ctx, m, did); err != nil {
		return "", err
	}
	return fmt.Sprintf("VM %q: %s%s; start it here with `lv start %s`", m.VM, did, owed, m.VM), nil
}

// convergeMovedGuest is the part of a migration's finish that does not need
// the other host, for a VM whose copy now lives on `on` (this host) after
// living on `from`: each VXLAN NIC's FDB entry pointed at on's VTEP, the
// VLANs of a running guest's NICs put on its taps here (applyTapVLANs), the
// gateways of a guest that runs here announced out of this host's bridges
// (announceGatewaysOf, what AnnounceMigratedGuest does on a live move's
// target), and the stack's LB backends refreshed.
func (s *Server) convergeMovedGuest(ctx context.Context, vm *corrosion.VMRecord, from, on string, running bool) {
	ctx = context.WithoutCancel(ctx)
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
	for _, iface := range ifaces {
		s.updateFDBForMigration(ctx, iface, from, on)
	}
	if running {
		if err := s.applyTapVLANs(ctx, vm.Name); err != nil {
			slog.Error("move: a running guest's NIC VLANs are not on its taps here; ConvergeTapVLANs retries", "vm", vm.Name, "error", err)
		}
		go s.announceGatewaysOf(ctx, vm.Name)
	}
	go s.refreshLBForStack(context.Background(), vm.StackName)
	s.fwLiveStep("converge:" + from + "->" + on)
}

// doctorDiscardTargetCopy is the DISCARD of m's target copy, which must be
// answered: --stop-target first stops a guest that runs there under the
// move's hold. A domain left defined after it is not the move's, and is not
// removed.
func (s *Server) doctorDiscardTargetCopy(ctx context.Context, m fwmig.Marker, stop bool, action pb.FirmwareMoveDoctorAction) error {
	if stop {
		if err := s.doctorStopTarget(ctx, m); err != nil {
			return err
		}
	}
	d, err := s.sendLiveFirmwareAbort(ctx, m.Target, m.VM, m.Binding, pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED, m.CreatedStubs)
	switch {
	case err != nil:
		return status.Errorf(codes.Unavailable, "VM %q: the DISCARD of %s's copy was not answered: %v; nothing changed here", m.VM, m.Target, err)
	case d.GetRefused():
		hint := ""
		if td := d.GetTargetDomain(); td.GetState() == "running" && !stop {
			hint = "; add --stop-target"
		}
		return doctorRefuse(m, action, fmt.Sprintf("%s refused the DISCARD of its copy: %s%s", m.Target, d.GetDetail(), hint))
	case d.GetTargetDomain().GetPresent():
		return doctorRefuse(m, action, fmt.Sprintf("a domain of the VM is still defined on %s (%s) outside the move's hold; it is not removed by this action: remove it there, then run this again",
			m.Target, domainWord(d.GetTargetDomain())))
	}
	return nil
}

// doctorStopTarget asks m's target to stop the guest it holds for the move
// (--stop-target) and waits for it to be shut off.
func (s *Server) doctorStopTarget(ctx context.Context, m fwmig.Marker) error {
	resp, err := s.doctorTargetOp(ctx, m, &pb.FirmwareMoveDoctorTargetRequest{Op: pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_STOP})
	if err != nil {
		return err
	}
	if td := resp.GetTargetDomain(); td.GetPresent() && td.GetState() != "shutoff" {
		return status.Errorf(codes.FailedPrecondition, "VM %q: its guest on %s is %s after the stop", m.VM, m.Target, td.GetState())
	}
	return nil
}

// doctorTargetOp sends one target op for m's attempt.
func (s *Server) doctorTargetOp(ctx context.Context, m fwmig.Marker, req *pb.FirmwareMoveDoctorTargetRequest) (*pb.FirmwareMoveDoctorTargetResponse, error) {
	req.VmName, req.Uuid, req.CreatedAt, req.AttemptId = m.VM, m.UUID, m.CreatedAt, m.Attempt
	client, closer, err := s.liveFirmwarePeer(ctx, m.Target)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "VM %q: reach %s: %v", m.VM, m.Target, err)
	}
	defer closer()
	cctx, cancel := context.WithTimeout(ctx, fwDoctorStopWait+fwLiveCallTimeout)
	defer cancel()
	resp, err := client.FirmwareMoveDoctorTarget(cctx, req)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return nil, status.Errorf(codes.FailedPrecondition, "VM %q: %s runs a build without the firmware-move doctor; upgrade it first", m.VM, m.Target)
		}
		return nil, status.Errorf(status.Code(err), "VM %q: %s: %s", m.VM, m.Target, status.Convert(err).Message())
	}
	return resp, nil
}

// ── --discard-target ──

// doctorDiscardTarget is the M1 row: a move parked before cutover whose
// target holds a domain the automatic DISCARD could not take (target_ran, or a
// target that refuses the abort, target_unreachable). The source's guest runs
// and its copy is current, so no acknowledgement: --stop-target stops a target
// guest that runs, the DISCARD quarantines the target's copy, and the marker
// goes.
func (s *Server) doctorDiscardTarget(ctx context.Context, m fwmig.Marker, req *pb.FirmwareMoveDoctorRequest) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_DISCARD_TARGET
	switch {
	case m.Phase == fwmig.PhaseSourcePaused:
		return "", doctorRefuse(m, action, "the source's guest is paused: `lv doctor firmware-move <vm> --accept-source`")
	case !(m.Phase == fwmig.PhaseTargetRan || m.Phase == fwmig.PhaseTargetUnreachable) || !fwPreCutover(m.ParkedFrom):
		return "", doctorRefuse(m, action, "after cutover the target may hold the only current copy: --adopt-target-copy or --accept-source")
	}
	if st, err := s.sourceDomainState(m.VM); err != nil || st != "running" {
		return "", doctorRefuse(m, action, fmt.Sprintf("it needs the source's guest running on %s, and it is %s (%v)", s.hostName, orNone(st), err))
	}
	if _, err := s.requireRowOn(ctx, m, s.hostName, action); err != nil {
		return "", err
	}
	if err := s.doctorDiscardTargetCopy(ctx, m, req.GetStopTarget(), action); err != nil {
		return "", err
	}
	r := s.doctorRun(ctx, m)
	s.reattachVFsOnSource(ctx, m.VM, r.vfs, len(r.vfs) > 0)
	s.noteSourceVFs(ctx, r)
	did := "an operator discarded the target's copy; the source's guest runs on"
	s.restoreRecoveredFirmwareRow(ctx, r, did)
	if err := s.unmarkByOperator(ctx, m, did); err != nil {
		return "", err
	}
	return fmt.Sprintf("VM %q: %s on %s", m.VM, did, s.hostName), nil
}

// ── --confirm-target-nvram, --push-source-nvram ──

// doctorConfirmNvram is N1: the target's NVRAM accepted by its hash now, its
// hold removed, and the marker released → the source cleanup (the retained
// bundle keeps the source's copy 24 h).
func (s *Server) doctorConfirmNvram(ctx context.Context, m fwmig.Marker, req *pb.FirmwareMoveDoctorRequest) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_CONFIRM_TARGET_NVRAM
	if m.Phase != fwmig.PhaseNvramUnconfirmed {
		return "", doctorRefuse(m, action, "it takes only a move parked nvram_unconfirmed")
	}
	if !sha256HexRe.MatchString(req.GetAcceptNvramHash()) {
		return "", status.Errorf(codes.InvalidArgument, "--accept-nvram-hash must be the target NVRAM's sha256 as shown (64 lowercase hex), not %q", req.GetAcceptNvramHash())
	}
	if _, err := s.doctorTargetOp(ctx, m, &pb.FirmwareMoveDoctorTargetRequest{
		Op: pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_CONFIRM_NVRAM, AcceptNvramHash: req.GetAcceptNvramHash()}); err != nil {
		return "", err
	}
	return s.doctorReleasedThenClean(ctx, m, fmt.Sprintf("the target's NVRAM %s was confirmed by an operator", req.GetAcceptNvramHash()))
}

// doctorReleasedThenClean moves m's marker to released and runs the source
// cleanup.
func (s *Server) doctorReleasedThenClean(ctx context.Context, m fwmig.Marker, did string) (string, error) {
	r, err := s.unparkedRun(ctx, m, fwmig.PhaseReleased)
	if err != nil {
		return "", err
	}
	s.releaseSourceVFsAfterCutover(ctx, m.VM, r.vfs)
	cerr := s.fwmigCleanupSourceAs(ctx, r.marker, true)
	s.settleRetriedPark(ctx, m)
	if cerr != nil {
		return "", status.Errorf(codes.FailedPrecondition, "VM %q: %s, and the source cleanup stopped: %v", m.VM, did, cerr)
	}
	return s.doctorOutcome(ctx, m, did+"; the source's state was retained for 24 h and cleaned up")
}

// doctorPushNvram writes the source's final NVRAM to the target:
//   - N1, the guest powered off (--stop-target stops it): with
//     --acknowledge-rollback, since the guest may have written variables;
//   - held_domain_absent (a target_unreachable park after the commit whose
//     target holds the verified hold with no domain): H1's checks without
//     "domain defined", the VM left stopped on the target.
//
// Then the marker is released and the source cleaned up.
func (s *Server) doctorPushNvram(ctx context.Context, m fwmig.Marker, req *pb.FirmwareMoveDoctorRequest) (string, error) {
	const action = pb.FirmwareMoveDoctorAction_FIRMWARE_MOVE_DOCTOR_ACTION_PUSH_SOURCE_NVRAM
	switch {
	case m.Phase == fwmig.PhaseNvramUnconfirmed:
		if !req.GetAcknowledgeRollback() {
			return "", doctorRefuse(m, action, "the guest may have written EFI variables since its release: add --acknowledge-rollback")
		}
	case m.Phase == fwmig.PhaseTargetUnreachable && m.ParkedFrom == fwmig.PhaseCommitted:
		tr, h, err := s.targetRecords(ctx, m, action)
		if err != nil {
			return "", err
		}
		if h == nil || (h.State != fwmig.HoldVerified && h.State != fwmig.HoldResuming) || tr.GetDomain().GetPresent() {
			return "", doctorRefuse(m, action, fmt.Sprintf("it is held_domain_absent only when %s holds the attempt verified with no domain, and it holds %s with the domain %s",
				m.Target, holdWord(h), domainWord(tr.GetDomain())))
		}
	default:
		return "", doctorRefuse(m, action, "it takes a move parked nvram_unconfirmed, or held_domain_absent after the commit")
	}
	if err := s.sourceDomainInactive(m, action); err != nil {
		return "", err
	}
	var nvram []byte
	if m.UEFI {
		b, err := os.ReadFile(s.fw().NvramPath(m.VM))
		if err != nil {
			return "", doctorRefuse(m, action, fmt.Sprintf("the source's final NVRAM cannot be read: %v", err))
		}
		if got := fwBytesSHA256(b); got != m.SrcNvramSHA256 {
			return "", doctorRefuse(m, action, fmt.Sprintf("the source's NVRAM is %s, not the %s recorded at cutover", got, orNone(m.SrcNvramSHA256)))
		}
		nvram = b
	}
	if req.GetStopTarget() {
		if err := s.doctorStopTarget(ctx, m); err != nil {
			return "", err
		}
	}
	if _, err := s.doctorTargetOp(ctx, m, &pb.FirmwareMoveDoctorTargetRequest{
		Op: pb.FirmwareMoveDoctorTargetOp_FIRMWARE_MOVE_DOCTOR_TARGET_OP_PUSH_NVRAM, Nvram: nvram,
		SrcNvramSha256: m.SrcNvramSHA256, AcknowledgeRollback: req.GetAcknowledgeRollback()}); err != nil {
		return "", err
	}
	return s.doctorReleasedThenClean(ctx, m, "the source's final NVRAM was pushed to "+m.Target+" by an operator")
}
