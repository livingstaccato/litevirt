package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// reservationReleaseVerb is the RBAC verb of `lv operation release-reservation`.
// Built-in Admin holds it; Operator does not.
const reservationReleaseVerb = "host.reservation.release"

// reservationReleaseHostTrailer is set by the host that decided a release
// request, so the entry node can tell a refusal that host returned from a
// transport failure reaching it (both are codes.Unavailable).
const reservationReleaseHostTrailer = "x-litevirt-reservation-host"

// reservationReleaseAuditTimeout bounds the audit write, which outlives the
// caller's context.
const reservationReleaseAuditTimeout = 10 * time.Second

// reservationReleaseState holds the manual release's test seam: beforeReclassify
// runs under the workload lock before the re-classify.
type reservationReleaseState struct {
	beforeReclassify func(opID string)
}

// reservationReleaseFacts is what the audit row says about the reservation.
type reservationReleaseFacts struct {
	host, vm, class string
	vcpu, memMiB    int
}

// ReleaseHostReservation is `lv operation release-reservation`: it releases a
// host capacity reservation whose operation is no longer running. It is decided
// on the reservation's target host, under the workload's lock there, and
// audited once, on the node the user called.
func (s *Server) ReleaseHostReservation(ctx context.Context, req *pb.ReleaseHostReservationRequest) (*pb.ReleaseHostReservationResponse, error) {
	// The forwarded hop is not audited: there the caller may be the peer's own
	// admin identity, and the entry node audits the real caller.
	peerHop := callerPrincipalKind(ctx) == principalKindPeer
	if peerHop {
		_ = grpc.SetTrailer(ctx, metadata.Pairs(reservationReleaseHostTrailer, s.hostName))
	}
	facts := &reservationReleaseFacts{}
	resp, err := s.releaseHostReservation(ctx, req, peerHop, facts)
	if !peerHop && callerUsername(ctx) != "" {
		s.auditReservationRelease(ctx, req.GetOperationId(), facts, resp, err)
	}
	return resp, err
}

func (s *Server) releaseHostReservation(ctx context.Context, req *pb.ReleaseHostReservationRequest,
	peerHop bool, facts *reservationReleaseFacts) (*pb.ReleaseHostReservationResponse, error) {
	if err := s.RequirePerm(ctx, "/", reservationReleaseVerb, "admin"); err != nil {
		return nil, err
	}
	opID := req.GetOperationId()
	if opID == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id is required")
	}
	if !req.GetForce() {
		return nil, status.Error(codes.FailedPrecondition,
			"releasing a reservation requires force: check it first with lv host inspect <host>")
	}

	view, resp, err := s.classifyForRelease(ctx, opID, facts)
	if view == nil {
		return resp, err
	}

	target := view.Vector.TargetHost
	if target != s.hostName {
		h, err := corrosion.GetHost(ctx, s.db, target)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read host %s: %v", target, err)
		}
		// A removed target leaves no host whose admission relies on the
		// reservation: it is decided here.
		if h != nil && h.State != "removed" {
			if peerHop {
				// Never forwarded twice: the entry node and this one disagree
				// about where the reservation is held.
				return nil, status.Errorf(codes.FailedPrecondition,
					"operation %s's reservation is held on %s by this host's (%s) replica, not here; retry", opID, target, s.hostName)
			}
			return s.forwardReservationRelease(ctx, req, view, h.State)
		}
	}
	return s.executeReservationRelease(ctx, view, facts)
}

// classifyForRelease classifies opID and answers the cases decided on any node:
// nothing counted (already released, or nothing to release), a manifest
// journal, an admission lease. view is nil when resp/err is the answer.
func (s *Server) classifyForRelease(ctx context.Context, opID string, facts *reservationReleaseFacts) (
	*corrosion.HostReservationView, *pb.ReleaseHostReservationResponse, error) {
	op, err := corrosion.GetOperation(ctx, s.db, opID)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "read operation %s: %v", opID, err)
	}
	if op == nil {
		return nil, nil, status.Errorf(codes.NotFound,
			"no operation %s (it may already have been reaped); lv host inspect <host> lists the reservations a host holds", opID)
	}
	view, err := corrosion.ClassifyReservation(ctx, s.db, opID)
	if errors.Is(err, corrosion.ErrReservationUnreadable) {
		// Its error can name projects, as lv host inspect's does: only a
		// caller who may vm.read cluster-wide sees it.
		slog.Warn("release a reservation: its data cannot be read", "operation_id", opID, "error", err)
		why := "see the daemon log"
		if s.RequirePerm(ctx, "/", "vm.read", "viewer") == nil {
			why = err.Error()
		}
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"the reservation of operation %s cannot be read (%s), so it cannot be classified and is not released", opID, why)
	}
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "classify the reservation of operation %s: %v", opID, err)
	}
	if view == nil {
		resp, err := s.releaseOfUncounted(ctx, op, facts)
		return nil, resp, err
	}
	facts.host, facts.vm, facts.class = view.Vector.TargetHost, view.VMName, string(view.Class)
	facts.vcpu, facts.memMiB = view.Vector.TargetCPU, view.Vector.TargetMemMiB
	switch view.Class {
	case corrosion.ReservationManifest:
		return nil, nil, status.Errorf(codes.InvalidArgument,
			"operation %s is a %s journal, not a capacity reservation; it is never released by hand (inspect it with lv operation show %s)",
			opID, view.Op.OperationKind, s.workloadArg(ctx, view.VMName))
	case corrosion.ReservationCapacityLease:
		maxAge := corrosion.CapacityLeaseMaxAge(view.Op.Method)
		at := "its expiry"
		if created, err := time.Parse(time.RFC3339Nano, view.Op.CreatedAt); err == nil {
			at = created.Add(maxAge).UTC().Format(time.RFC3339)
		}
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"operation %s is an admission lease; the stale-lease sweep releases it on its own at %s (%s after it was created), and it may still be deciding an admission until then",
			opID, at, maxAge)
	}
	return view, nil, nil
}

// releaseOfUncounted answers for an operation whose reservation is not counted:
// already released when a release step is at its header epoch, otherwise there
// is nothing to release.
func (s *Server) releaseOfUncounted(ctx context.Context, op *corrosion.OperationRecord,
	facts *reservationReleaseFacts) (*pb.ReleaseHostReservationResponse, error) {
	steps, err := corrosion.ListOperationSteps(ctx, s.db, op.ID, op.VMOwnerEpoch)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read operation %s's steps: %v", op.ID, err)
	}
	for _, st := range steps {
		if !corrosion.IsReservationReleaseStep(st) {
			continue
		}
		resp := &pb.ReleaseHostReservationResponse{Released: false, Detail: "already released"}
		if rv, err := corrosion.DecodeReservation(op.ReservationJSON); err == nil {
			resp.Host = rv.TargetHost
			facts.host = rv.TargetHost
		}
		facts.class = "already_released"
		return resp, nil
	}
	return nil, status.Errorf(codes.FailedPrecondition,
		"operation %s holds no reservation counted against any host: it is terminal at its header epoch, or it cannot be attributed to its project's current authority; nothing to release",
		op.ID)
}

// forwardReservationRelease asks the reservation's target host, in
// targetState, to release it.
func (s *Server) forwardReservationRelease(ctx context.Context, req *pb.ReleaseHostReservationRequest,
	view *corrosion.HostReservationView, targetState string) (*pb.ReleaseHostReservationResponse, error) {
	target := view.Vector.TargetHost
	unreachable := func(err error) error {
		if targetState != "active" && view.Class == corrosion.ReservationTerminalPastHeader && !view.ReleaseBlocked {
			// The reservation sweep's deputy releases a finished operation's
			// reservation on a host that is not active, so the host need not
			// be removed for it.
			return status.Errorf(codes.Unavailable,
				"host %s is %s and unreachable, or refused the request before handling it (%v): this operation finished, so the reservation sweep's deputy (the smallest active host) releases its reservation within a pass (%s); check with lv host inspect %s",
				target, targetState, err, reservationRecoveryInterval, target)
		}
		return status.Errorf(codes.Unavailable,
			"host %s is unreachable, or refused the request before handling it (%v): a reservation is released on the host that holds it, so that host can confirm no admission there still relies on it. Retry when it answers, or remove the host with lv host rm %s if it is gone for good",
			target, err, target)
	}
	client, conn, err := s.peerClient(ctx, target)
	if err != nil {
		return nil, unreachable(err)
	}
	defer conn.Close()
	var trailer metadata.MD
	resp, err := client.ReleaseHostReservation(ctx, req, grpc.Trailer(&trailer))
	if err != nil {
		answered := len(trailer.Get(reservationReleaseHostTrailer)) != 0
		switch status.Code(err) {
		case codes.Unavailable:
			if !answered {
				if refusedBeforeHandler(err) {
					return nil, status.Errorf(codes.Unavailable, "host %s refused the request before handling it: %s",
						target, status.Convert(err).Message())
				}
				return nil, unreachable(err)
			}
		case codes.Unimplemented:
			if !answered {
				return nil, status.Errorf(codes.FailedPrecondition,
					"host %s runs a build without reservation release; upgrade it (lv host upgrade %s) and retry: its own sweep also releases terminal reservations once upgraded",
					target, target)
			}
		}
		return nil, s.redactWorkloadName(ctx, err, view.VMName)
	}
	if resp.Vm != "" && !s.canReadVM(ctx, resp.Vm) {
		resp.Vm = ""
	}
	return resp, nil
}

// executeReservationRelease decides and writes the release on this node, under
// the workload's lock: the VM lock for a VM's reservation, the container lock
// for a container's.
func (s *Server) executeReservationRelease(ctx context.Context, view *corrosion.HostReservationView,
	facts *reservationReleaseFacts) (*pb.ReleaseHostReservationResponse, error) {
	if err := s.requireReplicaCaughtUp(ctx, "ReleaseHostReservation"); err != nil {
		return nil, err
	}
	opID := view.Op.ID
	container := view.Op.ResourceKind == "container"
	// The workload's own name, as its create journalled it: the lock is
	// keyed by it, not by the reservation vector's copy.
	name := view.Op.ResourceID
	if name == "" {
		name = view.VMName
	}
	var unlock func()
	var locked bool
	if container {
		unlock, locked = s.TryLockContainer(name)
	} else {
		unlock, locked = s.tryLockVMAs(name, "reservation release")
	}
	if !locked {
		noun := "VM"
		if container {
			noun = "container"
		}
		return nil, status.Errorf(codes.Unavailable,
			"%s %s has a request in flight on %s that may be deciding on this reservation; retry in a moment", noun, s.workloadRef(ctx, name), s.hostName)
	}
	defer unlock()
	if h := s.resRelease.beforeReclassify; h != nil {
		h(opID)
	}

	cur, resp, err := s.classifyForRelease(ctx, opID, facts)
	if cur == nil {
		return resp, err
	}
	switch cur.Class {
	case corrosion.ReservationInFlight:
		if container {
			return nil, status.Errorf(codes.FailedPrecondition,
				"operation %s is still running: it holds container %s's mutation barrier (state %s at owner epoch %d). Wait for it to finish; its reservation is released once it is terminal",
				opID, s.workloadRef(ctx, name), cur.LatestState, cur.LatestEpoch)
		}
		arg := s.workloadArg(ctx, cur.VMName)
		return nil, status.Errorf(codes.FailedPrecondition,
			"operation %s is still running: it holds VM %s's mutation barrier (state %s at owner epoch %d). Wait for it to finish, or inspect it with lv operation show %s; abort a wedged one with lv operation abort %s --force, and its reservation is released once it is terminal",
			opID, s.workloadRef(ctx, cur.VMName), cur.LatestState, cur.LatestEpoch, arg, arg)
	case corrosion.ReservationAdmitting:
		age := time.Duration(0)
		if created, err := time.Parse(time.RFC3339Nano, cur.Op.CreatedAt); err == nil {
			age = time.Since(created).Round(time.Second)
		}
		return nil, status.Errorf(codes.FailedPrecondition,
			"operation %s was admitted %s ago and may still be committing; retry after %s",
			opID, age, corrosion.RPCScopedLeaseMaxAge)
	default:
		if !handReleasableClass(cur.Class) {
			return nil, status.Errorf(codes.FailedPrecondition, "operation %s's reservation is %s; it is not released by hand", opID, cur.Class)
		}
	}

	release := corrosion.ReleaseReservation
	if cur.ReleaseBlocked {
		release = corrosion.ReleaseBlockedReservation
	}
	already, err := release(ctx, s.db, opID)
	switch {
	case errors.Is(err, corrosion.ErrReservationInFlight):
		return nil, status.Errorf(codes.FailedPrecondition,
			"operation %s took its workload's mutation barrier while the release was decided; it is running", opID)
	case errors.Is(err, corrosion.ErrReservationNotFound):
		return nil, status.Errorf(codes.NotFound, "operation %s was reaped while the release was decided", opID)
	case errors.Is(err, corrosion.ErrReservationReleaseBlocked), errors.Is(err, corrosion.ErrReservationNotReleasable):
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	case err != nil:
		s.noteStateWriteFail("reservation_release", err)
		return nil, status.Errorf(codes.Internal, "release the reservation of operation %s: %v", opID, err)
	case already:
		facts.class = "already_released"
		return &pb.ReleaseHostReservationResponse{Released: false, Host: cur.Vector.TargetHost, Detail: "already released"}, nil
	}
	s.reservationMetrics.Released("admin")
	slog.Warn("released a host reservation by hand",
		"operation_id", opID, "method", cur.Op.Method, "vm", cur.VMName, "host", cur.Vector.TargetHost,
		"vcpu", cur.Vector.TargetCPU, "mem_mib", cur.Vector.TargetMemMiB, "class", string(cur.Class),
		"release_blocked", cur.ReleaseBlocked, "header_epoch", cur.HeaderEpoch)
	detail := string(cur.Class)
	if cur.ReleaseBlocked {
		detail += "; its cancelled release row was tombstoned, so it was released with a failed step at the header's owner epoch"
	}
	out := &pb.ReleaseHostReservationResponse{
		Released: true, Host: cur.Vector.TargetHost,
		Vcpu: int32(cur.Vector.TargetCPU), MemoryMib: int32(cur.Vector.TargetMemMiB), Detail: detail,
	}
	if s.canReadVM(ctx, cur.VMName) {
		out.Vm = cur.VMName
	}
	return out, nil
}

// handReleasableClass: the classes `lv operation release-reservation`
// releases — the sweep's two, and no_running_operation.
func handReleasableClass(c corrosion.ReservationClass) bool {
	return sweepReleasableClass(c) || c == corrosion.ReservationNoRunningOperation
}

// auditReservationRelease writes the one audit row of a release request.
func (s *Server) auditReservationRelease(ctx context.Context, opID string, f *reservationReleaseFacts,
	resp *pb.ReleaseHostReservationResponse, err error) {
	result := "ok"
	switch {
	case err != nil:
		result = "refused"
	case !resp.GetReleased():
		result = "already"
		// Whichever node decided it: the entry node's own classification
		// of a forwarded request says nothing about what was released.
		f.class = "already_released"
	}
	if resp != nil && resp.Host != "" {
		f.host = resp.Host
	}
	detail := fmt.Sprintf("host=%s vm=%s vcpu=%d mem_mib=%d class=%s", f.host, f.vm, f.vcpu, f.memMiB, f.class)
	if err != nil {
		st := status.Convert(err)
		detail += fmt.Sprintf(" code=%s error=%s", st.Code(), boundAuditValue(st.Message(), 512))
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reservationReleaseAuditTimeout)
	defer cancel()
	s.audit(actx, "operation.reservation.release", boundAuditValue(opID, 128), detail, result)
}

// refusedBeforeHandler reports whether a codes.Unavailable from the target host
// is one its interceptors return before any handler runs (so without the
// handler's trailer): the host is up and answering, and the remedy is to retry,
// not to remove it.
func refusedBeforeHandler(err error) bool {
	msg := status.Convert(err).Message()
	return msg == forwardedIdentityNotVisible || strings.HasPrefix(msg, walQuarantineUserRefusal)
}

// workloadRef names a workload in a refusal: quoted when the caller may read
// it, as the success response's vm field is filled, and withheld otherwise.
func (s *Server) workloadRef(ctx context.Context, name string) string {
	if s.canReadVM(ctx, name) {
		return strconv.Quote(name)
	}
	return withheldWorkload
}

// workloadArg is workloadRef for a command argument: the bare name, or a
// placeholder.
func (s *Server) workloadArg(ctx context.Context, name string) string {
	if s.canReadVM(ctx, name) {
		return name
	}
	return "<vm>"
}

// withheldWorkload stands in for a workload name the caller may not read.
const withheldWorkload = "(name withheld)"

// workloadArgPattern matches the workload argument of an `lv operation show`
// or `lv operation abort` a refusal names: the command, the argument, a
// trailing sentence period, and the character that ends the argument.
var workloadArgPattern = regexp.MustCompile(`(lv operation (?:show|abort) )([^\s;,()]+?)(\.?)($|[\s;,()])`)

// redactWorkloadName withholds name from a refusal the target host returned
// when this node's caller may not read it. The target judged the forwarded hop,
// which is a peer unless forwarded identity is enforced, so only the entry node
// knows what its caller may see.
func (s *Server) redactWorkloadName(ctx context.Context, err error, name string) error {
	if name == "" || s.canReadVM(ctx, name) {
		return err
	}
	st := status.Convert(err)
	msg := strings.ReplaceAll(st.Message(), strconv.Quote(name), withheldWorkload)
	// The bare name appears only as the argument of the commands workloadArg
	// fills; any other word, even one equal to the name, is left alone.
	msg = workloadArgPattern.ReplaceAllStringFunc(msg, func(m string) string {
		sub := workloadArgPattern.FindStringSubmatch(m)
		if sub[2] != name {
			return m
		}
		return sub[1] + "<vm>" + sub[3] + sub[4]
	})
	if msg == st.Message() {
		return err
	}
	return status.Error(st.Code(), msg)
}
