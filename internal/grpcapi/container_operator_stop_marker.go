package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/lxc"
)

// `lv ct stop --force` on a host in write quarantine
// (health/container_operator_stop_marker.go): the container analogue of
// operator_stop_marker.go.
//
// A plain `lv ct stop` there is refused before the runtime is touched: its
// "operator-stop" record is refused, and an unrecorded stop is undone by
// the restart policy. The forced stop records itself locally first,
// durably, and stops the container only once that record is on disk; the
// container checker and `lv ct start` honour it; once the quarantine lifts
// the replay records the stop on the row and removes the marker.

// ctStopLocalOnlyHeader is the response header a forced container stop made
// under write quarantine answers with: the stop is recorded on that host
// only, so an entry that forwarded it does not wait to see the row stopped.
// A peer that does not set it is waited for as before.
const ctStopLocalOnlyHeader = "litevirt-ct-stop-local-only"

// quarantinedContainerStopRefusal is a plain `lv ct stop` of name on a host
// in write quarantine (reason): refused, nothing touched, naming --force.
func (s *Server) quarantinedContainerStopRefusal(name, reason string) error {
	return status.Errorf(codes.FailedPrecondition,
		"container %q was not stopped: host %s is in write quarantine (%s) and cannot record the stop on the "+
			"container, so its restart policy would start it again; nothing was changed. To stop it now run "+
			"`lv ct stop --force %s`: the stop is recorded on that host first and on the container once the "+
			"quarantine lifts. Otherwise %s, then retry `lv ct stop %s`",
		name, s.hostName, reason, name, s.quarantineRemedy(), name)
}

// quarantinedForceStopContainerLocked is `lv ct stop --force` of req.Name on
// a host in write quarantine (reason). The caller holds the container lock.
// It writes the operator-stop marker, then stops the container.
func (s *Server) quarantinedForceStopContainerLocked(ctx context.Context, req *pb.StopContainerRequest, project, reason string) (*emptypb.Empty, error) {
	rec, err := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "stop: read container row: %v", err)
	}
	if rec == nil {
		return nil, status.Errorf(codes.NotFound, "container %q not found on host %q", req.Name, s.hostName)
	}
	switch rec.State {
	case "running", "stopped", "error":
	default:
		// A relocation or a create is under way: its settle is a replicated
		// record, which the quarantine refuses.
		return nil, status.Errorf(codes.FailedPrecondition,
			"container %q is %s: under write quarantine (%s) the stop cannot settle it, and the stop was not applied; %s, then retry `lv ct stop --force %s`",
			req.Name, rec.State, reason, s.quarantineRemedy(), req.Name)
	}
	if err := health.WriteContainerOperatorStopMarker(s.dataDir, health.ContainerOperatorStopMarker{
		Container:   rec.Name,
		Host:        s.hostName,
		Incarnation: corrosion.IncarnationOf(rec.CreatedAt),
		OwnerEpoch:  rec.OwnerEpoch,
		StoppedAt:   time.Now().UTC().Format(time.RFC3339),
		Quarantine:  reason,
	}); err != nil {
		s.audit(ctx, "ct.stop", req.Name, "project="+project+" forced under write quarantine: marker not written", "error")
		return nil, status.Errorf(codes.FailedPrecondition,
			"container %q was not stopped: this host is in write quarantine (%s), so a forced stop must first be recorded "+
				"on this host, and that record could not be written (%v); the container is left running. Free space or "+
				"fix the data directory (%s), then retry `lv ct stop --force %s`; or %s",
			req.Name, reason, err, health.ContainerOperatorStopMarkerDir(s.dataDir), req.Name, s.quarantineRemedy())
	}
	if err := s.containerRuntime.StopContainer(ctx, req.Name, int(req.TimeoutSec)); err != nil {
		st, serr := s.containerRuntime.StateContainer(ctx, req.Name)
		switch {
		case serr == nil && st == string(lxc.StateStopped):
			slog.Info("container stop: already stopped; the forced stop is recorded on this host", "name", req.Name, "error", err)
		case serr == nil:
			// Not stopped: the marker would hold a running container's next
			// start for a stop that did not happen.
			if rerr := health.RemoveContainerOperatorStopMarker(s.dataDir, req.Name); rerr != nil {
				slog.Warn("container stop: removing the operator-stop marker of a stop that failed failed", "name", req.Name, "error", rerr)
			}
			s.audit(ctx, "ct.stop", req.Name, "project="+project+" forced under write quarantine", "error")
			return nil, status.Errorf(codes.Internal, "stop: %v (the container is %s)", err, st)
		default:
			s.audit(ctx, "ct.stop", req.Name, "project="+project+" forced under write quarantine", "error")
			return nil, status.Errorf(codes.Internal, "stop: %v (and whether the container still runs cannot be read: %v; the operator-stop marker is kept)", err, serr)
		}
	}
	slog.Warn("container stop: forced stop under write quarantine — recorded on this host only, recorded on the container once the quarantine lifts",
		"name", req.Name, "quarantine", reason)
	s.audit(ctx, "ct.stop", req.Name, "project="+project+" forced under write quarantine ("+reason+"): recorded on this host only, recorded on the container once the quarantine lifts", "ok")
	_ = grpc.SetHeader(ctx, metadata.Pairs(ctStopLocalOnlyHeader, "1"))
	return &emptypb.Empty{}, nil
}

// containerOperatorStopStartRefusal is the start gate of a container an
// operator-stop marker holds on this host. The caller holds the container
// lock. Under write quarantine the start is refused. Out of it the stop is
// replayed first, and replayed reports that the row was written, so the
// caller reads it again. A marker that cannot be read refuses the start.
func (s *Server) containerOperatorStopStartRefusal(ctx context.Context, rec *corrosion.ContainerRecord) (replayed bool, err error) {
	why, corrupt := health.ContainerOperatorStopHold(s.dataDir, s.hostName, rec)
	if why == "" {
		return false, nil
	}
	if corrupt {
		return false, status.Errorf(codes.FailedPrecondition, "container %q is held stopped on this host: %s. %s",
			rec.Name, why, health.ContainerOperatorStopMarkerCorruptRemedy(rec.Name))
	}
	if reason := s.stopQuarantineReason(); reason != "" {
		return false, status.Errorf(codes.FailedPrecondition,
			"container %q was not started: %s. This host is still in write quarantine (%s), so neither that stop nor a "+
				"start can be recorded; %s, and the stop is recorded on its own; then retry `lv ct start %s`",
			rec.Name, why, reason, s.quarantineRemedy(), rec.Name)
	}
	m, ok, rerr := health.ReadContainerOperatorStopMarker(s.dataDir, rec.Name)
	if rerr != nil || !ok {
		return false, status.Errorf(codes.Unavailable, "container %q: read its operator-stop marker again: %v; retry", rec.Name, rerr)
	}
	if err := s.replayContainerOperatorStopLocked(ctx, m); err != nil {
		if errors.Is(err, errReplayHeld) {
			return false, status.Errorf(codes.FailedPrecondition,
				"container %q was not started: %s, and its row is %s, which that stop is not recorded over. Record the "+
					"stop with `lv ct stop %s` (which removes the marker), then retry `lv ct start %s`",
				rec.Name, why, rec.State, rec.Name, rec.Name)
		}
		return false, status.Errorf(codes.Unavailable,
			"container %q was not started: recording the forced stop made under write quarantine failed (%v); retry `lv ct start %s`",
			rec.Name, err, rec.Name)
	}
	return true, nil
}

// containerOperatorStopHeldHere refuses a start of this host's container
// name through the runtime while an operator-stop marker holds it: the
// backstop under every start (startContainerArmed). Without a marker file
// it reads nothing more.
func (s *Server) containerOperatorStopHeldHere(ctx context.Context, name string) error {
	if s.dataDir == "" {
		return nil
	}
	if _, ok, err := health.ReadContainerOperatorStopMarker(s.dataDir, name); err == nil && !ok {
		return nil
	}
	rec, err := corrosion.GetContainer(ctx, s.db, s.hostName, name)
	if err != nil {
		return status.Errorf(codes.Unavailable, "container %q has an operator-stop marker on this host and its row cannot be read (%v), so it is not started; retry", name, err)
	}
	if rec == nil {
		return nil // a new container of the name; the replay drops the marker
	}
	if why, _ := health.ContainerOperatorStopHold(s.dataDir, s.hostName, rec); why != "" {
		return status.Errorf(codes.FailedPrecondition, "container %q is held stopped on this host: %s", name, why)
	}
	return nil
}

// clearContainerOperatorStopMarker removes name's marker once a stop of it
// has been recorded on its row by the ordinary path.
func (s *Server) clearContainerOperatorStopMarker(name string) {
	if s.dataDir == "" {
		return
	}
	if err := health.RemoveContainerOperatorStopMarker(s.dataDir, name); err != nil {
		slog.Warn("removing the container's operator-stop marker after its stop was recorded failed; the replay removes it", "container", name, "error", err)
	}
}

// replayContainerOperatorStops is ReplayOperatorStopMarkers for container
// markers. reason is the write quarantine, "" when out of it. It returns
// the markers still waiting, the corrupt ones, and whether one at owner
// epoch 0 waits (or the markers cannot be listed).
func (s *Server) replayContainerOperatorStops(ctx context.Context, reason string) (pending, corruptN int, waitEpoch0 bool) {
	names, err := health.ListContainerOperatorStopMarkers(s.dataDir)
	if err != nil {
		if operatorStopReplayLogDue("\x00ct-list") {
			slog.Error("operator-stop replay: the container marker directory cannot be read; every container with a marker stays held (repeated at most every 10m)",
				"dir", health.ContainerOperatorStopMarkerDir(s.dataDir), "error", err)
		}
		return 0, 0, true
	}
	corrupt := map[string]string{}
	for _, name := range names {
		m, ok, rerr := health.ReadContainerOperatorStopMarker(s.dataDir, name)
		if rerr != nil {
			corrupt[name] = rerr.Error()
			if operatorStopReplayLogDue("ct/" + name) {
				slog.Error("operator-stop replay: a container marker cannot be read; the container is held stopped on this host and the stop is not replayed (repeated at most every 10m)",
					"container", name, "error", rerr, "remedy", health.ContainerOperatorStopMarkerCorruptRemedy(name))
			}
			continue
		}
		if !ok || m.Host != s.hostName {
			continue // gone meanwhile, or another host's (a shared data dir)
		}
		wait := func() {
			pending++
			waitEpoch0 = waitEpoch0 || m.OwnerEpoch == 0
		}
		if reason != "" {
			wait()
			continue
		}
		unlock, locked := s.TryLockContainer(name)
		if !locked {
			wait()
			continue // an operation holds the container; next pass
		}
		err := s.replayContainerOperatorStopLocked(ctx, m)
		unlock()
		if err != nil {
			wait()
			if operatorStopReplayLogDue("ct/" + name) {
				slog.Warn("operator-stop replay: recording the forced container stop failed; the container stays held and it is tried again next pass (repeated at most every 10m)",
					"container", name, "error", err)
			}
		}
	}
	if reason == "" && s.db != nil {
		if err := health.ReportCorruptContainerOperatorStopMarkers(ctx, s.db, s.dataDir, s.hostName, corrupt); err != nil && operatorStopReplayLogDue("\x00ct-report") {
			slog.Warn("operator-stop replay: raising or resolving operator_stop_marker_corrupt for containers failed (repeated at most every 10m)", "error", err)
		}
	}
	return pending, len(corrupt), waitEpoch0
}

// replayContainerOperatorStopLocked records m's stop on its container's row
// and removes m. The caller holds the container lock, and the host is out
// of write quarantine.
func (s *Server) replayContainerOperatorStopLocked(ctx context.Context, m health.ContainerOperatorStopMarker) error {
	drop := func(why string) error {
		slog.Info("operator-stop replay: the container marker no longer applies; removed without recording", "container", m.Container, "why", why)
		return health.RemoveContainerOperatorStopMarker(s.dataDir, m.Container)
	}
	rec, err := corrosion.GetContainer(ctx, s.db, s.hostName, m.Container)
	switch {
	case err != nil:
		return fmt.Errorf("read the container: %w", err)
	case rec == nil:
		return drop("the container was deleted or is no longer on this host")
	case corrosion.IncarnationOf(rec.CreatedAt) != m.Incarnation:
		return drop("the container was deleted and created again (created_at " + rec.CreatedAt + ")")
	case rec.OwnerEpoch != m.OwnerEpoch:
		return drop(fmt.Sprintf("the container is owned under a later generation (owner epoch %d, the stop's %d)", rec.OwnerEpoch, m.OwnerEpoch))
	case rec.State == "stopped" && rec.StateDetail == "operator-stop":
		return drop("its operator stop is already recorded")
	}
	switch rec.State {
	case "running", "stopped", "error":
	default:
		return fmt.Errorf("%w (state %s)", errReplayHeld, rec.State)
	}
	if s.containerRuntime == nil {
		return errors.New("container runtime not wired")
	}
	st, serr := s.containerRuntime.StateContainer(ctx, m.Container)
	switch {
	case serr == nil && (st == string(lxc.StateRunning) || st == string(lxc.StateStarting)):
		// Started since by something that does not read the marker (an
		// older binary after a rollback, lxc-start): a stop is never
		// recorded over a running container.
		s.audit(ctx, "ct.stop", m.Container,
			"a forced stop made under write quarantine was not recorded: the container is "+st+" again on "+s.hostName, "error")
		return drop("the container runs again (" + st + ")")
	case serr != nil && !errors.Is(serr, lxc.ErrContainerNotFound):
		return fmt.Errorf("whether the container runs cannot be read: %w", serr)
	case serr == nil && st != string(lxc.StateStopped) && st != string(lxc.StateError):
		return fmt.Errorf("the container is %q; the stop is recorded once it settles", st)
	}
	// Guarded by the MARKER's identity, not the row just read.
	if err := corrosion.SetContainerStateDetailIfOwner(ctx, s.db, s.hostName, m.Container, m.Incarnation, m.OwnerEpoch, "stopped", "operator-stop"); err != nil {
		s.noteStateWriteFail(corrosion.OpContainerState, err)
		return fmt.Errorf("record operator-stop: %w", err)
	}
	s.audit(ctx, "ct.stop", m.Container,
		"`lv ct stop --force` made at "+m.StoppedAt+" while "+s.hostName+" was in write quarantine, recorded once it lifted", "ok")
	slog.Info("operator-stop replay: the forced container stop made under write quarantine is recorded", "container", m.Container)
	return health.RemoveContainerOperatorStopMarker(s.dataDir, m.Container)
}
