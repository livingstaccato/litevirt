package grpcapi

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

const qcsReason = "rolled back below latched token(s): x"

// qcsServer is a server on host-a owning container web, running.
func qcsServer(t *testing.T) (*Server, *fakeCTRuntime) {
	t.Helper()
	s := testServerWithLocks(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "web", Template: "download", Distro: "alpine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "web"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return s, rt
}

func qcsCTRow(t *testing.T, s *Server) *corrosion.ContainerRecord {
	t.Helper()
	ct, err := corrosion.GetContainer(context.Background(), s.db, s.hostName, "web")
	if err != nil || ct == nil {
		t.Fatalf("GetContainer: %+v %v", ct, err)
	}
	return ct
}

// qcsMark writes web's marker for row's current identity.
func qcsMark(t *testing.T, s *Server, row *corrosion.ContainerRecord) {
	t.Helper()
	if err := health.WriteContainerOperatorStopMarker(s.dataDir, health.ContainerOperatorStopMarker{
		Container: "web", Host: s.hostName, Incarnation: corrosion.IncarnationOf(row.CreatedAt),
		OwnerEpoch: row.OwnerEpoch, StoppedAt: "t", Quarantine: qcsReason,
	}); err != nil {
		t.Fatal(err)
	}
}

func qcsMarked(t *testing.T, s *Server) bool {
	t.Helper()
	p, _ := health.ContainerOperatorStopMarkerPath(s.dataDir, "web")
	_, err := os.Stat(p)
	return err == nil
}

// The forced stop's marker is on disk at the moment the runtime stops the
// container, and the row is not written.
//
// Mutation: the marker written after the stop: red.
func TestStopContainer_QuarantinedForceWritesMarkerBeforeStop(t *testing.T) {
	s, rt := qcsServer(t)
	s.db.SetWriteQuarantine(func() string { return qcsReason })
	stops, markedAtStop := 0, true
	rt.stopHook = func() { stops++; markedAtStop = markedAtStop && qcsMarked(t, s) }
	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("forced stop: %v", err)
	}
	if stops == 0 || !markedAtStop {
		t.Errorf("the container was stopped (%d stop(s)) before its marker was on disk", stops)
	}
	if row := qcsCTRow(t, s); row.State != "running" {
		t.Errorf("row %s: the quarantined stop wrote the row", row.State)
	}
}

// A forced stop whose runtime stop fails leaves no marker when the container
// still runs (it would hold a stop that did not happen), and keeps it when
// whether it runs cannot be read.
//
// Mutation: the marker kept on a failed stop of a running container: red.
func TestStopContainer_QuarantinedForceStopFailedMarker(t *testing.T) {
	s, rt := qcsServer(t)
	s.db.SetWriteQuarantine(func() string { return qcsReason })
	rt.stopErr = errors.New("lxc-stop web: timed out")
	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "web", Force: true}); status.Code(err) != codes.Internal {
		t.Fatalf("failed forced stop: %v, want Internal", err)
	}
	if qcsMarked(t, s) {
		t.Errorf("a stop that did not happen left its marker")
	}
	rt.stateErrByName = map[string]error{"web": errors.New("lxc-info: busy")}
	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "web", Force: true}); status.Code(err) != codes.Internal {
		t.Fatalf("failed forced stop, state unreadable: %v, want Internal", err)
	}
	if !qcsMarked(t, s) {
		t.Errorf("the marker of a stop that may have happened was removed")
	}
}

// Every runtime start of a held container is refused, wherever it comes
// from (startContainerArmed: snapshot revert, restore, migrate rollback);
// a marker for an earlier ownership holds nothing.
//
// Mutation: the backstop in startContainerArmed removed: red.
func TestStartContainerArmed_HeldByOperatorStopMarker(t *testing.T) {
	s, rt := qcsServer(t)
	row := qcsCTRow(t, s)
	qcsMark(t, s, row)
	before := len(rt.startCalls)
	if err := s.startContainerArmed(context.Background(), "web"); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "held stopped") {
		t.Fatalf("startContainerArmed with a marker: %v, want FailedPrecondition", err)
	}
	if len(rt.startCalls) != before {
		t.Fatalf("the held container was started: %v", rt.startCalls)
	}
	row.OwnerEpoch++
	qcsMark(t, s, row) // another generation's
	if err := s.startContainerArmed(context.Background(), "web"); err != nil {
		t.Fatalf("startContainerArmed with another generation's marker: %v", err)
	}
}

// The replay never records a stop over a container that runs again, and
// keeps the marker of a row in a state it does not write over.
//
// Mutations: the runs-again branch removed (the stop is recorded): red;
// errReplayHeld not returned for a pending row: red.
func TestReplayContainerOperatorStop_RunsAgainAndHeldState(t *testing.T) {
	s, _ := qcsServer(t)
	row := qcsCTRow(t, s)
	qcsMark(t, s, row) // the runtime still runs web
	m, _, err := health.ReadContainerOperatorStopMarker(s.dataDir, "web")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.replayContainerOperatorStopLocked(context.Background(), m); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if got := qcsCTRow(t, s); got.StateDetail == "operator-stop" {
		t.Errorf("a stop was recorded over a running container: %s/%q", got.State, got.StateDetail)
	}
	if qcsMarked(t, s) {
		t.Errorf("the marker of a container that runs again was kept")
	}

	if err := corrosion.SetContainerStateDetail(context.Background(), s.db, s.hostName, "web", "pending", "relocate-recreate"); err != nil {
		t.Fatal(err)
	}
	qcsMark(t, s, row)
	if err := s.replayContainerOperatorStopLocked(context.Background(), m); !errors.Is(err, errReplayHeld) {
		t.Fatalf("replay over a pending row: %v, want errReplayHeld", err)
	}
	if !qcsMarked(t, s) {
		t.Errorf("the marker of a held row was removed")
	}
}
