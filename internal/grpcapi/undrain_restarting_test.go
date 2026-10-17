package grpcapi

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// pingPeer answers Ping, or fails it with err.
type pingPeer struct {
	pb.LiteVirtClient
	err   error
	calls *atomic.Int32
	// as is the host name the peer answers in; empty: "w1".
	as string
}

func (p pingPeer) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	if p.calls != nil {
		p.calls.Add(1)
	}
	if p.err != nil {
		return nil, p.err
	}
	as := p.as
	if as == "" {
		as = "w1"
	}
	return &pb.PingResponse{HostName: as}, nil
}

func undrainServer(t *testing.T, state string, pingErr error) (*Server, *atomic.Int32) {
	t.Helper()
	s := testServerCov(t)
	insertTestHostCov(t, adminCtx(), s.db, "w1", state)
	calls := &atomic.Int32{}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host != "w1" {
			return nil, nil, errors.New("unexpected peer " + host)
		}
		return pingPeer{err: pingErr, calls: calls}, func() {}, nil
	}
	return s, calls
}

func hostStateOf(t *testing.T, s *Server, name string) string {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), s.db, name)
	if err != nil || h == nil {
		t.Fatalf("read host %s: %v", name, err)
	}
	return h.State
}

// TestUndrainHost_RestartingHostThatDoesNotAnswerIsRefused: a host recorded
// 'upgrading' whose daemon does not answer is restarting. Undrain refuses with
// FailedPrecondition and leaves it 'upgrading', which keeps its restart
// allowance (lab 1, 2026-10-17: the undrain wrote 'active', and the host was
// fenced 19 s later, before its daemon served).
//
// Mutation: drop the 'upgrading' check from UndrainHost — it records 'active'.
func TestUndrainHost_RestartingHostThatDoesNotAnswerIsRefused(t *testing.T) {
	s, calls := undrainServer(t, "upgrading", status.Error(codes.Unavailable, "connection refused"))
	_, err := s.UndrainHost(adminCtx(), &pb.UndrainHostRequest{Name: "w1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("undrain of a restarting host that does not answer: err=%v, want FailedPrecondition", err)
	}
	if msg := status.Convert(err).Message(); !strings.Contains(msg, "w1 is restarting") ||
		!strings.Contains(msg, "turns active by itself once its daemon serves") {
		t.Errorf("message %q does not say the host is restarting and turns active by itself", msg)
	}
	if got := hostStateOf(t, s, "w1"); got != "upgrading" {
		t.Errorf("host state = %q after a refused undrain, want 'upgrading'", got)
	}
	if calls.Load() == 0 {
		t.Error("the host was not asked whether it serves")
	}
}

// TestUndrainHost_RestartingHostThatAnswersTurnsActive: the documented remedy
// for upgrading_unconfirmed — a host whose daemon serves but could not record
// itself active — still works: it answers, and undrain records it active.
//
// Mutation: refuse every 'upgrading' host — this undrain fails.
func TestUndrainHost_RestartingHostThatAnswersTurnsActive(t *testing.T) {
	s, calls := undrainServer(t, "upgrading", nil)
	h, err := s.UndrainHost(adminCtx(), &pb.UndrainHostRequest{Name: "w1"})
	if err != nil {
		t.Fatalf("undrain of an 'upgrading' host that answers: %v", err)
	}
	if h.State != pb.HostState_HOST_ACTIVE || hostStateOf(t, s, "w1") != "active" {
		t.Errorf("host reply %v, recorded %q; want active", h.State, hostStateOf(t, s, "w1"))
	}
	if calls.Load() == 0 {
		t.Error("the host was not asked whether it serves")
	}
}

// TestUndrainHost_DrainedHostIsNotPinged: undrain of a draining host is as it
// was — recorded active whether or not the host answers, with no Ping.
func TestUndrainHost_DrainedHostIsNotPinged(t *testing.T) {
	for _, st := range []string{"draining", "maintenance"} {
		t.Run(st, func(t *testing.T) {
			s, calls := undrainServer(t, st, status.Error(codes.Unavailable, "down"))
			if _, err := s.UndrainHost(adminCtx(), &pb.UndrainHostRequest{Name: "w1"}); err != nil {
				t.Fatalf("undrain of a %s host: %v", st, err)
			}
			if got := hostStateOf(t, s, "w1"); got != "active" {
				t.Errorf("host state = %q, want active", got)
			}
			if calls.Load() != 0 {
				t.Errorf("a %s host was pinged %d times", st, calls.Load())
			}
		})
	}
}

// TestUndrainHost_RestartingSelfTurnsActive: the node handling the undrain is
// the host itself, so its daemon serves; no Ping is needed.
func TestUndrainHost_RestartingSelfTurnsActive(t *testing.T) {
	s, calls := undrainServer(t, "upgrading", status.Error(codes.Unavailable, "down"))
	insertTestHostCov(t, adminCtx(), s.db, s.hostName, "upgrading")
	if _, err := s.UndrainHost(adminCtx(), &pb.UndrainHostRequest{Name: s.hostName}); err != nil {
		t.Fatalf("undrain of this node itself: %v", err)
	}
	if got := hostStateOf(t, s, s.hostName); got != "active" {
		t.Errorf("host state = %q, want active", got)
	}
	if calls.Load() != 0 {
		t.Errorf("pinged a peer %d times for this node itself", calls.Load())
	}
}

// TestUndrainHost_AnswerInAnotherNameIsRefused: a Ping answered by a daemon
// that is not the host (its address reaches another node, as on a NAT'd lab
// where every node dials itself) does not show the host serves.
//
// Mutation: drop the host-name check from pingHost — the undrain records the
// restarting host active.
func TestUndrainHost_AnswerInAnotherNameIsRefused(t *testing.T) {
	s, calls := undrainServer(t, "upgrading", nil)
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return pingPeer{calls: calls, as: "w2"}, func() {}, nil
	}
	_, err := s.UndrainHost(adminCtx(), &pb.UndrainHostRequest{Name: "w1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("undrain answered in another host's name: err=%v, want FailedPrecondition", err)
	}
	if !strings.Contains(status.Convert(err).Message(), `answered as "w2"`) {
		t.Errorf("refusal %q does not name the host that answered", status.Convert(err).Message())
	}
	if got := hostStateOf(t, s, "w1"); got != "upgrading" {
		t.Errorf("host state = %q, want 'upgrading'", got)
	}
}

// TestUndrainHost_RestartRecordedAfterTheReadIsNotOverwritten: undrain read
// the host 'active', and the host's SIGTERM recorded it 'upgrading' before the
// write. The write is made only from the state read, so it does not land; the
// state is read again and the undrain goes the restarting host's way: its
// daemon does not answer, so it is refused and the host stays 'upgrading'.
//
// Mutation: make undrainFrom's write unconditional (UpdateHostState) — the
// host is recorded active over its SIGTERM's write.
func TestUndrainHost_RestartRecordedAfterTheReadIsNotOverwritten(t *testing.T) {
	s, calls := undrainServer(t, "upgrading", status.Error(codes.Unavailable, "stopping"))
	err := s.undrainFrom(adminCtx(), "w1", "active")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("undrain over a SIGTERM's write: err=%v, want FailedPrecondition", err)
	}
	if got := hostStateOf(t, s, "w1"); got != "upgrading" {
		t.Errorf("host state = %q, want the SIGTERM's 'upgrading'", got)
	}
	if calls.Load() == 0 {
		t.Error("the host recorded 'upgrading' since the read was not asked whether it serves")
	}
}

// TestUndrainHost_StateChangedToAnotherDrainedStateStillUndrains: a state
// that changed between the read and the write to anything but 'upgrading'
// (draining -> maintenance) is read again and undrained, as before.
func TestUndrainHost_StateChangedToAnotherDrainedStateStillUndrains(t *testing.T) {
	s, _ := undrainServer(t, "maintenance", nil)
	if err := s.undrainFrom(adminCtx(), "w1", "draining"); err != nil {
		t.Fatalf("undrain after the state changed to maintenance: %v", err)
	}
	if got := hostStateOf(t, s, "w1"); got != "active" {
		t.Errorf("host state = %q, want active", got)
	}
}
