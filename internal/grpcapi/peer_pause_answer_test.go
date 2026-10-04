package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The health probe carries THIS run's enforcement.partition_pause, which a
// failover coordinator relies on (docs/design/partition-pause.md §4.3). It is
// the config, not the build: a host whose flag is off says so, unready or not.
//
// Mutation: report true unconditionally — the flag-off answer goes red.
func TestReady_ReportsThisRunsPartitionPauseFlag(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host")
	for _, on := range []bool{true, false} {
		s.SetPartitionPause(on)
		resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
		if err != nil {
			t.Fatalf("Ready: %v", err)
		}
		if resp.GetPartitionPause() != on {
			t.Errorf("enforcement.partition_pause=%v, Ready says %v", on, resp.GetPartitionPause())
		}
	}
	// An unready node still says what it would do: its flag is a fact about
	// its config, not about whether its database answers.
	s.SetPartitionPause(true)
	s.db.Close()
	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil || resp.GetReady() || !resp.GetPartitionPause() {
		t.Errorf("unready node: ready=%v partition_pause=%v err=%v, want false/true/nil",
			resp.GetReady(), resp.GetPartitionPause(), err)
	}
}

// scriptedReady answers each Ready with the next scripted reply.
type scriptedReady struct {
	pb.LiteVirtClient
	replies []readyReply
}

type readyReply struct {
	resp *pb.ReadyResponse
	err  error
}

func (c *scriptedReady) Ready(context.Context, *pb.ReadyRequest, ...grpc.CallOption) (*pb.ReadyResponse, error) {
	r := c.replies[0]
	c.replies = c.replies[1:]
	return r.resp, r.err
}

// PeerPausesOnLoss is the peer's LATEST answer, never an older one: the flag
// changes only with a restart, and the latest answer is the one from the run
// a coordinator last reached. That is lab finding P1: the coordinator relied
// on a cached Ping from before the host's flag went off.
//
// Mutations: keep the first answer (record never overwrites) — the flag-off
// check goes red; drop the answer on Unimplemented — the old-build check goes
// red; ignore host_name — the wrong-host check goes red; forget the last
// answer on a transport failure — the unreachable check goes red.
func TestPeerPausesOnLoss_FollowsTheLatestAnswer(t *testing.T) {
	ans := func(host string, pause bool) readyReply {
		return readyReply{resp: &pb.ReadyResponse{HostName: host, Ready: true, PartitionPause: pause}}
	}
	c := &scriptedReady{replies: []readyReply{
		ans("host-b", true),
		ans("host-b", false), // restarted with the flag off
		ans("host-b", true),  // and back on
		{err: errors.New("connection refused")},
		{err: status.Error(codes.Unimplemented, "unknown method Ready")},
		ans("host-b", true),
		ans("host-c", true), // the address now answers as another host
	}}
	s := testServer(t)
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return c, func() {}, nil
	}
	probe := func() { _, _, _ = s.PeerReady(context.Background(), "host-b", "127.0.0.1:1") }

	if s.PeerPausesOnLoss("host-b") {
		t.Fatal("a peer never probed reads as pausing")
	}
	probe()
	if !s.PeerPausesOnLoss("host-b") {
		t.Fatal("a peer that said it pauses reads as not pausing")
	}
	probe()
	if s.PeerPausesOnLoss("host-b") {
		t.Fatal("a peer whose latest answer said its flag is off still reads as pausing")
	}
	probe()
	probe() // unreachable: the last run reached still stands
	if !s.PeerPausesOnLoss("host-b") {
		t.Fatal("a transport failure erased the last answer; it says nothing about the run that answered")
	}
	probe() // a build without the field reached on a later run pauses nothing we know of
	if s.PeerPausesOnLoss("host-b") {
		t.Fatal("an Unimplemented answer left an older run's answer standing")
	}
	probe()
	probe()
	if s.PeerPausesOnLoss("host-b") {
		t.Fatal("another host's answer was taken as host-b's")
	}
}

// Two probes of one host can be in flight at once (the checker's and PeerUp's).
// The one SENT later wins, whichever returns last.
//
// Mutation: drop the asked comparison — the late-returning older answer
// overwrites and this goes red.
func TestPeerPauseAnswers_TheLaterProbeWins(t *testing.T) {
	var a peerPauseAnswers
	t0 := time.Unix(1_900_000_000, 0)
	a.record("host-b", t0.Add(time.Second), false) // sent later, returned first
	a.record("host-b", t0, true)                   // sent earlier, returned last
	if a.m["host-b"].pause {
		t.Fatal("an answer to an earlier probe overwrote a later one")
	}
}
