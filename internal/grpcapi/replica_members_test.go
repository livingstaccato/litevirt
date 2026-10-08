package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// I-C (final-rereview-integrate-3.md): "every host lists replicas" asks the
// hosts admitted to memberlist membership — the peers replication reaches,
// as capabilities.ReplicationGated tokens confirm against — so a host row
// that is dead, fenced or removed for good no longer holds the dual write
// and the prune hold forever. A member on a main build still holds them.

// membersHosts gives s's cluster the host rows named, and the admitted
// membership members.
func membersHosts(t *testing.T, s *Server, rows []string, members ...string) {
	t.Helper()
	for i, h := range rows {
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
			Name: h, Address: "10.0.0." + string(rune('2'+i)), State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	var peers []corrosion.PeerInfo
	for _, m := range members {
		peers = append(peers, corrosion.PeerInfo{Name: m, Addr: "10.0.0.1:7946"})
	}
	s.db.SetMembersForTests(func() []corrosion.PeerInfo { return peers })
	t.Cleanup(func() { s.db.SetMembersForTests(nil) })
}

func TestEveryHostListsReplicas_ADeadHostRowDoesNotHoldIt(t *testing.T) {
	f := newPoolFixture(t)
	membersHosts(t, f.s, []string{"new-host", "dead-host"}, "new-host")
	f.s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host == "new-host" {
			return newReceiver{}, func() {}, nil
		}
		return unsureReceiver{}, func() {}, nil // dead-host: no answer
	}
	replicaPeersMemos.Delete(f.s)
	t.Cleanup(func() { replicaPeersMemos.Delete(f.s) })
	if !f.s.everyHostListsReplicas(context.Background()) {
		t.Fatal("a host row outside the cluster's membership (dead, fenced, removed) holds the dual write and the prune hold")
	}
}

func TestEveryHostListsReplicas_AMainBuildMemberStillHoldsIt(t *testing.T) {
	f := newPoolFixture(t)
	membersHosts(t, f.s, []string{"new-host", "main-host"}, "new-host", "main-host")
	f.s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host == "new-host" {
			return newReceiver{}, func() {}, nil
		}
		return &legacyReceiver{}, func() {}, nil
	}
	replicaPeersMemos.Delete(f.s)
	t.Cleanup(func() { replicaPeersMemos.Delete(f.s) })
	if f.s.everyHostListsReplicas(context.Background()) {
		t.Fatal("a member on a main build (no ListReplicas) does not hold the dual write")
	}
}

// Before gossip has admitted anyone, a cluster with other live host rows is
// not taken to be all on this build.
func TestEveryHostListsReplicas_NoMembersYetIsNotAll(t *testing.T) {
	f := newPoolFixture(t)
	membersHosts(t, f.s, []string{"main-host"})
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &legacyReceiver{}, func() {}, nil
	}
	replicaPeersMemos.Delete(f.s)
	t.Cleanup(func() { replicaPeersMemos.Delete(f.s) })
	if f.s.everyHostListsReplicas(context.Background()) {
		t.Fatal("with no admitted member yet, a cluster with another live host row was taken to be all on this build")
	}
}

// blockingReceiver answers ListReplicas only once released.
type blockingReceiver struct {
	pb.LiteVirtClient
	entered, release chan struct{}
}

func (b *blockingReceiver) ListReplicas(ctx context.Context, _ *pb.ListReplicasRequest, _ ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	close(b.entered)
	<-b.release
	return newReceiver{}.ListReplicas(ctx, nil)
}

// The probes (up to 10 s a host) run with no lock held: a run asking while
// another's probe is in flight is not queued behind it.
func TestEveryHostListsReplicas_NoLockIsHeldAcrossAProbe(t *testing.T) {
	f := newPoolFixture(t)
	membersHosts(t, f.s, []string{"slow-host"}, "slow-host")
	b := &blockingReceiver{entered: make(chan struct{}), release: make(chan struct{})}
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return b, func() {}, nil }
	replicaPeersMemos.Delete(f.s)
	t.Cleanup(func() { replicaPeersMemos.Delete(f.s) })
	done := make(chan bool, 1)
	go func() { done <- f.s.everyHostListsReplicas(context.Background()) }()
	select {
	case <-b.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the probe never reached the host")
	}
	m := replicaPeersMemoOf(f.s)
	locked := m.mu.TryLock()
	if locked {
		m.mu.Unlock()
	}
	close(b.release)
	if !<-done {
		t.Fatal("a host on this build answered, yet not every host lists replicas")
	}
	if !locked {
		t.Fatal("the memo's lock is held across a host probe: concurrent replication runs queue behind it")
	}
}
