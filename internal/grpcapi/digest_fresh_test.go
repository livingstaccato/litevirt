package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func digestNamed(t *testing.T, resp *pb.StateDigestResponse, table string) *pb.TableDigest {
	t.Helper()
	for _, d := range resp.GetTables() {
		if d.GetName() == table {
			return d
		}
	}
	t.Fatalf("no %s digest", table)
	return nil
}

// fresh turns a caller's outgoing fresh-digest mark into the incoming
// metadata the server sees.
func fresh(ctx context.Context) context.Context {
	out, _ := metadata.FromOutgoingContext(corrosion.WithFreshDigest(context.Background()))
	return metadata.NewIncomingContext(ctx, out)
}

// A verifying caller (`lv cluster converge`, reseed) asks for the digest as of
// now; everyone else gets the cache. The difference shows only for a write the
// cache cannot see — another process's.
func TestGetStateDigest_FreshOnRequest(t *testing.T) {
	s := testServer(t)
	peer := peerCtxFor(t, s, "peer-1")
	first, err := s.GetStateDigest(peer, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.ExecOutOfProcessForTest(`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
		VALUES ('beneath', 'h', 'y', 'active', 'x', 'x')`); err != nil {
		t.Fatal(err)
	}
	cached, _ := s.GetStateDigest(peer, &emptypb.Empty{})
	if digestNamed(t, cached, "stacks").GetHash() != digestNamed(t, first, "stacks").GetHash() {
		t.Fatal("precondition: the unhooked write reached the cache; the test cannot tell cached from fresh")
	}
	now, err := s.GetStateDigest(fresh(peer), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got := digestNamed(t, now, "stacks"); got.GetCount() != 1 || got.GetHash() == digestNamed(t, first, "stacks").GetHash() {
		t.Fatalf("a fresh-digest request was served the cache: %+v", got)
	}

	// The sensitive lane honours it the same way.
	req := &pb.SensitiveStateRequest{Sender: "node-a"}
	sfirst, err := s.GetSensitiveStateDigest(replicationPeerCtx("node-a"), req)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.ExecOutOfProcessForTest(`INSERT INTO registry_credentials (id, registry, username, secret, created_at, updated_at)
		VALUES ('rc', 'r', 'u', 's', 'x', 'x')`); err != nil {
		t.Fatal(err)
	}
	snow, err := s.GetSensitiveStateDigest(fresh(replicationPeerCtx("node-a")), req)
	if err != nil {
		t.Fatal(err)
	}
	if digestNamed(t, snow, "registry_credentials").GetCount() != 1 ||
		digestNamed(t, sfirst, "registry_credentials").GetCount() != 0 {
		t.Fatal("a fresh sensitive-digest request was served the cache")
	}
}
