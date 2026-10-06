package fleet

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A pool request for another host is forwarded, and reaches the owner as a
// peer — trusted as admin. So the host-path authority must be decided on the
// entry node, and the owner must still refuse its own protected directories,
// which only it knows.
func TestFleet_PoolHostPathGateHoldsAcrossTheForward(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	entry, owner := c.Nodes[0], c.Nodes[1]
	admin := c.SelfClient(entry)

	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "op", Password: "p4ssw0rd", Role: "operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "op", Name: "op"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	op := c.bearerClient(entry, tok.Token)

	_, err = op.CreateStoragePool(ctx, &pb.CreateStoragePoolRequest{
		Name: "evil", Driver: "dir", Target: t.TempDir(), Host: owner.Name,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator forwarding a dir pool: got %v, want PermissionDenied", err)
	}
	if _, ok, _ := corrosion.GetStoragePool(ctx, owner.DB, owner.Name, "evil"); ok {
		t.Fatalf("the owner created the refused pool")
	}

	// The owner's data dir is not the entry's: only the owner can refuse it.
	ownerData := filepath.Join(c.tmpRoot, owner.Name, "data")
	_, err = admin.CreateStoragePool(ctx, &pb.CreateStoragePoolRequest{
		Name: "inner", Driver: "dir", Target: ownerData, Host: owner.Name,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("admin forwarding a pool onto the owner's data dir: got %v, want InvalidArgument", err)
	}
}
