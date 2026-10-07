// Fleet scenario: per-file confinement of a shared pool directory survives a
// forward.
//
// A pool on <data_dir>/disks (or a directory two pools share) shows a caller
// only its project's files. The files live on the pool's host, so a content
// call that enters on another node is forwarded there, and reaches it under
// the entry node's host certificate — a trusted peer. Only a real two-node
// fleet, with a real forwarded RPC under a real peer certificate, proves the
// pool's host confines the call as the user who made it, not as that peer.
package fleet

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestFleet_SharedPoolContentIsConfinedAcrossTheForward(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	entry, owner := c.Node("node-0"), c.Node("node-1")
	disks := filepath.Join(c.tmpRoot, owner.Name, "data", "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}

	// An older cluster's owner: acme's pool pa and bravo's pool pb are both
	// its <data_dir>/disks, holding both projects' files.
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: owner.Name, Name: "pa", Driver: "local", Target: disks, Project: "acme", State: "active"},
		{HostName: owner.Name, Name: "pb", Driver: "local", Target: disks, Project: "bravo", State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, owner.DB, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []struct{ vm, project, pool string }{{"avm", "acme", "pa"}, {"bvm", "bravo", "pb"}} {
		path := filepath.Join(disks, v.vm+"-root.qcow2")
		if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{Name: v.vm, HostName: owner.Name, State: "stopped", Project: v.project}, nil,
			[]corrosion.DiskRecord{{VMName: v.vm, DiskName: "root", HostName: owner.Name, Path: path, StorageType: "local", StorageVolume: v.pool}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"avm-root.qcow2", "bvm-root.qcow2", "debian.iso", "stray.qcow2"} {
		if err := os.WriteFile(filepath.Join(disks, n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Real users with real API tokens, bound per project, and a real auth
	// engine on both nodes (the harness wires none by default).
	for _, n := range []*Node{entry, owner} {
		if err := auth.SeedBuiltinRoles(ctx, n.DB); err != nil {
			t.Fatalf("SeedBuiltinRoles: %v", err)
		}
	}
	admin := c.SelfClient(entry)
	tokens := map[string]string{}
	for _, u := range []struct{ name, project string }{{"carol", "acme"}, {"dave", "bravo"}} {
		pw := u.name + "s-password-0123456789"
		if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: u.name, Password: pw, Role: "operator"}); err != nil {
			t.Fatalf("CreateUser(%s): %v", u.name, err)
		}
		if _, err := admin.GrantRole(ctx, &pb.GrantRoleRequest{
			Path: "/projects/" + u.project, Role: "Operator", Principal: "user:" + u.name + "@local", Propagate: true,
		}); err != nil {
			t.Fatalf("GrantRole(%s): %v", u.name, err)
		}
		tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: u.name, Name: u.name})
		if err != nil {
			t.Fatalf("CreateToken(%s): %v", u.name, err)
		}
		tokens[u.name] = tok.Token
	}
	// Each node holds the other's rows: the entry reads the pool row before
	// forwarding, the owner resolves the forwarded token and bindings.
	ownerDump, entryDump := pullDump(t, c, owner), pullDump(t, c, entry)
	if err := entry.DB.MergeStateBytesLWW(ownerDump); err != nil {
		t.Fatal(err)
	}
	if err := owner.DB.MergeStateBytesLWW(entryDump); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{entry, owner} {
		e := auth.NewEngine(n.DB)
		if err := e.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		n.Server.SetAuthEngine(e)
	}
	carol := c.bearerClient(entry, tokens["carol"])
	dave := c.bearerClient(entry, tokens["dave"])

	upload := func(cl pb.LiteVirtClient, pool, name string) error {
		up, err := cl.UploadStoragePoolContent(ctx)
		if err != nil {
			return err
		}
		if err := up.Send(&pb.UploadStoragePoolContentRequest{PoolName: pool, Host: owner.Name, Filename: name}); err != nil {
			return err
		}
		if err := up.Send(&pb.UploadStoragePoolContentRequest{Chunk: []byte(name)}); err != nil {
			return err
		}
		_, err = up.CloseAndRecv()
		if err == io.EOF {
			err = nil
		}
		return err
	}
	list := func(cl pb.LiteVirtClient, pool string) []string {
		resp, err := cl.ListStoragePoolContents(ctx, &pb.ListStoragePoolContentsRequest{PoolName: pool, Host: owner.Name})
		if err != nil {
			t.Fatalf("list %s through the entry node: %v", pool, err)
		}
		var out []string
		for _, f := range resp.GetContents() {
			out = append(out, f.GetName())
		}
		sort.Strings(out)
		return out
	}

	if err := upload(dave, "pb", "bravo.iso"); err != nil {
		t.Fatalf("bravo uploads through the entry node: %v", err)
	}
	if err := upload(carol, "pa", "acme.iso"); err != nil {
		t.Fatalf("acme uploads through the entry node: %v", err)
	}
	if got := list(carol, "pa"); !slices.Equal(got, []string{"acme.iso", "avm-root.qcow2", "debian.iso"}) {
		t.Fatalf("acme's listing through the entry node = %v, want [acme.iso avm-root.qcow2 debian.iso]", got)
	}
	if got := list(dave, "pb"); !slices.Equal(got, []string{"bravo.iso", "bvm-root.qcow2", "debian.iso"}) {
		t.Fatalf("bravo's listing through the entry node = %v, want [bravo.iso bvm-root.qcow2 debian.iso]", got)
	}
	for _, n := range []string{"bravo.iso", "stray.qcow2"} {
		_, err := carol.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{PoolName: "pa", Host: owner.Name, Filename: n})
		if status.Code(err) != codes.NotFound {
			t.Errorf("acme deleting %s through the entry node: got %v, want NotFound", n, err)
		}
	}
	if _, err := os.Stat(filepath.Join(disks, "uploads", "bravo.iso")); err != nil {
		t.Errorf("bravo's upload was deleted: %v", err)
	}
	if _, err := carol.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{PoolName: "pa", Host: owner.Name, Filename: "acme.iso"}); err != nil {
		t.Errorf("acme deleting its own upload through the entry node: %v", err)
	}
}
