// Fleet scenario for the global ISO library in sync mode: an upload on one
// host reaches another over the real peer RPC (FetchISOLibraryFile, host-cert
// mTLS), verified against the replicated library record; a VM starts there only
// once its copy matches; a removal is followed.
package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

func TestFleet_ISOLibrarySync(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	a, b := c.Nodes[0], c.Nodes[1]
	a.DB.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.SetISOLibraryMode(ctx, a.DB, corrosion.ISOLibrarySync, "test"); err != nil {
		t.Fatal(err)
	}
	dirs := map[string]string{}
	for _, n := range c.Nodes {
		dirs[n.Name] = t.TempDir()
		if err := corrosion.UpsertStoragePool(ctx, n.DB, corrosion.StoragePoolRecord{
			HostName: n.Name, Name: grpcapi.GlobalISOLibraryName, Driver: "dir", Target: dirs[n.Name],
			Options: grpcapi.GlobalISOLibraryOptions(), State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}

	body := []byte("CD001 debian netinst")
	sum := sha256.Sum256(body)
	up, err := c.SelfClient(a).UploadStoragePoolContent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*pb.UploadStoragePoolContentRequest{
		{PoolName: grpcapi.GlobalISOLibraryName, Host: a.Name, Filename: "debian.iso"}, {Chunk: body},
	} {
		if err := up.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := up.CloseAndRecv(); err != nil {
		t.Fatalf("upload on %s: %v", a.Name, err)
	}
	e, ok, err := corrosion.GetISOCatalogEntry(ctx, b.DB, "debian.iso")
	if err != nil || !ok || e.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("the library record %s sees: %+v found=%v err=%v", b.Name, e, ok, err)
	}

	// Before b has synced, its listing says so.
	ls, err := c.SelfClient(b).ListISOs(ctx, &pb.ListISOsRequest{})
	if err != nil || len(ls.GetIsos()) != 1 || ls.GetIsos()[0].GetSyncState() != "syncing" {
		t.Fatalf("%s before sync: %+v err=%v, want debian.iso syncing", b.Name, ls.GetIsos(), err)
	}

	if err := b.Server.SyncISOLibrary(ctx); err != nil {
		t.Fatalf("sync on %s: %v", b.Name, err)
	}
	got, err := os.ReadFile(filepath.Join(dirs[b.Name], "debian.iso"))
	if err != nil || string(got) != string(body) {
		t.Fatalf("%s's copy = %q err=%v", b.Name, got, err)
	}
	ls, err = c.SelfClient(b).ListISOs(ctx, &pb.ListISOsRequest{})
	if err != nil || len(ls.GetIsos()) != 1 || ls.GetIsos()[0].GetSyncState() != "ok" {
		t.Fatalf("%s after sync: %+v err=%v, want debian.iso ok", b.Name, ls.GetIsos(), err)
	}

	// A removal on a is followed on b.
	if _, err := c.SelfClient(a).DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{
		PoolName: grpcapi.GlobalISOLibraryName, Host: a.Name, Filename: "debian.iso",
	}); err != nil {
		t.Fatalf("delete on %s: %v", a.Name, err)
	}
	if err := b.Server.SyncISOLibrary(ctx); err != nil {
		t.Fatalf("sync after delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirs[b.Name], "debian.iso")); !os.IsNotExist(err) {
		t.Fatalf("%s kept a removed library file: %v", b.Name, err)
	}
	if _, err := c.SelfClient(b).PullISO(ctx, &pb.PullISORequest{Ref: "nowhere/x.iso", Url: "http://127.0.0.1:1/x"}); status.Code(err) != codes.NotFound {
		t.Fatalf("pull into a pool that is not on the host: %v", err)
	}
}
