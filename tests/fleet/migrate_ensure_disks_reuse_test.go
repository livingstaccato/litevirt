package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// An earlier stub of this VM replaced by a LINK to a same-size qcow2 is not
// "reused": only a regular file is, so the link is replaced by a stub of its
// own and the mirror never writes into the link's target.
//
// Mutation: drop the IsRegular condition on the reuse in EnsureDisks - the link
// is reported reused, stays a link, and this is red.
func TestFleet_EnsureDisksDoesNotReuseALinkAsItsStub(t *testing.T) {
	o := newOwnPoolScenario(t, "sub")
	o.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"nfs1": {Driver: "dir", Target: o.nfs}})
	sub := filepath.Join(o.nfs, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(sub, "stub")
	peer := o.c.PeerClient(o.src, o.dst)
	req := &pb.EnsureDisksRequest{VmName: "fp1", Disks: []*pb.DiskStub{{Path: stub, SizeBytes: 1 << 20}}}
	if _, err := peer.EnsureDisks(context.Background(), req); err != nil {
		t.Fatalf("EnsureDisks 1: %v", err)
	}
	// Another tenant's image of the same size, and the stub swapped for a link to it.
	other := filepath.Join(o.out, "other.qcow2")
	if err := qcow2.Create(other, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(other)
	if err := os.Remove(stub); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, stub); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.EnsureDisks(context.Background(), req); err != nil {
		t.Fatalf("EnsureDisks 2: %v", err)
	}
	if fi, err := os.Lstat(stub); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("the stub is still not a regular file after EnsureDisks (%v, %v)", fi, err)
	}
	if after, _ := os.Stat(other); after == nil || before == nil || !os.SameFile(before, after) {
		t.Errorf("the other tenant's image was replaced")
	}
}
