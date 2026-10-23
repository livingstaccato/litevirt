package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// EnsureDisks creates its stub through the directory it judges: a STATIC link
// below the target's own pool, or as the pool directory itself, makes it refuse
// instead of creating a stub where the link points.
//
// Red on d0fb47b0a (the create was by path). Mutation: open the stub's directory
// by path (openPinnedDir(filepath.Dir(stub.Path), ...)) instead of openDiskDir -
// the stub appears outside the pool and this is red. (Creating through the held
// directory rather than by name only matters against a swap after the open, which
// this static test does not reach.)
func TestFleet_EnsureDisksCreateRefusesAStaticLink(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, o *ownPoolScenario) string // returns the stub path
	}{
		{"link below the pool", func(t *testing.T, o *ownPoolScenario) string {
			if err := os.MkdirAll(o.nfs, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(o.out, filepath.Join(o.nfs, "sub")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(o.nfs, "sub", "planted")
		}},
		{"the pool directory itself a link", func(t *testing.T, o *ownPoolScenario) string {
			pdir := filepath.Join(o.nfs, "p")
			if err := os.MkdirAll(o.nfs, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(o.out, pdir); err != nil {
				t.Fatal(err)
			}
			o.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"nfsp": {Driver: "dir", Target: pdir}})
			return filepath.Join(pdir, "planted")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOwnPoolScenario(t, "sub")
			o.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"nfs1": {Driver: "dir", Target: o.nfs}})
			if err := os.MkdirAll(o.out, 0o755); err != nil {
				t.Fatal(err)
			}
			stub := tc.plant(t, o)
			_, err := o.c.PeerClient(o.src, o.dst).EnsureDisks(context.Background(), &pb.EnsureDisksRequest{
				VmName: "fp1", Disks: []*pb.DiskStub{{Path: stub, SizeBytes: 1 << 20}}})
			if err == nil {
				t.Errorf("EnsureDisks accepted a stub behind a link")
			}
			if _, lerr := os.Lstat(filepath.Join(o.out, "planted")); lerr == nil {
				t.Errorf("EnsureDisks created %s through the link", filepath.Join(o.out, "planted"))
			}
		})
	}
}

// When a later stub fails, EnsureDisks removes the ones it made through the
// directory they were made in: with that directory swapped for a link to one
// holding a same-named file, the file survives.
//
// Mutation: os.Remove(p) in undo - the file is unlinked and this is red.
func TestFleet_EnsureDisksUndoDoesNotFollowASwappedDirectory(t *testing.T) {
	o := newOwnPoolScenario(t, "sub")
	o.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"nfs1": {Driver: "dir", Target: o.nfs}})
	sub := filepath.Join(o.nfs, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(o.out, "first")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The second stub fails on its size (1<<62), after the first was made.
	swapped := false
	o.dst.Server.SetEnsureStubCreatedHookForTest(func() {
		swapped = true
		_ = os.Rename(sub, sub+".old")
		_ = os.Symlink(o.out, sub)
	})
	_, err := o.c.PeerClient(o.src, o.dst).EnsureDisks(context.Background(), &pb.EnsureDisksRequest{
		VmName: "fp1", Disks: []*pb.DiskStub{
			{Path: filepath.Join(sub, "first"), SizeBytes: 1 << 20},
			{Path: filepath.Join(o.nfs, "second"), SizeBytes: 1 << 62},
		}})
	if err == nil {
		t.Fatal("EnsureDisks with an impossible second stub succeeded")
	}
	if !swapped {
		t.Fatalf("the first stub was never created, so the undo had nothing to remove (EnsureDisks: %v)", err)
	}
	if b, rerr := os.ReadFile(victim); rerr != nil || string(b) != "victim" {
		t.Errorf("the undo removed the file behind the swapped link (err %v, %q)", rerr, b)
	}
}
