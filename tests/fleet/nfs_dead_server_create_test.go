// Fleet scenario for an NFS server that stops answering while its export is
// mounted (lab 2 F-2): a pool create on that host, asked through another
// node, neither hangs nor lets a pool sit over another.

package fleet

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// F-2: a dir pool created on the host whose nfs pool's server does not
// answer — asked through another node — is created promptly, and that host
// keeps answering: the overlap with the nfs pool's mount point is decided
// from the mount table, with no stat of the dead mount. A pool whose overlap
// can only be decided on the dead mount is refused, promptly, never created.
func TestFleet_APoolCreateBesideAnNFSPoolWhoseServerDoesNotAnswer(t *testing.T) {
	mt := &rebootedMounts{dirs: map[string]string{}}
	t.Cleanup(storage.OverrideNosymfollowSupportForTest(false))
	t.Cleanup(storage.OverrideMountInfoForTest(mt.info))
	t.Cleanup(storage.OverrideNFSMountCommandForTest(mt.run))
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 1015})
	owner, peer := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const source = "10.9.9.41:/srv/lv"
	if err := corrosion.UpsertStoragePool(ctx, owner.DB, corrosion.StoragePoolRecord{
		HostName: owner.Name, Name: "shared", Driver: "nfs", Source: source, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	dir := storage.NFSPoolMountDir(filepath.Join(c.tmpRoot, owner.Name, "data"), storage.Config{Driver: "nfs", Source: source})
	mt.mu.Lock()
	mt.dirs[dir] = source // mounted; its server is about to stop answering
	mt.mu.Unlock()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	t.Cleanup(storage.OverrideFSCallBoundForTest(500 * time.Millisecond))
	t.Cleanup(storage.OverridePathResolverForTest(func(p string) string {
		if rel, err := filepath.Rel(dir, p); err == nil && !strings.HasPrefix(rel, "..") {
			<-release
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}))

	create := func(name, target string) error {
		done := make(chan error, 1)
		go func() {
			_, err := c.SelfClient(peer).CreateStoragePool(ctx, &pb.CreateStoragePoolRequest{
				Name: name, Driver: "dir", Target: target, Host: owner.Name,
			})
			done <- err
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(15 * time.Second):
			return errors.New("timed out: the create waited on the NFS server that does not answer")
		}
	}
	if err := create("beside", t.TempDir()); err != nil {
		t.Fatalf("a dir pool create beside the hung nfs pool, through the peer: %v", err)
	}
	// Inside the dead mount: whether it overlaps cannot be verified (nor is
	// the directory usable); refused, not created.
	err := create("inside", filepath.Join(dir, "sub"))
	if err == nil {
		t.Fatal("a pool inside the mount of an nfs pool whose server does not answer was created")
	}
	if strings.Contains(err.Error(), "timed out") {
		t.Fatal(err)
	}
	if _, err := c.PeerClient(peer, owner).ListStoragePools(ctx, &pb.ListStoragePoolsRequest{}); err != nil {
		t.Fatalf("the owner did not answer: %v", err)
	}
	eventually(t, 20*time.Second, "the peer to see the created pool", func() bool {
		r, ok, err := corrosion.GetStoragePool(ctx, peer.DB, owner.Name, "beside")
		return err == nil && ok && r.Driver == "dir"
	})
	if _, ok, _ := corrosion.GetStoragePool(ctx, owner.DB, owner.Name, "inside"); ok {
		t.Fatalf("pool %q was created", "inside")
	}
}
