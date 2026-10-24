// Fleet scenarios for the held-directory rules: the disk root itself, the
// source's read, the EnsureDisks stub replace, and the take-back (the
// re-review of 76e550e95).

package fleet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// sendDisk sends o's disk to the target as the source would, under ctx.
func sendDisk(ctx context.Context, t *testing.T, o *ownPoolScenario) error {
	t.Helper()
	up, err := o.c.PeerClient(o.src, o.dst).ReceiveMigrationDisk(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	var hd [16]byte
	binary.BigEndian.PutUint64(hd[:8], 0)
	binary.BigEndian.PutUint64(hd[8:], uint64(len(o.payload)))
	h.Write(hd[:])
	h.Write(o.payload)
	_ = up.Send(&pb.ReceiveMigrationDiskRequest{VmName: "fp1", Path: o.disk, SizeBytes: int64(len(o.payload))})
	_ = up.Send(&pb.ReceiveMigrationDiskRequest{Offset: 0, Data: o.payload})
	_ = up.Send(&pb.ReceiveMigrationDiskRequest{Sha256: hex.EncodeToString(h.Sum(nil))})
	_, err = up.CloseAndRecv()
	return err
}

// The target's own pool directory ITSELF replaced by a link (a dir pool that is
// a subdirectory of an NFS export, whose writer plants the link): the receive
// is refused and nothing is written where the link points. Run on a pool below
// mounts/, which must stay inside that area once resolved.
//
// Mutation: drop the check argument in openDiskDir - the file lands outside and
// this is red.
func TestFleet_ColdMigrationRefusesAnOwnPoolDirectoryThatIsItselfALink(t *testing.T) {
	o := newOwnPoolScenario(t, "p")
	pdir := filepath.Join(o.nfs, "p")
	ref := grpcapi.StoragePoolRef{Driver: "dir", Target: pdir}
	o.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"nfsp": ref})
	if err := os.Symlink(o.targetFile(o.out), o.targetFile(pdir)); err != nil {
		t.Fatal(err)
	}
	if err := sendDisk(context.Background(), t, o); err == nil {
		t.Errorf("the receive into a pool directory that is a link succeeded")
	}
	if o.wroteOutside() {
		t.Errorf("the receive followed the pool directory link and wrote %s", filepath.Join(o.out, "x.qcow2"))
	}
}

// A link planted on a parent of the disk inside the SOURCE's own pool is not
// followed: the move is refused and the file the link reaches is not sent.
//
// Mutation: read through hostDiskFile(path) again (drop the held directory in
// streamColdDisk) - the secret reaches the target and this is red.
func TestFleet_ColdMigrationSourceDoesNotReadThroughAParentLink(t *testing.T) {
	o := newOwnPoolScenario(t, "sub")
	o.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"nfs1": {Driver: "dir", Target: o.nfs}})
	srcFS := filepath.Join(o.c.tmpRoot, "fs-"+o.src.Name)
	secretDir := filepath.Join(srcFS, "secret-dir")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte("S"), len(o.payload))
	if err := os.WriteFile(filepath.Join(secretDir, "x.qcow2"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(srcFS, o.nfs, "sub")
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretDir, sub); err != nil {
		t.Fatal(err)
	}
	if err := o.migrate(); err == nil {
		t.Errorf("migrate --cold read through a parent link on the source")
	}
	if got, rerr := os.ReadFile(o.targetFile(o.disk)); rerr == nil && bytes.Equal(got, secret) {
		t.Errorf("the source followed a parent link and shipped %s to the target", filepath.Join(secretDir, "x.qcow2"))
	}
}

// EnsureDisks replacing a stub it made earlier removes through the directory it
// judges: after the stub's parent is swapped for a link to a directory holding a
// same-named file, a second EnsureDisks at another size is refused and the file
// stays.
//
// Mutation: os.Remove(stub.Path) at the replace site again - the file is
// unlinked and a new stub made there; this is red.
func TestFleet_EnsureDisksReplaceDoesNotFollowASwappedParent(t *testing.T) {
	o := newOwnPoolScenario(t, "sub")
	o.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"nfs1": {Driver: "dir", Target: o.nfs}})
	sub := filepath.Join(o.nfs, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(sub, "victim")
	peer := o.c.PeerClient(o.src, o.dst)
	if _, err := peer.EnsureDisks(context.Background(), &pb.EnsureDisksRequest{
		VmName: "fp1", Disks: []*pb.DiskStub{{Path: stub, SizeBytes: 1 << 20}}}); err != nil {
		t.Fatalf("EnsureDisks 1: %v", err)
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(o.out, "victim")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(sub, sub+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(o.out, sub); err != nil {
		t.Fatal(err)
	}
	_, err := peer.EnsureDisks(context.Background(), &pb.EnsureDisksRequest{
		VmName: "fp1", Disks: []*pb.DiskStub{{Path: stub, SizeBytes: 2 << 20}}})
	if err == nil {
		t.Errorf("EnsureDisks replaced a stub through a swapped parent")
	}
	if b, rerr := os.ReadFile(victim); rerr != nil || string(b) != "victim" {
		t.Errorf("the file behind the link was replaced (err %v, %d bytes)", rerr, len(b))
	}
}

// The take-back of a copy the source gave up on goes through the held
// directory: with the parent swapped for a link after the placement and before
// the take-back, the placed file is removed from the directory that was judged
// and a same-named file where the link points survives.
//
// Mutation: os.Remove(shown) in the take-back - the victim is removed and this
// is red.
func TestFleet_ColdMigrationTakeBackDoesNotFollowASwappedParent(t *testing.T) {
	o := newOwnPoolScenario(t, "pool")
	pool := o.targetFile(filepath.Join(o.nfs, "pool"))
	victim := filepath.Join(o.targetFile(o.out), "x.qcow2")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.dst.Server.SetColdDiskPlacedHookForTest(func() {
		if err := os.Rename(pool, pool+".judged"); err != nil {
			t.Errorf("swap: %v", err)
			return
		}
		if err := os.Symlink(o.targetFile(o.out), pool); err != nil {
			t.Errorf("swap: %v", err)
		}
		if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
			t.Errorf("victim: %v", err)
		}
		cancel()                           // the source gives up as the disk is placed
		time.Sleep(500 * time.Millisecond) // let the cancellation reach the receive
	})
	_ = sendDisk(ctx, t, o) // returns as soon as the client gives up; the target finishes after its sleep
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(filepath.Join(pool+".judged", "x.qcow2")); err != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "victim" {
		t.Errorf("the take-back removed or changed the file behind the swapped link (err %v, %q)", err, b)
	}
	if _, err := os.Lstat(filepath.Join(pool+".judged", "x.qcow2")); err == nil {
		t.Errorf("the placed copy was not taken back from the directory that was judged")
	}
}
