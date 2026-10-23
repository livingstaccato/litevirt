// Fleet scenarios: a cold-move receive and its cleanup act through the
// directory they judged, held open by descriptor, never through names that can
// be swapped for links afterwards (the re-review's m1, and the same flaw on the
// target's own pools).
//
// Each test is red on ca8968e9c, which resolved the parent twice and wrote
// through path strings.

package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// ownPoolScenario is fp1's disk under a pool both hosts have of their own
// (mounts/nfs1), with a link `sub` planted below it that points outside.
type ownPoolScenario struct {
	*foreignPoolScenario
	nfs, out string // logical paths: the pool directory, the link's target
}

func newOwnPoolScenario(t *testing.T, sub string) *ownPoolScenario {
	t.Helper()
	o := &ownPoolScenario{}
	o.foreignPoolScenario = newForeignPoolScenario(t,
		func(pool, _ string) string {
			o.nfs = filepath.Join(filepath.Dir(filepath.Dir(pool)), "mounts", "nfs1")
			o.out = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(pool))), "outside-own")
			return filepath.Join(o.nfs, sub, "x.qcow2")
		},
		func(pool, _ string) string { return pool })
	ref := grpcapi.StoragePoolRef{Driver: "dir", Target: o.nfs}
	o.src.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"default": {Driver: "local", Target: o.pool}, "nfs1": ref})
	o.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"nfs1": ref})
	if err := os.MkdirAll(o.targetFile(o.nfs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(o.targetFile(o.out), 0o755); err != nil {
		t.Fatal(err)
	}
	return o
}

func (o *ownPoolScenario) wroteOutside() bool {
	_, err := os.Lstat(filepath.Join(o.targetFile(o.out), "x.qcow2"))
	return err == nil
}

// A link planted below the target's OWN pool (an NFS export writer) is not
// followed: the move is refused and nothing is written outside the pool. Run
// with openat2 and with the O_NOFOLLOW walk of a kernel without it.
//
// Mutation: write through hostDiskFile(path) again (drop openPinnedDir in the
// receive) - the file lands outside and this is red.
func TestFleet_ColdMigrationDoesNotFollowALinkBelowTheTargetsOwnPool(t *testing.T) {
	for _, noOpenat2 := range []bool{false, true} {
		name := "openat2"
		if noOpenat2 {
			name = "openat-nofollow-walk"
		}
		t.Run(name, func(t *testing.T) {
			grpcapi.SetOpenat2DisabledForTest(noOpenat2)
			t.Cleanup(func() { grpcapi.SetOpenat2DisabledForTest(false) })
			o := newOwnPoolScenario(t, "sub")
			if err := os.Symlink(o.targetFile(o.out), o.targetFile(filepath.Join(o.nfs, "sub"))); err != nil {
				t.Fatal(err)
			}
			if err := o.migrate(); err == nil {
				t.Errorf("migrate --cold through a link below the target's pool succeeded")
			}
			if o.wroteOutside() {
				t.Errorf("the receive followed the link and wrote %s", filepath.Join(o.out, "x.qcow2"))
			}
		})
	}
}

// The directory the receive judged is the directory it writes: a component
// swapped for a link AFTER it was opened (here by a hook between the open and
// the write; an export writer in production) changes nothing. The file lands
// in the original directory, not where the link points.
//
// Mutation: as above - the write follows the swapped name, and this is red.
func TestFleet_ColdMigrationWritesThroughTheDirectoryItJudged(t *testing.T) {
	o := newOwnPoolScenario(t, "sub")
	sub := o.targetFile(filepath.Join(o.nfs, "sub"))
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	var swapped atomic.Bool
	o.dst.Server.SetColdDirOpenedHookForTest(func() {
		if swapped.Swap(true) {
			return
		}
		if err := os.Rename(sub, sub+".judged"); err != nil {
			t.Errorf("swap: %v", err)
			return
		}
		if err := os.Symlink(o.targetFile(o.out), sub); err != nil {
			t.Errorf("swap: %v", err)
		}
	})
	_ = o.migrate()
	if !swapped.Load() {
		t.Fatal("the hook never ran: the receive did not open the directory")
	}
	if o.wroteOutside() {
		t.Fatalf("the receive wrote through the swapped name into %s", o.out)
	}
	if _, err := os.Lstat(filepath.Join(sub+".judged", "x.qcow2")); err != nil {
		t.Errorf("the file is not in the directory that was judged: %v", err)
	}
}

// The reviewer's race, bounded by attempts: a writer flips a link in and out
// of a component with RENAME_EXCHANGE while cold moves run into a foreign pool
// directory. No attempt may write outside the target's areas.
//
// Mutation: as above - an attempt escapes (the old code did, in about twenty).
func TestFleet_ColdMigrationRaceBetweenJudgingAndWritingTheParent(t *testing.T) {
	deadline := time.Now().Add(20 * time.Second)
	for attempt := 1; attempt <= 40 && time.Now().Before(deadline); attempt++ {
		var def, outside string
		fp := newForeignPoolScenario(t,
			func(pool, _ string) string {
				def = pool
				outside = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(pool))), "outside-race")
				return filepath.Join(pool, "sub", "x.qcow2")
			},
			func(pool, _ string) string { return pool })
		sub := fp.targetFile(filepath.Join(def, "sub"))
		subL := fp.targetFile(filepath.Join(def, "subL"))
		out := fp.targetFile(outside)
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(out, subL); err != nil {
			t.Fatal(err)
		}
		var stop atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			for !stop.Load() {
				_ = unix.Renameat2(unix.AT_FDCWD, sub, unix.AT_FDCWD, subL, unix.RENAME_EXCHANGE)
			}
		}()
		merr := fp.migrate()
		stop.Store(true)
		<-done
		if _, err := os.Lstat(filepath.Join(out, "x.qcow2")); err == nil {
			t.Fatalf("attempt %d: the receive wrote outside the areas at %s (migrate: %v)", attempt, filepath.Join(out, "x.qcow2"), merr)
		}
		fp.c.Stop()
	}
}

// Cleanup removes through the directory it judges too: after a receive placed a
// file in the target's own pool, swapping a parent for a link and asking for
// the cleanup must not unlink a same-named file where the link points.
//
// Mutation: os.Remove(hostDiskFile(p)) again in CleanupMigrationArtifacts - the
// victim is unlinked and this is red.
func TestFleet_CleanupDoesNotFollowASwappedParentInTheTargetsOwnPool(t *testing.T) {
	o := newOwnPoolScenario(t, "pool")
	up, err := o.c.PeerClient(o.src, o.dst).ReceiveMigrationDisk(context.Background())
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
	if _, err := up.CloseAndRecv(); err != nil {
		t.Fatalf("receive: %v", err)
	}
	if _, err := os.Lstat(o.targetFile(o.disk)); err != nil {
		t.Fatalf("not placed: %v", err)
	}
	// The same-named file elsewhere, and the parent swapped for a link to it.
	victim := filepath.Join(o.targetFile(o.out), "x.qcow2")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	pd := o.targetFile(filepath.Join(o.nfs, "pool"))
	if err := os.Rename(pd, pd+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(o.targetFile(o.out), pd); err != nil {
		t.Fatal(err)
	}
	_, cerr := o.c.PeerClient(o.src, o.dst).CleanupMigrationArtifacts(context.Background(),
		&pb.CleanupMigrationArtifactsRequest{VmName: "fp1", DiskPaths: []string{o.disk}})
	t.Logf("cleanup: %v", cerr)
	if _, err := os.Lstat(victim); err != nil {
		t.Errorf("cleanup unlinked %s through the swapped link: %v", victim, err)
	}
}
