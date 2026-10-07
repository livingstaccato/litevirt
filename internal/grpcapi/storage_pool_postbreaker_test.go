package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// N5-C1: a restore of the data directory by a copy that keeps whole-second
// modification times (GNU tar's default format, scp -p, older rsync) leaves a
// project's uploads its own.
func TestPoolPostBreaker_UploadsStayOwnedAfterAWholeSecondCopy(t *testing.T) {
	for _, g := range []time.Duration{time.Second, time.Millisecond, time.Microsecond, 100 * time.Nanosecond} {
		t.Run(g.String(), func(t *testing.T) {
			s, disks := disksPoolServer(t)
			pat := hostPathEngineCtx(t, s, "pat", "Operator", poolRBACPathFor("", "default"))
			if err := uploadAs(pat, s, "default", "pats.qcow2", "x"); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(disks, poolUploadsSubdir, "pats.qcow2")
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			mt := fi.ModTime().Truncate(g)
			if mt.Equal(fi.ModTime()) {
				t.Skip("the upload's mtime is already on the unit")
			}
			if err := os.Chtimes(p, mt, mt); err != nil {
				t.Fatal(err)
			}
			if got := listNames(t, s, pat, "default"); !slices.Contains(got, "pats.qcow2") {
				t.Errorf("after a %s-precision restore pat's listing %v lacks pat's upload", g, got)
			}
			if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: "default", Filename: "pats.qcow2"}); err != nil {
				t.Errorf("pat deleting its own upload after the restore: %v", err)
			}
		})
	}
}

// N5-I1: during a partition another project's user uploads, into the global
// pool, a file at cvm's next runner name, and its record never reaches the
// majority. Failover does not take it: the upload left a marker on the store,
// which the majority sees with the file. It takes cvm's recorded replica.
func TestPoolPostBreaker_AnUploadDuringAPartitionIsNotALateReplica(t *testing.T) {
	h1, h2, dir := partitionedWriter(t, time.Now().Add(time.Minute), false)
	recorded := stampedReplicas(t, dir, "cvm-root")
	bob := hostPathEngineCtx(t, h1, "bob", "Operator", poolRBACPathFor("", "shared"))
	plant := "cvm-root-" + time.Now().Add(-time.Minute).UTC().Format(replicaStampLayout) + ".qcow2"
	if err := uploadAs(bob, h1, "shared", plant, string(qcow2Bytes(t))); err != nil {
		t.Fatalf("bob's upload through h1: %v", err)
	}
	// The upload's record never left h1's side of the partition.
	rows, err := corrosion.ListPoolRecords(context.Background(), h1.db, corrosion.PoolUploadKeyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	for k := range rows {
		if err := corrosion.SetPoolRecord(context.Background(), h1.db, k, "{}", "h1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := h2.AutoPromoteReplica(context.Background(), "cvm", "", 0); err != nil {
		t.Fatalf("failover of cvm on h2: %v", err)
	}
	if promotedFrom(dir, "cvm", plant) || len(recorded) != 1 || !promotedFrom(dir, "cvm", recorded[0]) {
		t.Errorf("cvm was promoted from bob's upload %s, not its recorded replica %v", plant, recorded)
	}
}
