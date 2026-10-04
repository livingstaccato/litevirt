package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A `.<replica>.partial` left by a crash on a build from before replica temps
// became `.repl-*.tmp` is swept from the replica pool, under the same rules as
// any other staging temp.
//
// publishReplica used to stage into "."+base(dst)+".partial". That name matches
// neither stagingTempPrefixes nor the .tmp suffix, and the next run's new
// timestamp never reused it, so each crash mid-convert left a full-size image
// that nothing removed. The current build no longer creates such a name, so
// every one on disk is a leftover — but the sweep still keeps to the
// `.repl-*.tmp` rules: only a pool (replica) directory, only a replica-shaped
// name, and only past the in-flight age bound, so a copy still being written
// (by an older-build peer on a shared pool, say) keeps a fresh mtime and is
// left alone.
func TestSweepStaleStaging_CollectsLegacyReplicaPartials(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	pool := replicaPoolDir(t, s, "replicas")
	images := filepath.Join(s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}

	old := time.Now().Add(-2 * time.Hour)
	write := func(dir, name string, mod time.Time) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("half a disk"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
		return p
	}

	gone := []string{
		write(pool, ".web-1-root-20260920T010000Z.qcow2.partial", old),
		write(pool, ".db-data-20260920T010000Z.raw.partial", old),
	}
	kept := []string{
		// In flight: inside the age bound.
		write(pool, ".web-1-root-20260927T010000Z.qcow2.partial", time.Now()),
		// Not replica-shaped: litevirt never wrote it.
		write(pool, ".notes.partial", old),
		write(pool, ".web-1-root-20260920T010000Z.iso.partial", old),
		// A real replica, and the published name the partial would have become.
		write(pool, "web-1-root-20260920T010000Z.qcow2", old),
		// Not a replica directory.
		write(images, ".web-1-root-20260920T010000Z.qcow2.partial", old),
	}

	s.SweepStaleStaging(context.Background())

	for _, p := range gone {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("stale legacy replica temp %s was not swept (stat err=%v)", p, err)
		}
	}
	for _, p := range kept {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s must be kept: %v", p, err)
		}
	}
}
