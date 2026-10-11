package fleet

import (
	"context"
	"crypto/rand"
	"testing"
	"time"
)

// A container replication run pushes into a backup repo on its target, so the
// repo's `backup_bwlimits` entry on the owner — the shared per-repo throttle
// backups into that repo run under — paces it: the archive it reads and the
// chunks it sends. 1 MiB of incompressible payload at 256 KiB/s takes at least
// 4 s to read and 4 s more to send (every chunk is new); the same run
// unlimited is the baseline.
//
// Mutations: pass no limiter to archiveContainerAs and pushManifestToPeerRepo
// in replicateContainer (as before) — the limited run is as fast as the
// baseline; drop either one alone — it is about 4 s, not 8, slower.
func TestContainerReplication_RunsUnderTheReposBandwidthLimit(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, b)
	sched := ctSchedule(t, c, a, name, b.Name, 3, false)

	run := func(at time.Time) time.Duration {
		t.Helper()
		buf := make([]byte, 1<<20)
		_, _ = rand.Read(buf)
		a.CT.Seed(name, string(buf))
		start := time.Now()
		if err := a.Server.RunReplication(ctx, sched, at); err != nil {
			t.Fatalf("run at %s: %v", at, err)
		}
		return time.Since(start)
	}
	base := time.Now().UTC().Add(-3 * time.Minute)
	unlimited := run(base)

	a.Server.SetBackupBandwidthLimits(map[string]int64{"dr": 256 << 10})
	limited := run(base.Add(time.Minute))
	if limited-unlimited < 6*time.Second {
		t.Fatalf("a run into repo dr limited to 256KiB/s took %v for 1 MiB (unlimited: %v); the repo's limit was not applied",
			limited, unlimited)
	}
	if got := len(replicas(t, repo, name)); got != 2 {
		t.Fatalf("the target holds %d replicas, want 2", got)
	}
}
