package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// skippedSetup records a relocate-skipped container web on host "dead", and
// an active host "lxc" whose litevirt.lxc label is lxcLabel.
func skippedSetup(t *testing.T, image, lxcLabel string) *corrosion.Client {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "lxc", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CPUTotal: 8, MemTotal: 8192,
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostStartup(ctx, db, "lxc", "active", "v1", 8, 8192, 100, true); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetHostLabel(ctx, db, "lxc", corrosion.LabelLXCCapable, lxcLabel); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "dead", Name: "web", State: "stopped", StateDetail: corrosion.ContainerRelocateSkippedDetail,
		Image: image, MemMiB: 128, Project: "p1", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

// A relocate-skipped container is relocated again once a host can take it, on
// a host removed for good only. On a host that is fenced, and may come back
// with the container's rootfs, the skip stays terminal.
//
// Mutation: drop the removed-host condition in retrySkippedOnRemovedHost —
// the fenced subtest relocates web and goes red. Drop the retry — the removed
// subtest leaves web skipped on dead and goes red.
func TestRelocateSkipped_RetriedOnceAHostCanTakeIt_OnARemovedHostOnly(t *testing.T) {
	for _, tc := range []struct {
		state string
		want  string // host owning web afterwards
	}{
		{"fenced", "dead"},
		{"removed", "lxc"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			ctx := context.Background()
			db := skippedSetup(t, "alpine:3.19", "true")
			c := newTestCoordinator("coord", db)
			c.relocateContainers(ctx, &corrosion.HostRecord{Name: "dead", State: tc.state},
				[]corrosion.HostRecord{{Name: "lxc", State: "active"}})
			for _, h := range []string{"dead", "lxc"} {
				g, _ := corrosion.GetContainer(ctx, db, h, "web")
				if (g != nil) != (h == tc.want) {
					t.Fatalf("web on %s = %+v, want it only on %s", h, g, tc.want)
				}
			}
			if tc.want == "lxc" {
				g, _ := corrosion.GetContainer(ctx, db, "lxc", "web")
				if g.State != "pending" || g.StateDetail != corrosion.ContainerRelocateRecreateDetail {
					t.Fatalf("web on lxc = %s/%s, want pending/%s", g.State, g.StateDetail, corrosion.ContainerRelocateRecreateDetail)
				}
			}
		})
	}
}

// While no host can take it, a retry writes and audits nothing: the skip
// already said so, and the removed-host pass runs every tick.
//
// Mutation: retry without asking placement first — each pass goes through
// pickContainerTarget, which marks and audits the missing container runtime
// again, and the audit count goes red.
func TestRelocateSkipped_QuietWhileNoHostCanTakeIt(t *testing.T) {
	ctx := context.Background()
	db := skippedSetup(t, "alpine:3.19", "false")
	c := newTestCoordinator("coord", db)
	before, _ := corrosion.GetContainer(ctx, db, "dead", "web")
	for i := 0; i < 3; i++ {
		c.relocateContainers(ctx, &corrosion.HostRecord{Name: "dead", State: "removed"},
			[]corrosion.HostRecord{{Name: "lxc", State: "active"}})
	}
	after, _ := corrosion.GetContainer(ctx, db, "dead", "web")
	if after == nil || after.StateDetail != corrosion.ContainerRelocateSkippedDetail || after.UpdatedAt != before.UpdatedAt {
		t.Fatalf("web on dead after three passes with no host for it: %+v, want it untouched (%+v)", after, before)
	}
	rows, err := db.Query(ctx, `SELECT 1 FROM audit_log WHERE target = 'web'`)
	if err != nil || len(rows) != 0 {
		t.Fatalf("%d audit rows for web (err %v), want none", len(rows), err)
	}
}

// A container with no image to re-pull comes back only from a backup. A
// restore that found none onto a target finds none again, so it is tried
// once per target, not on every pass.
//
// Mutation: drop the per-target memo — the restorer is called on every pass.
func TestRelocateSkipped_NoImageRetriesTheRestoreOncePerTarget(t *testing.T) {
	ctx := context.Background()
	db := skippedSetup(t, "", "true")
	c := newTestCoordinator("coord", db)
	fr := &fakeRestorer{db: db}
	c.Restorer = fr
	for i := 0; i < 3; i++ {
		c.relocateContainers(ctx, &corrosion.HostRecord{Name: "dead", State: "removed"},
			[]corrosion.HostRecord{{Name: "lxc", State: "active"}})
	}
	if fr.calls != 1 {
		t.Fatalf("the restorer was called %d times over three passes onto one target, want 1", fr.calls)
	}
	if g, _ := corrosion.GetContainer(ctx, db, "dead", "web"); g == nil || g.StateDetail != corrosion.ContainerRelocateSkippedDetail {
		t.Fatalf("web on dead after a restore that found no backup: %+v, want it still %s", g, corrosion.ContainerRelocateSkippedDetail)
	}
}
