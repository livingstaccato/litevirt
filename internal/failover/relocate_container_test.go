package failover

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// runsContainers labels hosts litevirt.lxc=true, as each one's daemon does
// when it finds a container runtime; placement puts a container nowhere else.
func runsContainers(t *testing.T, db *corrosion.Client, hosts ...string) {
	t.Helper()
	for _, h := range hosts {
		if err := corrosion.SetHostLabel(context.Background(), db, h, corrosion.LabelLXCCapable, "true"); err != nil {
			t.Fatalf("label %s litevirt.lxc=true: %v", h, err)
		}
	}
}

// TestRelocateContainers: on a fenced host, containers with a re-pullable image
// and an image-recreate policy are re-keyed to a healthy host (pending +
// relocate-recreate); policy=none and non-re-pullable containers are left in
// place (the latter loudly audited).
func TestRelocateContainers(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "live", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CPUTotal: 8, MemTotal: 8192,
	}); err != nil {
		t.Fatal(err)
	}
	runsContainers(t, db, "live")
	mk := func(name, image, policy string) {
		if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
			HostName: "dead", Name: name, State: "running", Image: image,
			CPULimit: 1, MemMiB: 128, Project: "p1", OnHostFailure: policy,
		}); err != nil {
			t.Fatalf("UpsertContainer %s: %v", name, err)
		}
	}
	mk("web", "alpine:3.19", "image-recreate") // relocates
	mk("novol", "", "image-recreate")          // skipped: no re-pullable image
	mk("noop", "alpine:3.19", "none")          // skipped: policy none

	c := newTestCoordinator("coord", db)
	candidates := []corrosion.HostRecord{{Name: "live", State: "active"}}
	c.relocateContainers(ctx, &corrosion.HostRecord{Name: "dead"}, candidates)

	// web → relocated to live, pending+relocate-recreate, source row gone.
	if g, _ := corrosion.GetContainer(ctx, db, "dead", "web"); g != nil {
		t.Errorf("web source row still present: %+v", g)
	}
	web, _ := corrosion.GetContainer(ctx, db, "live", "web")
	if web == nil || web.State != "pending" || web.StateDetail != corrosion.ContainerRelocateRecreateDetail {
		t.Errorf("web not relocated correctly: %+v", web)
	}
	// novol + noop stay on dead (not relocated).
	if g, _ := corrosion.GetContainer(ctx, db, "dead", "novol"); g == nil {
		t.Error("novol should not have been relocated (no re-pullable image)")
	}
	if g, _ := corrosion.GetContainer(ctx, db, "dead", "noop"); g == nil {
		t.Error("noop should not have been relocated (policy=none)")
	}
	if g, _ := corrosion.GetContainer(ctx, db, "live", "novol"); g != nil {
		t.Errorf("novol wrongly relocated: %+v", g)
	}

	// The skip was audited (ct.relocate.skipped).
	rows, _ := db.Query(ctx, `SELECT action FROM audit_log WHERE target = 'novol' AND action = 'ct.relocate.skipped'`)
	if len(rows) == 0 {
		t.Error("expected a ct.relocate.skipped audit row for novol")
	}
}

// A container is relocated only to a host with a container runtime, and when
// no survivor has one it is skipped — left visible, marked terminal and
// audited as such — rather than re-keyed onto a host that retries
// "lxc-create not found" forever (drill D3, main-8d1e56dc: blct on node-3).
//
// A survivor with no litevirt.lxc label at all is no LXC survivor either:
// placement is strict (corrosion.HostRunsContainers).
//
// Mutations: drop the placement engine's container-runtime filter — the
// "one LXC survivor" subtest relocates to nolxc and goes red; drop the skip
// on ErrNoContainerRuntime — the "no LXC survivor" subtest leaves the row
// unmarked and goes red; restore the lenient rule (refuse only "false") —
// "unlabelled survivor" relocates onto it and goes red.
func TestRelocateContainers_OnlyToAHostWithAContainerRuntime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lxcLabel string // litevirt.lxc on the "lxc" host; "" leaves it unlabelled
		want     string // host owning web afterwards
	}{
		{"one LXC survivor", "true", "lxc"},
		{"no LXC survivor", "false", "dead"},
		{"unlabelled survivor", "", "dead"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			ctx := context.Background()
			// nolxc has far more room, so only the runtime filter keeps web off it.
			for _, h := range []struct {
				name, label string
				mem         int
			}{{"nolxc", "false", 65536}, {"lxc", tc.lxcLabel, 4096}} {
				if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
					Name: h.name, Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
					State: "active", CPUTotal: 8, MemTotal: h.mem,
				}); err != nil {
					t.Fatal(err)
				}
				if h.label == "" {
					continue
				}
				if err := corrosion.SetHostLabel(ctx, db, h.name, corrosion.LabelLXCCapable, h.label); err != nil {
					t.Fatal(err)
				}
			}
			if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
				HostName: "dead", Name: "web", State: "running", Image: "alpine:3.19",
				MemMiB: 128, Project: "p1", OnHostFailure: "image-recreate",
			}); err != nil {
				t.Fatal(err)
			}

			c := newTestCoordinator("coord", db)
			candidates := []corrosion.HostRecord{{Name: "nolxc", State: "active"}, {Name: "lxc", State: "active"}}
			c.relocateContainers(ctx, &corrosion.HostRecord{Name: "dead"}, candidates)

			for _, h := range []string{"dead", "nolxc", "lxc"} {
				g, _ := corrosion.GetContainer(ctx, db, h, "web")
				if (g != nil) != (h == tc.want) {
					t.Fatalf("web on %s = %+v, want it only on %s", h, g, tc.want)
				}
			}
			if tc.want != "dead" {
				return
			}
			g, _ := corrosion.GetContainer(ctx, db, "dead", "web")
			if g.StateDetail != corrosion.ContainerRelocateSkippedDetail {
				t.Fatalf("web detail = %q, want %q (terminal, so the relocate loop stops)", g.StateDetail,
					corrosion.ContainerRelocateSkippedDetail)
			}
			rows, err := db.Query(ctx, `SELECT detail FROM audit_log WHERE target = 'web' AND action = 'ct.relocate.skipped'`)
			if err != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "container runtime") {
				t.Fatalf("ct.relocate.skipped audit for web = %v (err %v), want one row naming the missing container runtime", rows, err)
			}
		})
	}
}

// A relocating container is charged what it uses on the survivor: its memory
// limit, with no qemu overhead, and no host vCPU for its cpu figure. It was
// placed like a VM, so a container whose cpu figure exceeded the survivor's
// vCPU, or whose memory fit only without a VM's overhead, was stranded.
func TestRelocateContainers_ChargesMemoryOnly(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	// 1 vCPU / 4096 MiB: 3 allocatable vCPU, 3072 allocatable MiB.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "live", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CPUTotal: 1, MemTotal: 4096,
	}); err != nil {
		t.Fatal(err)
	}
	runsContainers(t, db, "live")
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "dead", Name: "web", State: "running", Image: "alpine:3.19",
		CPULimit: 8, MemMiB: 3000, Project: "p1", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	c := newTestCoordinator("coord", db)
	c.relocateContainers(ctx, &corrosion.HostRecord{Name: "dead"}, []corrosion.HostRecord{{Name: "live", State: "active"}})

	if web, _ := corrosion.GetContainer(ctx, db, "live", "web"); web == nil {
		t.Fatal("web (cpu 8, 3000 MiB) was not relocated to live (3 vCPU, 3072 MiB allocatable)")
	}
}
