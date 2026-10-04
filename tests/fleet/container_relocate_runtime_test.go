package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Host-loss relocation re-homes a container only onto a host that can run it.
// Drill D3 (main-8d1e56dc) relocated blct to node-3, whose daemon had recorded
// litevirt.lxc=false, and node-3's reconciler retried "lxc-create not found"
// forever. With no survivor able to run it, the container is left visible on
// the fenced host, marked relocate-skipped, instead.
//
// The survivor without a runtime sorts first by name and has the same room as
// the other, so the runtime filter is the only thing keeping the container off
// it.
//
// A survivor whose record carries no litevirt.lxc label at all is no LXC
// survivor either: placement is strict (corrosion.HostRunsContainers).
//
// Mutations: drop the placement engine's container-runtime filter — "one LXC
// survivor" re-homes onto node-0 and goes red; drop the coordinator's skip on
// ErrNoContainerRuntime — "no LXC survivor" leaves the row unmarked and goes
// red; restore the lenient rule (refuse only "false") — "unlabelled survivor"
// re-homes onto node-1 and goes red.
func TestContainerRelocate_OnlyOntoAHostWithAContainerRuntime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bRuntime string // litevirt.lxc on node-1; "" removes the label
		wantHost int    // index of the node owning ct afterwards
	}{
		{"one LXC survivor", "true", 1},
		{"no LXC survivor", "false", 2},
		{"unlabelled survivor", "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 3, SharedCRDT: true})
			ctx := context.Background()
			a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			for _, l := range []struct {
				n *Node
				v string
			}{{a, "false"}, {b, tc.bRuntime}, {victim, "true"}} {
				if l.v == "" {
					// The harness labels every node; take node-1's away.
					if err := a.DB.Execute(ctx, `UPDATE hosts SET labels = json_remove(labels, '$."`+
						corrosion.LabelLXCCapable+`"') WHERE name = ?`, l.n.Name); err != nil {
						t.Fatalf("unlabel %s: %v", l.n.Name, err)
					}
					if h, err := corrosion.GetHost(ctx, a.DB, l.n.Name); err != nil || h == nil {
						t.Fatalf("read %s back: %v", l.n.Name, err)
					} else if _, ok := h.Labels[corrosion.LabelLXCCapable]; ok {
						t.Fatalf("%s still carries %s: %v", l.n.Name, corrosion.LabelLXCCapable, h.Labels)
					}
					continue
				}
				if err := corrosion.SetHostLabel(ctx, a.DB, l.n.Name, corrosion.LabelLXCCapable, l.v); err != nil {
					t.Fatalf("label %s: %v", l.n.Name, err)
				}
			}
			putContainer(t, victim, "ct", "docker.io/library/alpine:3.19", "image-recreate")

			if got := fenceVictim(t, c, a, victim, a, b); got != 1 {
				t.Fatalf("fencer fired %d times, want 1 — without a fence there is no relocation pass", got)
			}

			host, rec := findContainer(t, c, "ct")
			if rec == nil {
				t.Fatal("ct vanished — a relocatable container must never be lost")
			}
			if want := c.Nodes[tc.wantHost].Name; host != want {
				t.Fatalf("ct is on %s, want %s", host, want)
			}
			if host == victim.Name && rec.StateDetail != corrosion.ContainerRelocateSkippedDetail {
				t.Fatalf("ct left on the fenced host with detail %q, want %q", rec.StateDetail,
					corrosion.ContainerRelocateSkippedDetail)
			}
			if host != victim.Name && rec.StateDetail != corrosion.ContainerRelocateRecreateDetail {
				t.Fatalf("ct re-homed with detail %q, want %q", rec.StateDetail, corrosion.ContainerRelocateRecreateDetail)
			}
		})
	}
}
