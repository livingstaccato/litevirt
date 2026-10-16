// Fleet scenario: a compose redeploy that changes migrate.on-host-failure on an
// existing VM takes effect at the next failover (lab 2, finding F2).
//
// The change is classified as live metadata and applied in place. The in-place
// patch stored the migrate block and not the spec's top-level on_host_failure,
// which is the only policy the failover coordinator reads — and restart-any is
// the block's zero value, so `lv inspect` showed `migrate: {}`. A VM deployed
// with "none" and redeployed with "restart-any" was then skipped on host loss:
// "failover: VM skipped (on_host_failure=none)".
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const composeMigratePolicy = `name: mpol

images:
  test:
    source: file:///dev/null

vms:
  pol:
    image: test
    cpu: 1
    memory: 512
    migrate:
      on-host-failure: none
`

// Deploy with on-host-failure none, redeploy with restart-any (the same VM,
// updated in place), fail its host: the VM is recovered onto a survivor.
//
// Mutation: drop the on_host_failure copy from applyLiveMetadata's "migrate"
// case — the redeploy stores only the migrate block, the coordinator still
// reads "none", and pol stays on the failed host.
func TestFleet_ComposeMigratePolicyChangeTakesEffectAtFailover(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	entry := c.Nodes[0]
	if err := corrosion.InsertImage(ctx, entry.DB, corrosion.ImageRecord{Name: "test", Format: "qcow2",
		SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	for _, n := range c.Nodes {
		if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
			t.Fatalf("stage image file on %s: %v", n.Name, err)
		}
	}
	client := c.SelfClient(entry)

	deployClean(t, ctx, client, composeMigratePolicy)
	var created *corrosion.VMRecord
	eventually(t, 10*time.Second, "pol to be created and running", func() bool {
		vm, err := corrosion.GetVM(ctx, entry.DB, "pol")
		created = vm
		return err == nil && vm != nil && vm.State == "running"
	})
	if got := corrosion.VMFailurePolicy(*created); got != "none" {
		t.Fatalf("created with on_host_failure %q, want none", got)
	}

	deployClean(t, ctx, client, edit(t, composeMigratePolicy, "on-host-failure: none", "on-host-failure: restart-any"))
	updated, err := corrosion.GetVM(ctx, entry.DB, "pol")
	if err != nil || updated == nil {
		t.Fatalf("GetVM(pol) after the redeploy: %v %v", updated, err)
	}
	if updated.CreatedAt != created.CreatedAt || updated.HostName != created.HostName {
		t.Fatalf("the redeploy replaced pol (created %s on %s → %s on %s); the test needs an in-place update",
			created.CreatedAt, created.HostName, updated.CreatedAt, updated.HostName)
	}
	if got := corrosion.VMFailurePolicy(*updated); got != "restart-any" {
		t.Fatalf("on_host_failure after the redeploy = %q, want restart-any (spec %s)", got, updated.Spec)
	}

	// pol's host fails; one of the other two coordinates.
	var victim, coord, other *Node
	for _, n := range c.Nodes {
		switch {
		case n.Name == updated.HostName:
			victim = n
		case coord == nil:
			coord = n
		default:
			other = n
		}
	}
	if victim == nil {
		t.Fatalf("pol is on %q, not a fleet node", updated.HostName)
	}
	if got := fenceVictim(t, c, coord, victim, coord, other); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	vm, err := corrosion.GetVM(ctx, coord.DB, "pol")
	if err != nil || vm == nil {
		t.Fatalf("GetVM(pol) after the failover: %v %v", vm, err)
	}
	if vm.HostName == victim.Name || vm.State != "pending" {
		evs, _ := corrosion.ListVMEvents(ctx, coord.DB, "pol", 20, "")
		var seen []string
		for _, e := range evs {
			seen = append(seen, e.Type+": "+e.Detail)
		}
		t.Fatalf("pol after %s failed = %s on %s, want it pending on a survivor (events: %s)",
			victim.Name, vm.State, vm.HostName, strings.Join(seen, "; "))
	}
}
