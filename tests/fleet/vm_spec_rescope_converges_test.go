package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_VMSpecNetworkRescopeConverges: node-1, cut off, runs the
// start-up pass that rewrites network names in VM specs
// (MigrateLegacyNetworkNames, here healing an attachment an earlier pass
// mis-prefixed), and the VM's owner, node-0, then writes the VM's state
// before the rewrite reaches it. The rewrite used to be a bare
// `UPDATE vms SET spec, updated_at`: the owner skipped it as older than its
// state write, every other replica took it, and the spec stayed split under
// one updated_at for good (an opaque column, which anti-entropy never
// settles). As a desired-spec edit it is ordered by its generation, and every
// replica ends holding the rewritten spec and the owner's state.
//
// Mutation: write the rewrite as the bare spec update again — "tables apart: vms".
func TestFleet_VMSpecNetworkRescopeConverges(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	latchSpecConflict(t, c, nil, nil)
	owner, migrator := c.Nodes[0], c.Nodes[1]
	if err := corrosion.UpsertNetwork(ctx, owner.DB, corrosion.NetworkRecord{Name: "ext", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
		Name: "web-1", StackName: "web", HostName: owner.Name, State: "running",
		Spec: `{"name":"web-1","network":[{"name":"web_ext"}]}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

	cutOffFully(c, migrator)
	if err := corrosion.MigrateLegacyNetworkNames(ctx, migrator.DB); err != nil {
		t.Fatal(err)
	}
	if vm := vmOn(t, migrator, "web-1"); !strings.Contains(vm.Spec, `"name":"ext"`) {
		t.Fatalf("fixture: %s did not rewrite the spec: %s", migrator.Name, vm.Spec)
	}
	time.Sleep(20 * time.Millisecond) // the owner's state write is the later one
	if err := corrosion.UpdateVMState(ctx, owner.DB, "web-1", "stopped", ""); err != nil {
		t.Fatal(err)
	}

	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		vm := vmOn(t, n, "web-1")
		if !strings.Contains(vm.Spec, `"name":"ext"`) || strings.Contains(vm.Spec, "web_ext") || vm.State != "stopped" {
			t.Errorf("%s holds %s (%s), want the rewritten spec and the owner's state", n.Name, vm.Spec, vm.State)
		}
	}
}

// TestFleet_ALaggingVMSpecRescopeDoesNotBringBackADeletedVM: the owner
// deletes the VM while node-1 lags, and node-1's rewrite is stamped after the
// delete. The rewrite is an edit of a live VM, not a re-create: the VM stays
// deleted on every replica, over the WAL and after an anti-entropy round.
func TestFleet_ALaggingVMSpecRescopeDoesNotBringBackADeletedVM(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	latchSpecConflict(t, c, nil, nil)
	owner, migrator := c.Nodes[0], c.Nodes[1]
	if err := corrosion.UpsertNetwork(ctx, owner.DB, corrosion.NetworkRecord{Name: "ext", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
		Name: "web-1", StackName: "web", HostName: owner.Name, State: "running",
		Spec: `{"name":"web-1","network":[{"name":"web_ext"}]}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

	cutOffFully(c, migrator)
	if err := corrosion.DeleteVM(ctx, owner.DB, "web-1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := corrosion.MigrateLegacyNetworkNames(ctx, migrator.DB); err != nil {
		t.Fatal(err)
	}
	if vm := vmOn(t, migrator, "web-1"); vm == nil || !strings.Contains(vm.Spec, `"name":"ext"`) {
		t.Fatalf("fixture: %s did not rewrite the live VM: %+v", migrator.Name, vm)
	}

	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	for _, a := range c.Nodes {
		for _, b := range c.Nodes {
			if a != b {
				if err := b.DB.MergeStateBytesLWW(pullDump(t, c, a)); err != nil {
					t.Fatalf("merge %s into %s: %v", a.Name, b.Name, err)
				}
			}
		}
	}
	for _, n := range c.Nodes {
		if vm := vmOn(t, n, "web-1"); vm != nil {
			t.Errorf("%s holds web-1 live (%s): the lagging rewrite brought back a deleted VM", n.Name, vm.Spec)
		}
	}
	c.WaitConverged(t, convergeTimeout)
}
