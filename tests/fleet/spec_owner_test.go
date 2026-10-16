// Fleet scenarios: a spec edit entered on a host that does not own the VM is
// made on the owner (grpcapi/spec_owner.go), so two edits of one VM's spec are
// serialised on one host instead of becoming two versions at one generation.
// An owner that cannot be reached does not refuse the edit.
package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ownerCPUEdit is an edit the owner makes to vm-own's spec on its own.
func ownerCPUEdit(t *testing.T, a *Node, name string) {
	t.Helper()
	if _, _, err := corrosion.MutateDesiredSpec(context.Background(), a.DB, name, func(old string) (string, error) {
		var m map[string]any
		if err := json.Unmarshal([]byte(old), &m); err != nil {
			return "", err
		}
		m["cpu"] = 4
		out, err := json.Marshal(m)
		return string(out), err
	}); err != nil {
		t.Fatalf("owner edit on %s: %v", a.Name, err)
	}
}

func specHas(t *testing.T, n *Node, name string, parts ...string) bool {
	t.Helper()
	vm := vmOn(t, n, name)
	if vm == nil {
		return false
	}
	for _, p := range parts {
		if !strings.Contains(vm.Spec, p) {
			return false
		}
	}
	return true
}

// The D7 case: node-1's replication is cut, the owner edits cpu, and node-1
// sets a label. The label is made on the owner, over the owner's cpu edit,
// so nothing is lost and every replica ends with both.
//
// Red before the forward: the owner holds only cpu, node-1 only the label,
// each at generation 1.
func TestFleet_ALabelEditEnteredOffTheOwnerIsMadeOnTheOwner(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	insertVM(t, a, "vm-own", a.Name)
	c.WaitConverged(t, convergeTimeout)

	c.Isolate(b) // replication only: b can still call a
	ownerCPUEdit(t, a, "vm-own")
	if _, err := c.SelfClient(b).SetVMLabels(ctx, &pb.SetVMLabelsRequest{Name: "vm-own", Labels: map[string]string{"tier": "front"}}); err != nil {
		t.Fatalf("SetVMLabels via %s: %v", b.Name, err)
	}
	if !specHas(t, a, "vm-own", `"cpu":4`, `"tier":"front"`) {
		t.Fatalf("the owner %s does not hold both edits before the cut heals: %s", a.Name, vmOn(t, a, "vm-own").Spec)
	}
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if !specHas(t, n, "vm-own", `"cpu":4`, `"tier":"front"`) {
			t.Errorf("%s lost an edit: %s", n.Name, vmOn(t, n, "vm-own").Spec)
		}
	}
}

// An owner that cannot be reached at all does not refuse the edit: it is made
// where it entered, as before the forward.
func TestFleet_ALabelEditWhileTheOwnerIsUnreachableIsMadeHere(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	insertVM(t, a, "vm-own", a.Name)
	c.WaitConverged(t, convergeTimeout)

	c.Isolate(b)
	c.SetLinkFaultBoth(a, b, LinkFault{Block: true, BlockAll: true})
	if _, err := c.SelfClient(b).SetVMLabels(ctx, &pb.SetVMLabelsRequest{Name: "vm-own", Labels: map[string]string{"tier": "front"}}); err != nil {
		t.Fatalf("SetVMLabels via %s with the owner unreachable: %v", b.Name, err)
	}
	if !specHas(t, b, "vm-own", `"tier":"front"`) {
		t.Fatalf("%s did not make the edit itself: %s", b.Name, vmOn(t, b, "vm-own").Spec)
	}
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if !specHas(t, n, "vm-own", `"tier":"front"`) {
			t.Errorf("%s does not hold the label: %s", n.Name, vmOn(t, n, "vm-own").Spec)
		}
	}
}

func withLabel(yaml string) string {
	return strings.Replace(yaml, "    memory: 256\n", "    memory: 256\n    labels:\n      tier: front\n", 1)
}

// A deploy entered on node-1 changes web's labels, a live-metadata patch. It
// is written on node-0, web's owner, which node-1 cannot replicate to: the
// owner holds the label before the cut heals, and node-1 does not.
//
// Red before the forward: the patch is written on node-1 and node-0 has
// nothing until the cut heals.
func TestFleet_ADeployEnteredOffTheOwnerPatchesTheSpecOnTheOwner(t *testing.T) {
	c, _ := newRecreateRemoteFleet(t, 1, "node-0")
	n0, n1 := c.Nodes[0], c.Nodes[1]
	c.Isolate(n1)
	deployClean(t, context.Background(), c.SelfClient(n1), withLabel(recreateRemoteYAML("node-0", "first")))
	if !specHas(t, n0, "web", `"tier":"front"`) {
		t.Fatalf("the owner %s does not hold the deploy's label: %s", n0.Name, vmOn(t, n0, "web").Spec)
	}
	if specHas(t, n1, "web", `"tier":"front"`) {
		t.Fatalf("%s, cut off from the owner's replication, holds the label: the patch was written here", n1.Name)
	}
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if !specHas(t, n, "web", `"tier":"front"`) {
			t.Errorf("%s does not hold the label: %s", n.Name, vmOn(t, n, "web").Spec)
		}
	}
}

// An owner on a build without PatchVMSpec answers Unimplemented; the deploy
// patches the spec where it entered, as before.
func TestFleet_ADeployPatchesHereWhenTheOwnerLacksPatchVMSpec(t *testing.T) {
	c, _ := newRecreateRemoteFleet(t, 1, "node-0")
	n0, n1 := c.Nodes[0], c.Nodes[1]
	defer n0.DoNotImplement("PatchVMSpec")()
	deployClean(t, context.Background(), c.SelfClient(n1), withLabel(recreateRemoteYAML("node-0", "first")))
	if !specHas(t, n1, "web", `"tier":"front"`) {
		t.Fatalf("%s did not patch the spec itself after the owner answered Unimplemented: %s", n1.Name, vmOn(t, n1, "web").Spec)
	}
	eventually(t, convergeTimeout, "the label to reach the owner", func() bool {
		return specHas(t, n0, "web", `"tier":"front"`)
	})
}
