package fleet

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// guarded declares box's security groups and guard; plain declares neither.
const composeNICSecurity = `name: sec-stack

images:
  test:
    source: file:///dev/null

networks:
  lan:
    external: true

security-groups:
  web:
    rules:
      - { direction: ingress, proto: tcp, port: "8080", action: accept }

vms:
  box:
    image: test
    cpu: 1
    memory: 256
    disks:
      root: 1G
    network:
      - name: lan
        security-groups: [web]
        spoof-guard: "on"
        allowed-addresses: [10.31.0.250]
        allow-vlan-tags: true
    placement:
      host: node-0
  plain:
    image: test
    cpu: 1
    memory: 256
    disks:
      root: 1G
    network:
      - name: lan
    placement:
      host: node-0
`

// liveSec is the one NIC of vm as node n's replica enforces it.
func liveSec(t *testing.T, n *Node, vm string) compose.LiveNIC {
	t.Helper()
	v, err := corrosion.GetVM(context.Background(), n.DB, vm)
	if err != nil || v == nil {
		t.Fatalf("GetVM %s on %s: %v %v", vm, n.Name, v, err)
	}
	live, err := corrosion.LiveNICSecurity(context.Background(), n.DB, vm, specUUID(t, v.Spec))
	if err != nil || len(live) != 1 {
		t.Fatalf("LiveNICSecurity %s on %s = %+v, %v", vm, n.Name, live, err)
	}
	return live[0]
}

func declaredRestored(l compose.LiveNIC) bool {
	g := l.Guard
	return slices.Equal(l.SecurityGroups, []string{"web"}) && g != nil && g.Mode == "on" &&
		slices.Equal(g.Allowed, []string{"10.31.0.250"}) && g.AllowVLANTags
}

// N2 (lab c713): an operator's runtime `lv sg bind` and `lv firewall
// nic-guard set`, made through one node, are drift a compose deploy through
// another node reports and puts back — for the NIC whose file declares them —
// and says aloud that the restore removes protection set outside the file. A
// NIC whose file declares neither keeps what the operator set, and a restored
// stack plans no further change.
func TestFleet_ComposeRestoresDeclaredNICSecurityAndLeavesTheRest(t *testing.T) {
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	deployer, operator := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	if err := corrosion.InsertImage(ctx, deployer.DB, corrosion.ImageRecord{Name: "test", Format: "qcow2",
		SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if err := writeEmptyImageFile(deployer.Server.ImagePathForTests("test")); err != nil {
		t.Fatal(err)
	}
	// The external bridge the NICs attach to (a bridge, where guards are
	// enforced; the harness's bridge ensure is a no-op).
	if err := corrosion.UpsertNetwork(ctx, deployer.DB, corrosion.NetworkRecord{Name: "lan", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"br-lan"}`}); err != nil {
		t.Fatal(err)
	}
	dc, oc := c.SelfClient(deployer), c.SelfClient(operator)

	deployClean(t, ctx, dc, composeNICSecurity)
	if l := liveSec(t, deployer, "box"); !declaredRestored(l) {
		t.Fatalf("box after deploy = %+v (guard %+v), want the file's binding and guard", l, l.Guard)
	}
	eventually(t, 10*time.Second, "the stack's NIC rows to reach the operator's node", func() bool {
		v, _ := corrosion.GetVM(ctx, operator.DB, "plain")
		return v != nil && declaredRestored(liveSec(t, operator, "box"))
	})

	// The operator's runtime changes, through the other node: box is moved
	// to an isolation group and loses its guard's allowances; plain is
	// isolated and unguarded.
	for _, req := range []*pb.BindSecurityGroupsRequest{
		{VmName: "box", NetworkName: "lan", SecurityGroups: []string{"isolate"}},
		{VmName: "plain", NetworkName: "lan", SecurityGroups: []string{"isolate"}},
	} {
		if _, err := oc.BindSecurityGroups(ctx, req); err != nil {
			t.Fatalf("BindSecurityGroups %s: %v", req.VmName, err)
		}
	}
	for _, req := range []*pb.SetNICGuardRequest{
		{VmName: "box", NetworkName: "lan", Mode: "on"},
		{VmName: "plain", NetworkName: "lan", Mode: "off"},
	} {
		if _, err := oc.SetNICGuard(ctx, req); err != nil {
			t.Fatalf("SetNICGuard %s: %v", req.VmName, err)
		}
	}
	eventually(t, 10*time.Second, "the runtime changes to reach the deployer", func() bool {
		b, p := liveSec(t, deployer, "box"), liveSec(t, deployer, "plain")
		return slices.Equal(b.SecurityGroups, []string{"isolate"}) && b.Guard != nil && len(b.Guard.Allowed) == 0 &&
			slices.Equal(p.SecurityGroups, []string{"isolate"}) && p.Guard != nil && p.Guard.Mode == "off"
	})

	// The plan sees box's drift, says the restore unbinds its isolation group
	// and relaxes its live guard, and leaves plain alone.
	var boxOp, plainOp, warnings string
	for _, p := range dryRunPlan(t, ctx, dc, composeNICSecurity) {
		switch {
		case p.Phase == "warning":
			warnings += p.Detail + "\n"
		case p.VmName == "box":
			boxOp = p.Phase + " " + p.Detail
		case p.VmName == "plain":
			plainOp = p.Phase + " " + p.Detail
		}
	}
	if !strings.HasPrefix(boxOp, string(compose.OpUpdate)) || !strings.Contains(boxOp, compose.NICSecurityGroupsFieldPrefix+"0") ||
		!strings.Contains(boxOp, compose.NICGuardFieldPrefix+"0") {
		t.Errorf("box planned %q, want an update of its binding and guard", boxOp)
	}
	if !strings.Contains(warnings, "box") || !strings.Contains(warnings, "unbinds security group(s) isolate") ||
		!strings.Contains(warnings, "10.31.0.250") || !strings.Contains(warnings, "vlan") {
		t.Errorf("warnings %q do not say the restore unbinds box's isolation group and relaxes its live guard", warnings)
	}
	if !strings.HasPrefix(plainOp, string(compose.OpNoChange)) {
		t.Errorf("plain planned %q over an undeclared binding and guard, want no change", plainOp)
	}

	// The deploy puts box back, on every replica, and leaves plain as the
	// operator set it.
	eventsBefore := len(deployer.Virt.EventLog())
	deployClean(t, ctx, dc, composeNICSecurity)
	for _, n := range c.Nodes {
		eventually(t, 10*time.Second, "box's declared security back on "+n.Name, func() bool {
			return declaredRestored(liveSec(t, n, "box"))
		})
	}
	if p := liveSec(t, deployer, "plain"); !slices.Equal(p.SecurityGroups, []string{"isolate"}) || p.Guard == nil || p.Guard.Mode != "off" {
		t.Errorf("plain after deploy = %+v (guard %+v), want the operator's isolate binding and off guard kept", p, p.Guard)
	}
	for _, e := range deployer.Virt.EventLog()[eventsBefore:] {
		if e.Op == "undefine" || e.Op == "destroy" || e.Op == "define" {
			t.Errorf("restoring NIC security recorded a %q on %s; it is applied in place", e.Op, e.Domain)
		}
	}

	// Converged: the same file plans no change.
	for _, p := range dryRunPlan(t, ctx, dc, composeNICSecurity) {
		if (p.VmName == "box" || p.VmName == "plain") && p.Phase != string(compose.OpNoChange) {
			t.Errorf("after the restore %s planned %q (%s), want no change", p.VmName, p.Phase, p.Detail)
		}
	}
}
