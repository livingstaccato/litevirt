package fleet

import (
	"context"
	"io"
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

	// Without --allow-weaken, both of box's restores may remove protection
	// set outside the file (the isolation group; the guard's allowances), so
	// the plan withholds them and says how to apply them. plain is left
	// alone. lv compose diff (DiffStack) shows the same plan as up's dry-run.
	plan := func(allowWeaken bool) (box, plain, warnings string) {
		for _, p := range planWith(t, ctx, dc, composeNICSecurity, allowWeaken) {
			switch {
			case p.Phase == "warning":
				warnings += p.Detail + "\n"
			case p.VmName == "box":
				box = p.Phase + " " + p.Detail
			case p.VmName == "plain":
				plain = p.Phase + " " + p.Detail
			}
		}
		return
	}
	diff := func(allowWeaken bool) (box, plain, warnings string) {
		resp, err := dc.DiffStack(ctx, &pb.DiffStackRequest{ComposeYaml: composeNICSecurity, AllowWeaken: allowWeaken})
		if err != nil {
			t.Fatalf("DiffStack: %v", err)
		}
		for _, e := range resp.Entries {
			switch {
			case strings.HasPrefix(e.Detail, "⚠ "):
				warnings += strings.TrimPrefix(e.Detail, "⚠ ") + "\n"
			case e.VmName == "box" && !strings.HasPrefix(e.Detail, "dns "):
				box = e.Detail
			case e.VmName == "plain" && !strings.HasPrefix(e.Detail, "dns "):
				plain = e.Detail
			}
		}
		return
	}
	boxOp, plainOp, warnings := plan(false)
	if !strings.HasPrefix(boxOp, string(compose.OpNoChange)) {
		t.Errorf("box planned %q without --allow-weaken, want no change", boxOp)
	}
	for _, want := range []string{"box: nic 0 (lan) security groups not restored", "unbinds isolate", "nic 0 (lan) guard not restored",
		"10.31.0.250", "--allow-weaken"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings %q lack %q", warnings, want)
		}
	}
	if !strings.HasPrefix(plainOp, string(compose.OpNoChange)) {
		t.Errorf("plain planned %q over an undeclared binding and guard, want no change", plainOp)
	}
	dBox, _, dWarnings := diff(false)
	if !strings.Contains(boxOp, dBox) || dWarnings != warnings {
		t.Errorf("diff and up disagree:\n diff box %q warnings %q\n up   box %q warnings %q", dBox, dWarnings, boxOp, warnings)
	}

	// A deploy without the opt-in keeps the isolation in place, and its own
	// stream (not only the dry-run's) says what it withheld, for a caller
	// that does not plan first (the UI, REST, gitops).
	sawWithheld := false
	for _, p := range deployRequest(t, ctx, dc, &pb.DeployStackRequest{ComposeYaml: composeNICSecurity}) {
		if p.Phase == "error" {
			t.Fatalf("deploy failed for %s: %s", p.VmName, p.Error)
		}
		if p.Phase == "warning" && strings.Contains(p.Detail, "box: nic 0 (lan) security groups not restored") {
			sawWithheld = true
		}
	}
	if !sawWithheld {
		t.Error("the executing deploy's stream did not report the withheld restore")
	}
	if b := liveSec(t, deployer, "box"); !slices.Equal(b.SecurityGroups, []string{"isolate"}) || b.Guard == nil || len(b.Guard.Allowed) != 0 {
		t.Fatalf("box after a deploy without --allow-weaken = %+v (guard %+v), want the operator's isolation kept", b, b.Guard)
	}

	// With it, the plan restores both and still names what it weakens.
	boxOp, _, warnings = plan(true)
	if !strings.HasPrefix(boxOp, string(compose.OpUpdate)) || !strings.Contains(boxOp, compose.NICSecurityGroupsFieldPrefix+"0") ||
		!strings.Contains(boxOp, compose.NICGuardFieldPrefix+"0") {
		t.Errorf("box planned %q with --allow-weaken, want an update of its binding and guard", boxOp)
	}
	if !strings.Contains(warnings, "applied with --allow-weaken") || !strings.Contains(warnings, "unbinds isolate") {
		t.Errorf("warnings %q do not name the weakening applied", warnings)
	}
	if dBox, _, dWarnings := diff(true); !strings.Contains(boxOp, dBox) || dWarnings != warnings {
		t.Errorf("diff --allow-weaken and up --allow-weaken disagree:\n diff %q %q\n up %q %q", dBox, dWarnings, boxOp, warnings)
	}

	// The deploy puts box back, on every replica, and leaves plain as the
	// operator set it.
	eventsBefore := len(deployer.Virt.EventLog())
	deployWith(t, ctx, dc, composeNICSecurity, true)
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

	// Converged: the same file plans no change, with or without the opt-in.
	for _, aw := range []bool{false, true} {
		for _, p := range planWith(t, ctx, dc, composeNICSecurity, aw) {
			if (p.VmName == "box" || p.VmName == "plain") && p.Phase != string(compose.OpNoChange) {
				t.Errorf("after the restore %s planned %q (%s), want no change", p.VmName, p.Phase, p.Detail)
			}
		}
	}
}

// planWith is a dry-run deploy's progress.
func planWith(t *testing.T, ctx context.Context, client pb.LiteVirtClient, yaml string, allowWeaken bool) []*pb.DeployProgress {
	t.Helper()
	return deployRequest(t, ctx, client, &pb.DeployStackRequest{ComposeYaml: yaml, DryRun: true, AllowWeaken: allowWeaken})
}

// deployWith runs a deploy and fails on an error phase.
func deployWith(t *testing.T, ctx context.Context, client pb.LiteVirtClient, yaml string, allowWeaken bool) {
	t.Helper()
	for _, p := range deployRequest(t, ctx, client, &pb.DeployStackRequest{ComposeYaml: yaml, AllowWeaken: allowWeaken}) {
		if p.Phase == "error" {
			t.Fatalf("deploy failed for %s: %s", p.VmName, p.Error)
		}
	}
}

func deployRequest(t *testing.T, ctx context.Context, client pb.LiteVirtClient, req *pb.DeployStackRequest) []*pb.DeployProgress {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, req)
	if err != nil {
		t.Fatalf("DeployStack: %v", err)
	}
	var out []*pb.DeployProgress
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("DeployStack stream: %v", err)
		}
		out = append(out, p)
	}
}
