package fleet

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// An update is applied with the least destructive mechanism the change
// allows, on the default strategy (no `update:` block): a change that can be
// applied to the running VM is applied in place, one that bakes into the
// domain is a reconfigure + restart of the SAME VM, and only a change of VM
// identity recreates. The regression: every update was a DeleteVM (disks
// removed) plus a fresh create, so a label edit wiped the VM's disk.

const composeUpdateBase = `name: upd

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    labels:
      tier: a
    network:
      - name: hc
    healthcheck:
      type: tcp
      target: "5432"
      interval: 1h
      action: alert
`

var domainMACRE = regexp.MustCompile(`<mac address="([^"]+)"`)

// vmIdentity is what must survive an update that keeps the VM.
type vmIdentity struct {
	createdAt string
	uuid      string
	mac       string
	disks     map[string]string // disk name → path
}

const diskSentinel = "litevirt-test: data that must survive an update\n"

func newUpdateNode(t *testing.T) (*Node, pb.LiteVirtClient) {
	t.Helper()
	_, node, client := newComposeFailNode(t)
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	if _, err := client.CreateNetwork(context.Background(), &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return node, client
}

// identityOf reads db's identity and, the first time, marks each disk file
// with a sentinel the test checks is still there afterwards.
func identityOf(t *testing.T, ctx context.Context, node *Node, vm string, mark bool) vmIdentity {
	t.Helper()
	rec, err := corrosion.GetVM(ctx, node.DB, vm)
	if err != nil || rec == nil {
		t.Fatalf("GetVM(%s): %v %v", vm, rec, err)
	}
	id := vmIdentity{createdAt: rec.CreatedAt, uuid: specUUID(t, rec.Spec), disks: map[string]string{}}
	if m := domainMACRE.FindStringSubmatch(node.Virt.DefinedXML(vm)); m != nil {
		id.mac = m[1]
	}
	disks, err := corrosion.ListDisks(ctx, node.DB, vm)
	if err != nil {
		t.Fatalf("ListDisks(%s): %v", vm, err)
	}
	for _, d := range disks {
		id.disks[d.DiskName] = d.Path
		if mark {
			if err := os.WriteFile(d.Path, []byte(diskSentinel), 0o644); err != nil {
				t.Fatalf("mark disk %s: %v", d.Path, err)
			}
		}
	}
	if id.mac == "" || len(id.disks) == 0 {
		t.Fatalf("%s identity incomplete: %+v", vm, id)
	}
	return id
}

// assertSameVM checks the update kept the VM: same incarnation, same uuid and
// MAC, same disk paths with the sentinel intact, and no undefine (or, unless
// redefined is allowed, define) of the domain.
func assertSameVM(t *testing.T, ctx context.Context, node *Node, vm string, before vmIdentity, from int, redefineAllowed bool) {
	t.Helper()
	after := identityOf(t, ctx, node, vm, false)
	if after.createdAt != before.createdAt {
		t.Errorf("%s created_at %s → %s: the VM was recreated", vm, before.createdAt, after.createdAt)
	}
	if after.uuid != before.uuid {
		t.Errorf("%s uuid %s → %s: the VM was recreated", vm, before.uuid, after.uuid)
	}
	if after.mac != before.mac {
		t.Errorf("%s MAC %s → %s: the VM was recreated", vm, before.mac, after.mac)
	}
	for name, path := range before.disks {
		if after.disks[name] != path {
			t.Errorf("%s disk %s path %s → %s", vm, name, path, after.disks[name])
		}
		if b, err := os.ReadFile(path); err != nil || string(b) != diskSentinel {
			t.Errorf("%s disk %s at %s lost its data (err=%v, %d bytes)", vm, name, path, err, len(b))
		}
	}
	for _, e := range node.Virt.EventLog()[from:] {
		if e.Domain != vm {
			continue
		}
		// A redefine replaces the domain definition while keeping its disks
		// and firmware state (undefine keep_state=true, then define); anything
		// else is the VM being torn down.
		redefine := e.Op == "define" || (e.Op == "undefine" && strings.HasPrefix(e.Note, "keep_state=true"))
		if (e.Op == "undefine" || e.Op == "define") && !(redefine && redefineAllowed) {
			t.Errorf("%s: %s %s during an update that keeps the VM", vm, e.Op, e.Note)
		}
	}
}

func storedSpec(t *testing.T, ctx context.Context, node *Node, vm string) *pb.VMSpec {
	t.Helper()
	rec, err := corrosion.GetVM(ctx, node.DB, vm)
	if err != nil || rec == nil {
		t.Fatalf("GetVM(%s): %v", vm, err)
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(rec.Spec), spec); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return spec
}

func planDetailFor(t *testing.T, ctx context.Context, client pb.LiteVirtClient, yaml, vm string) (string, string) {
	t.Helper()
	for _, op := range dryRunPlan(t, ctx, client, yaml) {
		if op.VmName == vm && (op.Phase == string(compose.OpUpdate) || op.Phase == string(compose.OpCreate) || op.Phase == string(compose.OpNoChange)) {
			return op.Phase, op.Detail
		}
	}
	t.Fatalf("no plan entry for %s", vm)
	return "", ""
}

func waitRunning(t *testing.T, ctx context.Context, node *Node, vm string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec, _ := corrosion.GetVM(ctx, node.DB, vm)
		if rec != nil && rec.State == "running" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %+v, want running", vm, rec)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func setupUpdateVM(t *testing.T) (context.Context, *Node, pb.LiteVirtClient, vmIdentity) {
	t.Helper()
	node, client := newUpdateNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, composeUpdateBase)
	waitRunning(t, ctx, node, "db")
	return ctx, node, client, identityOf(t, ctx, node, "db", true)
}

func edit(t *testing.T, yaml, old, new string) string {
	t.Helper()
	out := strings.Replace(yaml, old, new, 1)
	if out == yaml {
		t.Fatalf("fixture edit %q did not apply", old)
	}
	return out
}

func TestFleet_ComposeLabelChangeKeepsTheVM(t *testing.T) {
	ctx, node, client, before := setupUpdateVM(t)
	next := edit(t, composeUpdateBase, "      tier: a\n", "      tier: b\n")

	if phase, detail := planDetailFor(t, ctx, client, next, "db"); phase != string(compose.OpUpdate) || !strings.Contains(detail, "in place") {
		t.Errorf("plan for a label change = %s %q, want an update applied in place", phase, detail)
	}
	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, next)
	assertSameVM(t, ctx, node, "db", before, from, false)
	if got := storedSpec(t, ctx, node, "db").Labels["tier"]; got != "b" {
		t.Errorf("label tier = %q after the update, want b", got)
	}
}

func TestFleet_ComposeMemoryChangeKeepsTheVM(t *testing.T) {
	ctx, node, client, before := setupUpdateVM(t)
	next := edit(t, composeUpdateBase, "    memory: 512\n", "    memory: 384\n")

	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, next)
	assertSameVM(t, ctx, node, "db", before, from, false)
	if got := storedSpec(t, ctx, node, "db").MemoryMib; got != 384 {
		t.Errorf("memory = %d after the update, want 384", got)
	}
	// Converged: the same file again is no change.
	if phase, detail := planDetailFor(t, ctx, client, next, "db"); phase != string(compose.OpNoChange) {
		t.Errorf("re-applying the file plans %s %q, want no change", phase, detail)
	}
}

// The rolling engine applies a change that can keep the VM to the VM, whatever
// the strategy: a label edit under `rolling` is not a recreate.
func TestFleet_ComposeRollingStrategyLabelChangeKeepsTheVM(t *testing.T) {
	node, client := newUpdateNode(t)
	ctx := context.Background()
	base := edit(t, composeUpdateBase, "  db:\n    image: test\n", "  db:\n    update:\n      strategy: rolling\n    image: test\n")
	deployClean(t, ctx, client, base)
	waitRunning(t, ctx, node, "db")
	before := identityOf(t, ctx, node, "db", true)

	next := edit(t, base, "      tier: a\n", "      tier: b\n")
	from := len(node.Virt.EventLog())
	msgs := deployClean(t, ctx, client, next)
	sawRolling := false
	for _, p := range msgs {
		if p.Phase == "rolling-update" {
			sawRolling = true
		}
	}
	if !sawRolling {
		t.Fatalf("deploy did not take the rolling path; got %v", msgs)
	}
	assertSameVM(t, ctx, node, "db", before, from, false)
	if got := storedSpec(t, ctx, node, "db").Labels["tier"]; got != "b" {
		t.Errorf("label tier = %q after the update, want b", got)
	}
}

// A container has no in-place reconfigure: its update is a recreate, and the
// plan says so.
func TestFleet_ComposeContainerUpdateIsPlannedAsARecreate(t *testing.T) {
	_, client := newContainerComposeNode(t)
	ctx := context.Background()
	yaml := composeContainerDeps[:strings.Index(composeContainerDeps, "  app:\n")]
	deployClean(t, ctx, client, yaml)
	next := edit(t, yaml, "    memory: 256\n", "    memory: 384\n")
	phase, detail := planDetailFor(t, ctx, client, next, "ct")
	if phase != string(compose.OpUpdate) || !strings.Contains(detail, "recreate") || !strings.Contains(detail, "container is replaced") {
		t.Errorf("container update planned as %s %q, want a recreate that says the container is replaced", phase, detail)
	}
}

func TestFleet_ComposeHealthcheckChangeKeepsTheVM(t *testing.T) {
	ctx, node, client, before := setupUpdateVM(t)
	next := edit(t, composeUpdateBase, `      target: "5432"`, `      target: "5433"`)

	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, next)
	assertSameVM(t, ctx, node, "db", before, from, false)
	if got := storedSpec(t, ctx, node, "db").GetHealthcheck().GetTarget(); got != "5433" {
		t.Errorf("healthcheck target = %q after the update, want 5433", got)
	}
}

// A change that bakes into the domain (a cpu grow with no hotplug ceiling)
// reconfigures and restarts the same VM: redefined, never undefined.
func TestFleet_ComposeRestartClassChangeRestartsTheSameVM(t *testing.T) {
	ctx, node, client, before := setupUpdateVM(t)
	next := edit(t, composeUpdateBase, "    cpu: 1\n", "    cpu: 2\n")

	if _, detail := planDetailFor(t, ctx, client, next, "db"); !strings.Contains(detail, "restart") || !strings.Contains(detail, "disks kept") {
		t.Errorf("plan for a cpu grow = %q, want a restart of the same VM with its disks kept", detail)
	}
	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, next)
	assertSameVM(t, ctx, node, "db", before, from, true)
	if got := storedSpec(t, ctx, node, "db").Cpu; got != 2 {
		t.Errorf("cpu = %d after the update, want 2", got)
	}
	waitRunning(t, ctx, node, "db")
}

// An image change needs a new root disk: the plan says the disks are replaced.
func TestFleet_ComposeImageChangeIsPlannedAsADiskReplacingRecreate(t *testing.T) {
	ctx, node, client, _ := setupUpdateVM(t)
	if err := node.DB.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES ('test2', 'qcow2', 'file:///dev/null', 'deadbeef', 1024, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	if err := writeEmptyImageFile(node.Server.ImagePathForTests("test2")); err != nil {
		t.Fatalf("stage image file: %v", err)
	}
	next := edit(t, composeUpdateBase, "    image: test\n", "    image: test2\n")
	next = edit(t, next, "images:\n  test:\n", "images:\n  test2:\n    source: file:///dev/null\n  test:\n")
	phase, detail := planDetailFor(t, ctx, client, next, "db")
	if phase != string(compose.OpUpdate) {
		t.Fatalf("image change planned as %s %q, want an update", phase, detail)
	}
	for _, want := range []string{"recreate", "disks are replaced", "image"} {
		if !strings.Contains(detail, want) {
			t.Errorf("plan for an image change %q does not say %q", detail, want)
		}
	}
}
