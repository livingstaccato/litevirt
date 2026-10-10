package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// Disk discard, per-disk I/O limits and virtio-net multiqueue ride in the VM's
// stored spec, and every domain definition of the VM is rendered from it.

const composeTuneBase = `name: upd

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 2
    memory: 512
    placement:
      host: node-0
    disks:
      root:
        size: 1G
        iotune:
          read_iops_sec: 500
      data:
        size: 1G
    network:
      - name: hc
        queues: 2
    healthcheck:
      type: tcp
      target: "5432"
      interval: 1h
      action: alert
`

func hasQueues(x string, n int) bool {
	return strings.Contains(x, fmt.Sprintf("queues=%q", fmt.Sprint(n))) || strings.Contains(x, fmt.Sprintf("queues='%d'", n))
}

func tuneOf(t *testing.T, node *Node, dev string) lv.IOTune {
	t.Helper()
	x, err := node.Virt.DumpXML("db")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := lv.DiskIOTuneFromXML(x, dev)
	if !ok {
		t.Fatalf("no disk %s in the domain:\n%s", dev, x)
	}
	return got
}

// latchIOFeature opens the disk/NIC feature's gate for real on every node: the
// production wiring of the release-feature gate, the shared release token
// latched across the fleet, and the feature's first use recorded and
// acknowledged by every host.
func latchIOFeature(t *testing.T, c *Cluster) {
	t.Helper()
	ctx := context.Background()
	gates := gateAll(t, c)
	wireReleaseFeatures(t, c, gates)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch", n.Name)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		n := n
		var last error
		eventually(t, 15*time.Second, n.Name+" to open the disk/NIC gate", func() bool {
			last = n.Server.WithReleaseFeature(ctx, capabilities.FeatureVMDiskNICIO,
				func(_ context.Context, g capabilities.FeatureGrant) error {
					return g.Check(capabilities.FeatureVMDiskNICIO)
				})
			return last == nil
		})
	}
}

// newTunedNode is newUpdateNode with the disk/NIC feature latched.
func newTunedNode(t *testing.T) (*Node, pb.LiteVirtClient) {
	t.Helper()
	c, node, client := newComposeFailNode(t)
	node.Server.SetBridgeEnsure(node.Net.EnsureBridge)
	latchIOFeature(t, c)
	if _, err := client.CreateNetwork(context.Background(), &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return node, client
}

func setupTunedVM(t *testing.T) (context.Context, *Node, pb.LiteVirtClient, vmIdentity) {
	t.Helper()
	node, client := newTunedNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, composeTuneBase)
	waitRunning(t, ctx, node, "db")
	return ctx, node, client, identityOf(t, ctx, node, "db", true)
}

// A create renders the compose file's tuning into the domain, and defaults an
// unset discard to unmap on the local store (stored in the spec, so it is the
// VM's own setting from here on).
//
// Mutations: drop ApplyDiskTuning from baseDomainConfig — the iotune read goes
// red; drop ApplyNICTuning — the queues check goes red; drop the create-time
// default — the data disk's spec/XML checks go red.
func TestFleet_ComposeCreateRendersDiskAndNICTuning(t *testing.T) {
	ctx, node, _, _ := setupTunedVM(t)
	x := node.Virt.DefinedXML("db")
	if got := tuneOf(t, node, "vda"); got.ReadIopsSec != 500 {
		t.Errorf("vda throttle = %+v, want read_iops_sec 500", got)
	}
	if got := tuneOf(t, node, "vdb"); !got.IsZero() {
		t.Errorf("vdb names no limit but is throttled: %+v", got)
	}
	if !hasQueues(x, 2) || strings.Contains(x, "vhost") {
		t.Errorf("the NIC has no multiqueue driver (or it forces vhost):\n%s", x)
	}
	if n := strings.Count(x, `discard="unmap"`); n != 2 {
		t.Errorf("%d disks render discard=unmap, want both (the local-store default)\n%s", n, x)
	}
	spec := storedSpec(t, ctx, node, "db")
	if spec.Network[0].Mac == "" {
		t.Errorf("the NIC's assigned MAC was not recorded in the spec, so its queues cannot follow it through a hot-plug")
	}
	if spec.Disks[1].Discard != "unmap" || spec.Network[0].Queues != 2 || spec.Disks[0].Io.GetReadIopsSec() != 500 {
		t.Errorf("stored spec = %+v / %+v / %+v", spec.Disks[0], spec.Disks[1], spec.Network[0])
	}
}

// Changing a limit in the file throttles the running disk in place: the same
// VM, no restart, no redefine, and the spec follows. Applying the same file
// again is no change.
//
// Mutations: classify iotune as restart-class — the VM is redefined and the
// no-define check goes red; drop the "disk_io" case from applyLiveMetadata — the
// XML check goes red.
func TestFleet_ComposeIOTuneChangeIsAppliedLive(t *testing.T) {
	ctx, node, client, before := setupTunedVM(t)
	next := edit(t, composeTuneBase, "read_iops_sec: 500", "read_iops_sec: 800\n          write_bytes_sec: 10M")

	if phase, detail := planDetailFor(t, ctx, client, next, "db"); phase != string(compose.OpUpdate) || !strings.Contains(detail, "in place") {
		t.Errorf("plan for an iotune change = %s %q, want an update applied in place", phase, detail)
	}
	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, next)
	assertSameVM(t, ctx, node, "db", before, from, false)
	if got := tuneOf(t, node, "vda"); got.ReadIopsSec != 800 || got.WriteBytesSec != 10<<20 {
		t.Errorf("vda throttle after the update = %+v", got)
	}
	if got := storedSpec(t, ctx, node, "db").Disks[0].Io; got.GetReadIopsSec() != 800 {
		t.Errorf("stored limits = %+v", got)
	}
	if phase, detail := planDetailFor(t, ctx, client, next, "db"); phase != string(compose.OpNoChange) {
		t.Errorf("re-applying plans %s %q, want no change", phase, detail)
	}
	// An empty iotune clears the limit.
	cleared := edit(t, next, "        iotune:\n          read_iops_sec: 800\n          write_bytes_sec: 10M\n", "        iotune: {}\n")
	deployClean(t, ctx, client, cleared)
	if got := tuneOf(t, node, "vda"); !got.IsZero() {
		t.Errorf("vda throttle after `iotune: {}` = %+v, want none", got)
	}
}

// discard and queues bake into the domain: the same VM is reconfigured and
// restarted (redefined, never undefined), and the new definition carries them.
//
// Mutations: skip persistHardwareTuning — the redefine renders the old spec and
// the XML checks go red; drop RedefineHardware from UpdateVM's redefine
// condition — nothing is redefined and the XML checks go red.
func TestFleet_ComposeDiscardAndQueuesChangeRestartTheSameVM(t *testing.T) {
	ctx, node, client, before := setupTunedVM(t)
	next := edit(t, composeTuneBase, "        size: 1G\n        iotune:", "        size: 1G\n        discard: off\n        iotune:")
	next = edit(t, next, "queues: 2", "queues: 4")

	if _, detail := planDetailFor(t, ctx, client, next, "db"); !strings.Contains(detail, "restart") || !strings.Contains(detail, "disks kept") {
		t.Errorf("plan = %q, want a restart of the same VM with its disks kept", detail)
	}
	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, next)
	assertSameVM(t, ctx, node, "db", before, from, true)
	x := node.Virt.DefinedXML("db")
	if !strings.Contains(x, "discard='ignore'") && !strings.Contains(x, `discard="ignore"`) || !hasQueues(x, 4) {
		t.Errorf("redefined domain lacks the new discard/queues:\n%s", x)
	}
	spec := storedSpec(t, ctx, node, "db")
	if spec.Disks[0].Discard != "ignore" || spec.Network[0].Queues != 4 {
		t.Errorf("stored spec = %+v %+v", spec.Disks[0], spec.Network[0])
	}
	if got := tuneOf(t, node, "vda"); got.ReadIopsSec != 500 {
		t.Errorf("the redefine dropped the throttle: %+v", got)
	}
	waitRunning(t, ctx, node, "db")
}

// A limit set from another node is forwarded to the owner, throttles the disk
// there, is recorded in the spec and replicated, and is carried by a cold
// migration to the target: the destination's definition has it, and so does the
// VM's spec. Independent replicas: the write reaches the other node by
// replication, not through a shared database.
//
// Mutations: make SetDiskIO apply locally instead of forwarding — the owner's
// XML check goes red; drop the spec write — the replicated/migrated spec checks
// go red.
func TestFleet_SetDiskIOForwardsAndMigrationCarriesIt(t *testing.T) {
	sc := newColdStoppedScenarioWith(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 91})
	ctx := context.Background()
	if _, _, err := corrosion.MutateDesiredSpec(ctx, sc.src.DB, "os1", func(old string) (string, error) {
		spec := &pb.VMSpec{}
		if err := json.Unmarshal([]byte(old), spec); err != nil {
			return "", err
		}
		spec.Disks = []*pb.DiskSpec{{Name: "root", Bus: "virtio"}, {Name: "data", Bus: "virtio"}}
		b, err := json.Marshal(spec)
		return string(b), err
	}); err != nil {
		t.Fatalf("seed spec disks: %v", err)
	}
	sc.c.WaitConverged(t, convergeTimeout)
	latchIOFeature(t, sc.c)

	// dst is not the owner: the call is forwarded.
	if _, err := sc.c.SelfClient(sc.dst).SetDiskIO(ctx, &pb.SetDiskIORequest{
		VmName: "os1", DiskName: "root", Limits: &pb.DiskIOLimits{TotalIopsSec: 250, TotalIopsSecMax: 500, BurstSeconds: 3},
	}); err != nil {
		t.Fatalf("SetDiskIO via the non-owner: %v", err)
	}
	want := lv.IOTune{TotalIopsSec: 250, TotalIopsSecMax: 500, BurstSec: 3}
	srcXML, _ := sc.src.Virt.DumpXMLInactive("os1")
	if got, _ := lv.DiskIOTuneFromXML(srcXML, "vda"); got != want {
		t.Fatalf("the owner's domain throttle = %+v, want %+v", got, want)
	}
	if sc.dst.Virt.DomainExists("os1") {
		t.Fatal("the forwarding node defined a domain for a VM it does not own")
	}
	sc.c.WaitConverged(t, convergeTimeout)
	if got := specOn(t, sc.dst, "os1").Disks[0].Io.GetTotalIopsSec(); got != 250 {
		t.Fatalf("the limit did not replicate to the non-owner's spec: %d", got)
	}

	// The migration gate wants live health the scenario does not publish; the
	// latch has done its work (the call above was accepted), so unwire it.
	for _, n := range sc.c.Nodes {
		n.Server.SetGate(nil)
	}
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("migrate --cold: %v", err)
	}
	dstXML, err := sc.dst.Virt.DumpXMLInactive("os1")
	if err != nil {
		t.Fatalf("target domain: %v", err)
	}
	if got, _ := lv.DiskIOTuneFromXML(dstXML, "vda"); got != want {
		t.Errorf("the migrated domain's throttle = %+v, want %+v", got, want)
	}
	if got := specOn(t, sc.dst, "os1").Disks[0].Io.GetTotalIopsSec(); got != 250 {
		t.Errorf("the migrated VM's spec lost the limit: %d", got)
	}
}

func specOn(t *testing.T, n *Node, vm string) *pb.VMSpec {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), n.DB, vm)
	if err != nil || rec == nil {
		t.Fatalf("GetVM(%s) on %s: %v %v", vm, n.Name, rec, err)
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(rec.Spec), spec); err != nil {
		t.Fatalf("parse spec on %s: %v", n.Name, err)
	}
	return spec
}

const composeNoTuning = `name: upd

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 2
    memory: 512
    placement:
      host: node-0
    disks:
      root: 1G
    network:
      - name: hc
`

const composeImplicitRoot = `name: upd

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 2
    memory: 512
    placement:
      host: node-0
`

// Before the token latches, a deploy that sets any tuning is refused before a
// VM exists, and a deploy that sets none renders exactly what main does: no
// discard default is stored or rendered, for an explicit or the implicit root.
//
// Mutations: drop the up-front refusal in DeployStack — the first stage goes
// red; apply the create default without the latch check — the stored-spec and
// XML checks go red.
func TestFleet_DiskNICIORefusedUntilTheTokenLatches(t *testing.T) {
	_, node, client := newComposeFailNode(t) // no gate wired: not latched
	ctx := context.Background()
	for name, y := range map[string]string{
		"iotune":  composeTuneBase,
		"discard": strings.Replace(composeNoTuning, "      root: 1G\n", "      root:\n        size: 1G\n        discard: on\n", 1),
		"queues":  strings.Replace(composeNoTuning, "      - name: hc\n", "      - name: hc\n        queues: 2\n", 1),
	} {
		stream, err := client.DeployStack(ctx, &pb.DeployStackRequest{ComposeYaml: y})
		if err == nil {
			_, err = stream.Recv()
		}
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade") {
			t.Fatalf("%s before the latch: err = %v, want FailedPrecondition naming the cluster upgrade", name, err)
		}
		if rec, _ := corrosion.GetVM(ctx, node.DB, "db"); rec != nil {
			t.Fatalf("%s: a VM was created despite the refusal", name)
		}
	}
}

func unlatchedCreateRendersAsMain(t *testing.T, y string, implicit bool) {
	t.Helper()
	ctx := context.Background()
	n, c := newUpdateNode(t) // no gate wired: not latched
	deployClean(t, ctx, c, y)
	x := n.Virt.DefinedXML("db")
	if strings.Contains(x, "discard") || strings.Contains(x, "iotune") || strings.Contains(x, "queues") {
		t.Errorf("an unlatched create renders tuning:\n%s", x)
	}
	spec := storedSpec(t, ctx, n, "db")
	for _, d := range spec.Disks {
		if d.Discard != "" {
			t.Errorf("an unlatched create stored discard %q", d.Discard)
		}
	}
	if implicit && len(spec.Disks) != 0 {
		t.Errorf("an unlatched create listed the implicit root in the spec: %+v", spec.Disks)
	}
}

func TestFleet_DiskNICIOUnlatchedExplicitRootRendersAsMain(t *testing.T) {
	unlatchedCreateRendersAsMain(t, composeNoTuning, false)
}

func TestFleet_DiskNICIOUnlatchedImplicitRootRendersAsMain(t *testing.T) {
	unlatchedCreateRendersAsMain(t, composeImplicitRoot, true)
}

// After the latch the default also reaches the root disk a VM gets when no
// disks are named: it is listed in the spec, with discard unmap, and rendered.
//
// Mutation: skip adding the implicit root to the spec — the spec check goes red.
func TestFleet_ImplicitRootDiskGetsTheDefaultDiscardOnceLatched(t *testing.T) {
	node, client := newTunedNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, composeImplicitRoot)
	waitRunning(t, ctx, node, "db")
	spec := storedSpec(t, ctx, node, "db")
	if len(spec.Disks) != 1 || spec.Disks[0].Name != "root" || spec.Disks[0].Discard != "unmap" {
		t.Fatalf("stored disks = %+v, want root with discard unmap", spec.Disks)
	}
	if !strings.Contains(node.Virt.DefinedXML("db"), `discard="unmap"`) {
		t.Errorf("the implicit root does not render discard:\n%s", node.Virt.DefinedXML("db"))
	}
	// Re-applying the same (diskless) file is no change, and keeps the VM.
	if phase, detail := planDetailFor(t, ctx, client, composeImplicitRoot, "db"); phase != string(compose.OpNoChange) {
		t.Errorf("re-applying plans %s %q, want no change", phase, detail)
	}
}
