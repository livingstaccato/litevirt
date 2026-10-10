package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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

func setupTunedVM(t *testing.T) (context.Context, *Node, pb.LiteVirtClient, vmIdentity) {
	t.Helper()
	node, client := newUpdateNode(t)
	ctx := context.Background()
	deployClean(t, ctx, client, composeTuneBase)
	waitRunning(t, ctx, node, "db")
	return ctx, node, client, identityOf(t, ctx, node, "db", true)
}

// A create renders the compose file's tuning into the domain, and defaults an
// unset discard to unmap on the local store (stored in the spec, so it is the
// VM's own setting from here on).
//
// Mutations: drop the DiskConfig.IOTune copy in CreateVM — the iotune read goes
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
	if !strings.Contains(x, `<driver name="vhost" queues="2"`) {
		t.Errorf("the NIC has no vhost multiqueue driver:\n%s", x)
	}
	if n := strings.Count(x, `discard="unmap"`); n != 2 {
		t.Errorf("%d disks render discard=unmap, want both (the local-store default)\n%s", n, x)
	}
	spec := storedSpec(t, ctx, node, "db")
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
	if !strings.Contains(x, `discard="ignore"`) || !strings.Contains(x, `queues="4"`) {
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
// there, and is carried by a cold migration to the target: the destination's
// definition has it, and so does the VM's spec.
//
// Mutations: make SetDiskIO apply locally instead of forwarding — the owner's
// XML check goes red; drop the spec write — the migrated spec check goes red.
func TestFleet_SetDiskIOForwardsAndMigrationCarriesIt(t *testing.T) {
	sc := newColdStoppedScenario(t)
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
	vm := sc.vm(t)
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Disks[0].Io.GetTotalIopsSec() != 250 {
		t.Errorf("the migrated VM's spec lost the limit: %+v", spec.Disks[0])
	}
}
