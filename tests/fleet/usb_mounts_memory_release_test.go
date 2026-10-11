package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/lxc"
)

// seedStoppedVM puts a stopped VM `hv` on owner: spec, a root disk row and a
// defined domain, replicated to every node.
func seedStoppedVM(t *testing.T, c *Cluster, owner *Node) {
	t.Helper()
	spec, _ := json.Marshal(&pb.VMSpec{Name: "hv", Cpu: 1, MemoryMib: 1024,
		Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio"}}})
	if err := corrosion.InsertVM(context.Background(), owner.DB, corrosion.VMRecord{
		Name: "hv", HostName: owner.Name, State: "stopped", Spec: string(spec), CPUActual: 1, MemActual: 1024,
	}, nil, []corrosion.DiskRecord{{VMName: "hv", DiskName: "root", HostName: owner.Name,
		Path: "/var/lib/litevirt/disks/hv-root.qcow2", SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda", Bus: "virtio"}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	x, err := lv.GenerateDomainXML(lv.VMConfig{Name: "hv", CPU: 1, MemoryMiB: 1024,
		Disks: []lv.DiskConfig{{Name: "root", Path: "/var/lib/litevirt/disks/hv-root.qcow2", Bus: "virtio"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Virt.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
}

func hotplugMaxOn(t *testing.T, n *Node, vm string) int32 {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), n.DB, vm)
	if err != nil || rec == nil {
		return -1
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(rec.Spec), spec); err != nil {
		t.Fatalf("parse spec on %s: %v", n.Name, err)
	}
	return spec.MemoryHotplugMaxMib
}

// USB devices, memory hot-add and container host access go through the shared
// release token's usb_mounts_memory gate. While one host is still on the
// previous build the token cannot latch: turning hot-add on is refused with the
// release gate's text, and nothing is recorded or stored. Once the fleet is
// uniform the first write records the feature's use, every replica holds the
// record, and only then does the band land in the spec — a peer never sees it
// without the record. The request enters on a node that does not own the VM,
// so it is the owner, the node that writes, whose gate records the use.
//
// Mutations: write UpdateVM's spec through the plain MutateDesiredSpec with
// no grant (the stub's entry-only check) — the RecordedBy check goes red, and
// with the refusal also removed at the entry the refusal stage goes red.
func TestFleet_USBMountsMemoryReleaseToken_RefusedThenRecordedBeforeData(t *testing.T) {
	c, _ := latchedFleet(t, 3, 5127)
	ctx := context.Background()
	owner, entry, old := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	seedStoppedVM(t, c, owner)
	feature := string(capabilities.FeatureUSBMountsMemory)
	req := &pb.UpdateVMRequest{Name: "hv", MemoryHotplugMaxMib: proto.Int32(4096)}

	// 1. One host on the previous build: refused, nothing recorded, nothing stored.
	old.Server.SetWALQuarantined(func() bool { return true })
	want := "the cluster upgrade must finish first (usb_mounts_memory needs " + capabilities.ReleaseToken + ")"
	_, err := c.SelfClient(entry).UpdateVM(ctx, req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) ||
		!strings.Contains(err.Error(), old.Name) || !strings.HasSuffix(status.Convert(err).Message(), "— see `lv cluster upgrade-status`") {
		t.Fatalf("UpdateVM hot-add with %s on the old build: %v, want FailedPrecondition %q naming %s and ending with the upgrade-status pointer",
			old.Name, err, want, old.Name)
	}
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, feature) {
			t.Fatalf("%s holds a use of usb_mounts_memory after only a refusal", n.Name)
		}
		if got := hotplugMaxOn(t, n, "hv"); got != 0 {
			t.Fatalf("%s: a refused write stored hot-add max %d", n.Name, got)
		}
	}

	// 2. Uniform fleet. First the latch is driven on every node by an unrelated
	// feature, as the HA monitor does in production, so the entry node's check
	// is the cheap local hint and only the owner records the use.
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	info, _ := capabilities.LookupFeature(capabilities.FeatureUSBMountsMemory)
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		capabilities.FeatureUSBMountsMemory: info,
		"widgets":                           {Token: capabilities.ReleaseToken, Description: "Widgets"},
	}))
	for _, n := range c.Nodes {
		n := n
		eventually(t, 20*time.Second, n.Name+" to latch the release token", func() bool {
			return writeFeature(ctx, n, "widgets") == nil
		})
	}
	if featureUsedOn(t, owner, capabilities.ReleaseToken, feature) {
		t.Fatal("usb_mounts_memory was recorded before any write of it")
	}
	var violation atomic.Value
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, n := range c.Nodes {
				rec, gerr := corrosion.GetVM(ctx, n.DB, "hv")
				if gerr != nil || rec == nil || !strings.Contains(rec.Spec, "memory_hotplug_max_mib") {
					continue
				}
				if used, uerr := corrosion.ReleaseFeatureUsed(ctx, n.DB, capabilities.ReleaseToken, feature); uerr == nil && !used {
					violation.Store(n.Name)
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	var last error
	eventually(t, 20*time.Second, "UpdateVM hot-add to be accepted on a uniform fleet", func() bool {
		_, last = c.SelfClient(entry).UpdateVM(ctx, req)
		return last == nil
	})
	c.WaitConverged(t, convergeTimeout)
	close(stop)
	<-done
	if v := violation.Load(); v != nil {
		t.Fatalf("%s saw memory hot-add in a spec before it held the use record", v)
	}
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, feature) {
			t.Errorf("%s does not hold the usb_mounts_memory use record", n.Name)
		}
		uses, _ := corrosion.ListReleaseFeatureUses(ctx, n.DB)
		for _, u := range uses {
			if u.Feature == feature && u.RecordedBy != owner.Name {
				t.Errorf("%s: the use was last recorded by %s, want the writing node %s", n.Name, u.RecordedBy, owner.Name)
			}
		}
		if got := hotplugMaxOn(t, n, "hv"); got != 4096 {
			t.Errorf("%s: hot-add max after the write = %d, want 4096", n.Name, got)
		}
	}
}

// wrongGrantGate opens every feature but hands out another feature's grant, so
// only a write through a CHECKING writer is refused: it pins the writer choice
// at a call site whose grant is taken upstream.
type wrongGrantGate struct{ t testing.TB }

func (g wrongGrantGate) WithFeature(ctx context.Context, _ capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	return write(ctx, capabilities.GrantForTest(g.t, capabilities.FeatureVMLimits))
}

func (wrongGrantGate) FeatureAvailable(capabilities.Feature) bool { return true }

// An admin's restore that keeps a backup's host mount writes the container row
// through the feature's checking writer: handed a grant that is not the
// feature's, the restore is refused and no row lands.
//
// Mutation: write the restored row with the plain CreateContainerAtomic in
// RestoreContainer — the restore succeeds and this goes red.
func TestFleet_AdminRestoreOfHostAccessGoesThroughTheWriter(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		n.Server.SetReleaseFeatureGate(openReleaseGate{t})
	}
	allowed, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.MkdirAll(filepath.Join(allowed, "data"), 0o755)
	lxc.TrustHookBinaryForTest(t)
	dst.CT.SetHostAccessPolicy(lxc.HostAccess{MountPaths: []string{allowed}, HookBinary: "/opt/litevirt"})
	createSizedContainer(t, c, src, "ct", "", 0, 256)
	rec, _ := corrosion.GetContainer(ctx, src.DB, src.Name, "ct")
	cs := corrosion.DecodeCreateSpec(rec.CreateSpec)
	cs.Mounts = []corrosion.ContainerHostMount{{HostPath: filepath.Join(allowed, "data"), ContainerPath: "/data"}}
	rec.CreateSpec = corrosion.EncodeCreateSpec(cs)
	if err := corrosion.UpsertContainer(ctx, src.DB, *rec); err != nil {
		t.Fatal(err)
	}
	repo, ts := backupContainer(t, c, src, "ct")

	dst.Server.SetReleaseFeatureGate(wrongGrantGate{t})
	err := restoreContainerAt(t, c, dst, repo, "ct", ts)
	if err == nil || !strings.Contains(err.Error(), "without a grant") {
		t.Fatalf("admin restore with another feature's grant = %v; want refused by the writer", err)
	}
	if row, _ := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct"); row != nil {
		t.Fatalf("a refused restore left a row: %+v", row)
	}
}
