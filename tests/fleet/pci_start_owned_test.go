package fleet

// After the hardware_v2 latch, a VM's start realizes its PCI intents on its
// host. A VM that already owns the device realizing an intent there keeps
// it: a restart neither looks for a free one nor claims a second.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// pciStartDev is one inventory row on the test host.
type pciStartDev struct {
	addr, device, typ string
	group             int
}

// pciStartFleet latches hardware_v2 on a two-node fleet and puts vm on its
// first node, pending, with an intent per selector in devs and the devices
// given in that node's inventory, all free.
func pciStartFleet(t *testing.T, ctx context.Context, vm string, devs []*pb.DeviceSpec, inv []pciStartDev) (*Cluster, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 2})
	latchHardwareV2(t, c, gateAll(t, c))
	n := c.Nodes[0]
	for _, d := range inv {
		if err := corrosion.UpsertPCIDevice(ctx, n.DB, corrosion.PCIDeviceRecord{HostName: n.Name, Address: d.addr,
			VendorID: "10de", DeviceID: d.device, DeviceName: d.typ, Type: d.typ, Driver: "vfio-pci", IOMMUGroup: d.group}); err != nil {
			t.Fatal(err)
		}
	}
	disk := filepath.Join(t.TempDir(), vm+"-root.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{Name: vm, HostName: n.Name, State: "pending", CPUActual: 1, MemActual: 256,
		Spec: vmSpecJSON(t, &pb.VMSpec{Name: vm, Cpu: 1, MemoryMib: 256, Devices: devs})},
		nil, []corrosion.DiskRecord{{VMName: vm, DiskName: "root", HostName: n.Name, Path: disk, StorageType: "nfs"}}); err != nil {
		t.Fatal(err)
	}
	occ := map[string]int{}
	for _, d := range devs {
		kind, key := corrosion.ClassifyPCISelector(d)
		payload, err := protojson.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		canon := corrosion.CanonicalPCISelector(d)
		if err := corrosion.UpsertPCIIntent(ctx, n.DB, corrosion.PCIIntentRecord{VMName: vm,
			DeviceID: corrosion.DeterministicPCIIntentID(canon, occ[canon]), HostName: n.Name,
			SelectorKind: kind, SelectorPayload: string(payload), ExclusiveKey: key}); err != nil {
			t.Fatal(err)
		}
		occ[canon]++
	}
	if err := n.Virt.DefineDomain(`<domain type='kvm'><name>` + vm + `</name><devices></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	return c, n
}

// pciStartRun has n's reconciler start vm, and returns its row.
func pciStartRun(t *testing.T, ctx context.Context, n *Node, vm string) *corrosion.VMRecord {
	t.Helper()
	pciFoStart(t, ctx, n)
	v, err := corrosion.GetVM(ctx, n.DB, vm)
	if err != nil || v == nil {
		t.Fatalf("read %s: %+v %v", vm, v, err)
	}
	return v
}

// pciStartCrash has vm's domain on n die and n's reconciler start it again.
func pciStartCrash(t *testing.T, ctx context.Context, n *Node, vm string) *corrosion.VMRecord {
	t.Helper()
	_ = n.Virt.DestroyDomain(vm)
	if err := corrosion.RescheduleVMHost(ctx, n.DB, vm, n.Name, "pending"); err != nil {
		t.Fatal(err)
	}
	return pciStartRun(t, ctx, n, vm)
}

var pciStartHostdevRE = regexp.MustCompile(`bus=["']0x([0-9a-f]{2})["'] slot=["']0x([0-9a-f]{2})["'] function=["']0x([0-7])["']`)

// pciStartHostdevs is every PCI hostdev source address in xml, as a BDF.
func pciStartHostdevs(xml string) []string {
	var out []string
	for _, m := range pciStartHostdevRE.FindAllStringSubmatch(xml, -1) {
		out = append(out, "0000:"+m[1]+":"+m[2]+"."+m[3])
	}
	sort.Strings(out)
	return out
}

// pciStartOwned is every device on n's host its inventory records vm as
// owning.
func pciStartOwned(t *testing.T, ctx context.Context, n *Node, vm string) []string {
	t.Helper()
	devs, err := corrosion.ListPCIDevices(ctx, n.DB, n.Name, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range devs {
		if d.VMName == vm {
			out = append(out, d.Address)
		}
	}
	sort.Strings(out)
	return out
}

// pciStartRealized is every address a live realization of vm records.
func pciStartRealized(t *testing.T, ctx context.Context, n *Node, vm string) []string {
	t.Helper()
	reals, err := corrosion.ListVMPCIRealizations(ctx, n.DB, vm)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range reals {
		out = append(out, r.ResolvedAddress)
	}
	sort.Strings(out)
	return out
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A VM whose GPU is a type selector is restarted after a guest crash on the
// host where it owns its GPU. It runs with that GPU; a spare GPU of its type
// stays free, and the VM owns exactly the devices it has. With two intents
// of the type it keeps its two.
func TestFleet_PCIStart_TypeSelectorRestartKeepsItsDevice(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	gpu := &pb.DeviceSpec{Type: "gpu", Vendor: "10de"}
	for _, tc := range []struct {
		name  string
		devs  []*pb.DeviceSpec
		inv   []pciStartDev
		owned []string // the devices the first start takes, and the restart keeps
	}{
		{"no spare", []*pb.DeviceSpec{gpu},
			[]pciStartDev{{"0000:81:00.0", "2330", "gpu", 50}},
			[]string{"0000:81:00.0"}},
		{"a spare", []*pb.DeviceSpec{gpu},
			[]pciStartDev{{"0000:81:00.0", "2330", "gpu", 50}, {"0000:82:00.0", "2330", "gpu", 51}},
			[]string{"0000:81:00.0"}},
		{"two intents and a spare", []*pb.DeviceSpec{gpu, gpu},
			[]pciStartDev{{"0000:81:00.0", "2330", "gpu", 50}, {"0000:82:00.0", "2330", "gpu", 51}, {"0000:83:00.0", "2330", "gpu", 52}},
			[]string{"0000:81:00.0", "0000:82:00.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, n := pciStartFleet(t, ctx, "tvm", tc.devs, tc.inv)
			if v := pciStartRun(t, ctx, n, "tvm"); v.State != "running" {
				t.Fatalf("setup: first start: %s %q", v.State, v.StateDetail)
			}
			if got := pciStartOwned(t, ctx, n, "tvm"); !eqStrings(got, tc.owned) {
				t.Fatalf("setup: after the first start tvm owns %v; want %v", got, tc.owned)
			}
			v := pciStartCrash(t, ctx, n, "tvm")
			if v.State != "running" {
				t.Fatalf("restart on the host where tvm owns its GPU refused: %s %q", v.State, v.StateDetail)
			}
			if got := pciStartOwned(t, ctx, n, "tvm"); !eqStrings(got, tc.owned) {
				t.Errorf("after the restart tvm owns %v; want %v (the devices it had, no spare)", got, tc.owned)
			}
			if got := pciStartHostdevs(n.Virt.DefinedXML("tvm")); !eqStrings(got, tc.owned) {
				t.Errorf("tvm restarted with hostdevs %v; want %v", got, tc.owned)
			}
			if got := pciStartRealized(t, ctx, n, "tvm"); !eqStrings(got, tc.owned) {
				t.Errorf("tvm's realizations after the restart are %v; want %v", got, tc.owned)
			}
		})
	}
}
