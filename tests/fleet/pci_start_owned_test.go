package fleet

// After the hardware_v2 latch, a VM's start realizes its PCI intents on its
// host. A VM that already owns the device realizing an intent there keeps
// it: a restart neither looks for a free one nor claims a second.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
	"time"

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

// A GPU and its audio function share an IOMMU group, and the VM names both
// by address. It starts on its host with each function passed through once,
// and restarts after a guest crash the same way.
func TestFleet_PCIStart_GPUAndItsAudioFunctionByAddress(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	ctx := context.Background()
	pair := []string{"0000:81:00.0", "0000:81:00.1"}
	_, n := pciStartFleet(t, ctx, "avm",
		[]*pb.DeviceSpec{{Address: pair[0]}, {Address: pair[1]}},
		[]pciStartDev{{pair[0], "2330", "gpu", 50}, {pair[1], "22a3", "audio", 50}})
	for _, step := range []string{"start", "restart"} {
		var v *corrosion.VMRecord
		if step == "start" {
			v = pciStartRun(t, ctx, n, "avm")
		} else {
			v = pciStartCrash(t, ctx, n, "avm")
		}
		if v.State != "running" {
			t.Fatalf("%s of avm refused: %s %q", step, v.State, v.StateDetail)
		}
		if got := pciStartHostdevs(n.Virt.DefinedXML("avm")); !eqStrings(got, pair) {
			t.Errorf("%s: avm has hostdevs %v; want %v, each once", step, got, pair)
		}
		if got := pciStartOwned(t, ctx, n, "avm"); !eqStrings(got, pair) {
			t.Errorf("%s: avm owns %v; want %v", step, got, pair)
		}
		if got := pciStartRealized(t, ctx, n, "avm"); !eqStrings(got, pair) {
			t.Errorf("%s: avm's realizations are %v; want %v, each once", step, got, pair)
		}
	}
}

// The same VM fails over onto b, which has the same pair in one IOMMU group:
// it starts there with b's GPU and b's audio function, each once.
func TestFleet_PCIFailover_GPUAndItsAudioFunction(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	audio := pciFoDevice{vendor: "10de", device: "22a3", name: "GH100 HD Audio", typ: "audio"}
	pair := []string{"0000:81:00.0", "0000:81:00.1"}
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		clock := NewVirtualClock(time.Now().UTC())
		c, a, b, victim := pciFoFleetWith(t, clock, pciFoSetup{latched: latched,
			victimDevs: []pciFoDevice{h100.at(pciFoBDF), audio.at("0000:41:00.1")},
			onB:        []pciFoDevice{h100.at(pair[0]), audio.at(pair[1])}})
		// One IOMMU group per pair, as the hardware has it.
		for _, r := range []struct {
			host, addr, owner string
			group             int
		}{{victim.Name, "0000:41:00.1", pciFoVM, 40}, {b.Name, pair[1], "", 60}} {
			if err := corrosion.UpsertPCIDevice(ctx, a.DB, corrosion.PCIDeviceRecord{HostName: r.host, Address: r.addr,
				VendorID: audio.vendor, DeviceID: audio.device, DeviceName: audio.name, Type: audio.typ, Driver: "vfio-pci",
				IOMMUGroup: r.group, VMName: r.owner}); err != nil {
				t.Fatal(err)
			}
		}
		c.WaitConverged(t, convergeTimeout, a, b)
		pciFoFailOver(t, ctx, c, clock, a, b)
		if vm := vmOn(t, a, pciFoVM); vm == nil || vm.HostName != b.Name {
			t.Fatalf("%s on %+v; want it on %s", pciFoVM, vm, b.Name)
		}
		pciFoStart(t, ctx, b)
		v := vmOn(t, b, pciFoVM)
		if v == nil || v.State != "running" {
			t.Fatalf("%s did not start on %s: %+v", pciFoVM, b.Name, v)
		}
		if got := pciStartHostdevs(b.Virt.DefinedXML(pciFoVM)); !eqStrings(got, pair) {
			t.Errorf("%s on %s has hostdevs %v; want %v, each once", pciFoVM, b.Name, got, pair)
		}
		for _, addr := range pair {
			if o := pciFoOwner(t, ctx, b, b.Name, addr); o != pciFoVM {
				t.Errorf("%s on %s is owned by %q; want %s", addr, b.Name, o, pciFoVM)
			}
		}
	})
}

// The VM names only its GPU by address, so its first start realizes the
// audio function as the GPU's group sibling. Its audio function is then
// named by address too. A crash restart runs it with each function once,
// and each intent's realization holds only its own device.
func TestFleet_PCIStart_NamingTheSiblingLaterKeepsItRestartable(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	ctx := context.Background()
	pair := []string{"0000:81:00.0", "0000:81:00.1"}
	_, n := pciStartFleet(t, ctx, "svm",
		[]*pb.DeviceSpec{{Address: pair[0]}},
		[]pciStartDev{{pair[0], "2330", "gpu", 50}, {pair[1], "22a3", "audio", 50}})
	if v := pciStartRun(t, ctx, n, "svm"); v.State != "running" {
		t.Fatalf("setup: first start: %s %q", v.State, v.StateDetail)
	}
	if got := pciStartRealized(t, ctx, n, "svm"); !eqStrings(got, pair) {
		t.Fatalf("setup: realized %v after the first start; want %v (the audio function as the GPU's sibling)", got, pair)
	}
	audio := &pb.DeviceSpec{Address: pair[1]}
	kind, key := corrosion.ClassifyPCISelector(audio)
	payload, err := protojson.Marshal(audio)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertPCIIntent(ctx, n.DB, corrosion.PCIIntentRecord{VMName: "svm",
		DeviceID: corrosion.DeterministicPCIIntentID(corrosion.CanonicalPCISelector(audio), 0), HostName: n.Name,
		SelectorKind: kind, SelectorPayload: string(payload), ExclusiveKey: key}); err != nil {
		t.Fatal(err)
	}
	v := pciStartCrash(t, ctx, n, "svm")
	if v.State != "running" {
		t.Fatalf("crash restart after naming the audio function refused: %s %q", v.State, v.StateDetail)
	}
	if got := pciStartHostdevs(n.Virt.DefinedXML("svm")); !eqStrings(got, pair) {
		t.Errorf("svm has hostdevs %v; want %v, each once", got, pair)
	}
	if got := pciStartRealized(t, ctx, n, "svm"); !eqStrings(got, pair) {
		t.Errorf("svm's realizations are %v; want %v, each once", got, pair)
	}
}

// The VM's GPU on the failed host shares its IOMMU group with an audio
// function, realized as the GPU's sibling. b has an H100 alone in its group.
// After the failover the VM starts on b with that H100, and its realization
// is the H100 alone: the failed host's sibling row does not refuse it.
func TestFleet_PCIFailover_SiblingRealizedOnTheOldHostDoesNotRefuseTheStart(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := pciFoFleetWith(t, clock, pciFoSetup{latched: true, onB: []pciFoDevice{h100.at(pciFoThere)}})
	if err := corrosion.UpsertPCIDevice(ctx, a.DB, corrosion.PCIDeviceRecord{HostName: victim.Name, Address: "0000:41:00.1",
		VendorID: "10de", DeviceID: "22a3", DeviceName: "GH100 HD Audio", Type: "audio", Driver: "vfio-pci", IOMMUGroup: 40, VMName: pciFoVM}); err != nil {
		t.Fatal(err)
	}
	intents, err := corrosion.ListVMPCIIntents(ctx, a.DB, pciFoVM)
	if err != nil || len(intents) != 1 {
		t.Fatalf("setup: intents %+v (%v); want one", intents, err)
	}
	for i, addr := range []string{pciFoBDF, "0000:41:00.1"} {
		if err := corrosion.UpsertPCIRealization(ctx, a.DB, corrosion.PCIRealizationRecord{VMName: pciFoVM, DeviceID: intents[0].DeviceID,
			MemberID: fmt.Sprintf("m%d", i), HostName: victim.Name, ResolvedAddress: addr, Ordinal: i}); err != nil {
			t.Fatal(err)
		}
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	pciFoFailOver(t, ctx, c, clock, a, b)
	pciFoStart(t, ctx, b)
	v := vmOn(t, b, pciFoVM)
	if v == nil || v.State != "running" || v.HostName != b.Name {
		t.Fatalf("%s did not start on %s: %+v", pciFoVM, b.Name, v)
	}
	if got := pciStartRealized(t, ctx, b, pciFoVM); !eqStrings(got, []string{pciFoThere}) {
		t.Errorf("%s's realizations on %s are %v; want [%s]", pciFoVM, b.Name, got, pciFoThere)
	}
}

// A type-selector VM's crash restart fails once in StartDomain (a transient
// qemu failure). The VM keeps owning its GPU, and the row that says it
// realizes its intent stays: the next restart runs it with that GPU, does
// not need a free one, and does not take a spare beside it.
func TestFleet_PCIStart_AFailedRestartKeepsTheDeviceRealized(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	owned := []string{"0000:81:00.0"}
	for _, tc := range []struct {
		name string
		inv  []pciStartDev
	}{
		{"no spare", []pciStartDev{{"0000:81:00.0", "2330", "gpu", 50}}},
		{"a spare", []pciStartDev{{"0000:81:00.0", "2330", "gpu", 50}, {"0000:82:00.0", "2330", "gpu", 51}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, n := pciStartFleet(t, ctx, "tvm", []*pb.DeviceSpec{{Type: "gpu"}}, tc.inv)
			if v := pciStartRun(t, ctx, n, "tvm"); v.State != "running" {
				t.Fatalf("setup: first start: %s %q", v.State, v.StateDetail)
			}
			fails := 1
			n.Virt.FailStartDomain = func(string) error {
				if fails > 0 {
					fails--
					return errors.New("qemu: transient start failure")
				}
				return nil
			}
			if v := pciStartCrash(t, ctx, n, "tvm"); v.State == "running" {
				t.Fatalf("setup: the restart was meant to fail in StartDomain")
			}
			if got := pciStartOwned(t, ctx, n, "tvm"); !eqStrings(got, owned) {
				t.Errorf("after the failed restart tvm owns %v; want %v", got, owned)
			}
			if got := pciStartRealized(t, ctx, n, "tvm"); !eqStrings(got, owned) {
				t.Errorf("after the failed restart tvm's realizations are %v; want %v", got, owned)
			}
			v := pciStartCrash(t, ctx, n, "tvm")
			if v.State != "running" {
				t.Fatalf("the next restart refused: %s %q", v.State, v.StateDetail)
			}
			if got := pciStartOwned(t, ctx, n, "tvm"); !eqStrings(got, owned) {
				t.Errorf("after the next restart tvm owns %v; want %v (no spare beside it)", got, owned)
			}
			if got := pciStartHostdevs(n.Virt.DefinedXML("tvm")); !eqStrings(got, owned) {
				t.Errorf("tvm runs with hostdevs %v; want %v", got, owned)
			}
		})
	}
}

// A VM's selectors mix an address, a type or a mapping over one IOMMU group
// {GPU, audio}. It starts with each function passed through once, whatever
// order its intents are read in.
func TestFleet_PCIStart_MixedSelectorsInOneGroup(t *testing.T) {
	pair := []string{"0000:81:00.0", "0000:81:00.1"}
	for _, tc := range []struct {
		name string
		devs []*pb.DeviceSpec
	}{
		{"addr audio + type gpu", []*pb.DeviceSpec{{Address: pair[1]}, {Type: "gpu"}}},
		{"type gpu + addr audio", []*pb.DeviceSpec{{Type: "gpu"}, {Address: pair[1]}}},
		{"addr gpu + map audio", []*pb.DeviceSpec{{Address: pair[0]}, {Mapping: "aud"}}},
		{"type gpu + map audio", []*pb.DeviceSpec{{Type: "gpu"}, {Mapping: "aud"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer vfio.SetFS(vfioBoundSysfs{})()
			ctx := context.Background()
			_, n := pciStartFleet(t, ctx, "mvm", tc.devs,
				[]pciStartDev{{pair[0], "2330", "gpu", 50}, {pair[1], "22a3", "audio", 50}})
			if err := corrosion.CreateResourceMapping(ctx, n.DB, "aud", ""); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.AddMappingDevice(ctx, n.DB, "aud", n.Name, pair[1], "10de", "22a3"); err != nil {
				t.Fatal(err)
			}
			if v := pciStartRun(t, ctx, n, "mvm"); v.State != "running" {
				t.Fatalf("start refused: %s %q", v.State, v.StateDetail)
			}
			if got := pciStartHostdevs(n.Virt.DefinedXML("mvm")); !eqStrings(got, pair) {
				t.Errorf("mvm has hostdevs %v; want %v, each once", got, pair)
			}
		})
	}
}

// The VM's GPU gains a group sibling between starts (a rescan finds its audio
// function). The restart claims the audio function beside the GPU it owns,
// and StartDomain fails once: the audio function is given back, and the GPU
// stays owned and realized, so the next restart runs with both.
func TestFleet_PCIStart_AFailedRestartGivesBackOnlyWhatItClaimed(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	ctx := context.Background()
	gpu, aud := "0000:81:00.0", "0000:81:00.1"
	_, n := pciStartFleet(t, ctx, "tvm", []*pb.DeviceSpec{{Type: "gpu"}}, []pciStartDev{{gpu, "2330", "gpu", 50}})
	if v := pciStartRun(t, ctx, n, "tvm"); v.State != "running" {
		t.Fatalf("setup: first start: %s %q", v.State, v.StateDetail)
	}
	if err := corrosion.UpsertPCIDevice(ctx, n.DB, corrosion.PCIDeviceRecord{HostName: n.Name, Address: aud,
		VendorID: "10de", DeviceID: "22a3", DeviceName: "audio", Type: "audio", Driver: "vfio-pci", IOMMUGroup: 50}); err != nil {
		t.Fatal(err)
	}
	fails := 1
	n.Virt.FailStartDomain = func(string) error {
		if fails > 0 {
			fails--
			return errors.New("qemu: transient start failure")
		}
		return nil
	}
	if v := pciStartCrash(t, ctx, n, "tvm"); v.State == "running" {
		t.Fatalf("setup: the restart was meant to fail in StartDomain")
	}
	if got := pciStartOwned(t, ctx, n, "tvm"); !eqStrings(got, []string{gpu}) {
		t.Errorf("after the failed restart tvm owns %v; want [%s]", got, gpu)
	}
	if got := pciStartRealized(t, ctx, n, "tvm"); !eqStrings(got, []string{gpu}) {
		t.Errorf("after the failed restart tvm's realizations are %v; want [%s]", got, gpu)
	}
	v := pciStartCrash(t, ctx, n, "tvm")
	if v.State != "running" {
		t.Fatalf("the next restart refused: %s %q", v.State, v.StateDetail)
	}
	if got := pciStartHostdevs(n.Virt.DefinedXML("tvm")); !eqStrings(got, []string{gpu, aud}) {
		t.Errorf("tvm runs with hostdevs %v; want [%s %s]", got, gpu, aud)
	}
}
