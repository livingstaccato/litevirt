package fleet

// A VM with a PCI passthrough device is recovered off a failed host only onto
// a host with a free device of the same kind (vendor and device id), and is
// started there with that device. A BDF names a slot on one host, never a
// device across hosts: the device at the same address on a survivor is
// whatever that host has there.
//
// Each scenario runs before the hardware_v2 latch (the reconciler rebuilds
// the domain from the spec, and the devices are claimed in the inventory as
// CreateVM claims them) and after it (the start preflight realizes the VM's
// intents).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/vfio"
)

const (
	pciFoVM  = "gpuvm"
	pciFoBDF = "0000:41:00.0" // the GPU's slot on the failed host
)

// pciFoDevice is one inventory row a scenario puts on a host.
type pciFoDevice struct {
	addr, vendor, device, name, typ string
}

var (
	h100 = pciFoDevice{vendor: "10de", device: "2330", name: "GH100 [H100 SXM5 80GB]", typ: "gpu"}
	l40s = pciFoDevice{vendor: "10de", device: "26b9", name: "AD102GL [L40S]", typ: "gpu"}
	nvme = pciFoDevice{vendor: "144d", device: "a808", name: "NVMe SSD Controller PM9A1", typ: "nvme"}
)

func (d pciFoDevice) at(addr string) pciFoDevice { d.addr = addr; return d }

// pciFoFleet seeds a three-node fleet in which the victim runs pciFoVM with
// the H100 at pciFoBDF, survivors a and b carry the devices given, and the
// victim is isolated. With latched, hardware_v2 is latched fleet-wide first.
func pciFoFleet(t *testing.T, clock *VirtualClock, latched bool, labels map[string]string, onA, onB []pciFoDevice) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	ctx := context.Background()
	disk := filepath.Join(t.TempDir(), pciFoVM+"-root.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return victimFleet(t, clock, func(c *Cluster, a, b, victim *Node) {
		put := func(host string, d pciFoDevice, owner string, group int) {
			t.Helper()
			if err := corrosion.UpsertPCIDevice(ctx, a.DB, corrosion.PCIDeviceRecord{
				HostName: host, Address: d.addr, VendorID: d.vendor, DeviceID: d.device,
				DeviceName: d.name, Type: d.typ, Driver: "vfio-pci", IOMMUGroup: group, VMName: owner,
			}); err != nil {
				t.Fatal(err)
			}
		}
		put(victim.Name, h100.at(pciFoBDF), pciFoVM, 40)
		for i, d := range onA {
			put(a.Name, d, "", 50+i)
		}
		for i, d := range onB {
			put(b.Name, d, "", 60+i)
		}
		dev := &pb.DeviceSpec{Address: pciFoBDF}
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: pciFoVM, HostName: victim.Name, State: "running",
			CPUActual: 1, MemActual: 256,
			Spec: vmSpecJSON(t, &pb.VMSpec{Name: pciFoVM, Cpu: 1, MemoryMib: 256, Labels: labels, Devices: []*pb.DeviceSpec{dev}})},
			nil, []corrosion.DiskRecord{{VMName: pciFoVM, DiskName: "root", HostName: victim.Name, Path: disk, StorageType: "nfs"}}); err != nil {
			t.Fatal(err)
		}
		if !latched {
			// The intent CreateVM writes beside the claim, whatever the latch.
			kind, key := corrosion.ClassifyPCISelector(dev)
			payload, err := protojson.Marshal(dev)
			if err != nil {
				t.Fatal(err)
			}
			if err := corrosion.UpsertPCIIntent(ctx, a.DB, corrosion.PCIIntentRecord{
				VMName: pciFoVM, DeviceID: corrosion.DeterministicPCIIntentID(corrosion.CanonicalPCISelector(dev), 0),
				HostName: victim.Name, SelectorKind: kind, SelectorPayload: string(payload), ExclusiveKey: key,
			}); err != nil {
				t.Fatal(err)
			}
			return
		}
		// The VM's domain on the victim passes the H100 through: the audit
		// adopts the VM from it and writes its intent.
		c.WaitConverged(t, convergeTimeout)
		if err := victim.Virt.DefineDomain(`<domain type='kvm'><name>` + pciFoVM + `</name><devices>` +
			`<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x0000' bus='0x41' slot='0x00' function='0x0'/></source></hostdev>` +
			`</devices></domain>`); err != nil {
			t.Fatal(err)
		}
		latchHardwareV2(t, c, gateAll(t, c))
		c.WaitConverged(t, convergeTimeout)
		intents, err := corrosion.ListVMPCIIntents(ctx, a.DB, pciFoVM)
		if err != nil || len(intents) != 1 || intents[0].SelectorKind != "address" {
			t.Fatalf("after the latch %s has intents %+v (%v); want its one address intent", pciFoVM, intents, err)
		}
	})
}

// pciFoFailOver runs the coordinator on the survivors until the victim is
// fenced, and returns the coordinators for later passes.
func pciFoFailOver(t *testing.T, ctx context.Context, c *Cluster, clock *VirtualClock, a, b *Node) *Coordinators {
	t.Helper()
	cs := c.NewCoordinators(clock)
	pciFoTick(t, ctx, c, cs, clock, a, b)
	if f := cs.Fences(); len(f) != 1 {
		t.Fatalf("fences = %+v; want the victim fenced once", f)
	}
	return cs
}

// pciFoTick runs three coordinator passes on a.
func pciFoTick(t *testing.T, ctx context.Context, c *Cluster, cs *Coordinators, clock *VirtualClock, a, b *Node) {
	t.Helper()
	for i := 0; i < 3; i++ {
		cs.Tick(ctx, a)
		c.WaitConverged(t, convergeTimeout, a, b)
		clock.Advance(contentionPoll)
	}
}

// pciFoStart runs n's reconciler once, wired as the daemon wires it.
func pciFoStart(t *testing.T, ctx context.Context, n *Node) {
	t.Helper()
	rec := health.NewReconciler(n.Name, t.TempDir(), n.DB, n.Virt)
	rec.SetHardwareStartPreparer(n.Server.PrepareHardwareForStart)
	rec.SetPassthroughForRebuild(n.Server.PassthroughForRebuild)
	rec.ReconcileOnce(ctx)
}

// pciFoOwner is the VM n's inventory records as owning addr on host.
func pciFoOwner(t *testing.T, ctx context.Context, n *Node, host, addr string) string {
	t.Helper()
	devs, err := corrosion.ListPCIDevices(ctx, n.DB, host, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		if d.Address == addr {
			return d.VMName
		}
	}
	t.Fatalf("%s has no device %s in its inventory", host, addr)
	return ""
}

// pciFoHostdevBuses is the source bus of every PCI hostdev in xml.
func pciFoHostdevBuses(xml string) []string {
	var buses []string
	for rest := xml; ; {
		i := strings.Index(rest, "<hostdev")
		if i < 0 {
			return buses
		}
		rest = rest[i:]
		end := strings.Index(rest, "</hostdev>")
		if end < 0 {
			return buses
		}
		el := rest[:end]
		if j := strings.Index(el, "bus="); j >= 0 && len(el) > j+10 {
			buses = append(buses, el[j+5:j+9])
		}
		rest = rest[end:]
	}
}

func pciFoRegimes(t *testing.T, run func(t *testing.T, latched bool)) {
	for _, tc := range []struct {
		name    string
		latched bool
	}{{"pre-latch", false}, {"post-latch", true}} {
		t.Run(tc.name, func(t *testing.T) { run(t, tc.latched) })
	}
}

// No survivor has a free device of the VM's kind: the VM is held on its
// failed host with a condition that says why and what to do, and is not
// started anywhere without its GPU.
func TestFleet_PCIFailover_NoMatchingDeviceHoldsTheVM(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		clock := NewVirtualClock(time.Now().UTC())
		c, a, b, victim := pciFoFleet(t, clock, latched, nil,
			[]pciFoDevice{l40s.at("0000:81:00.0")}, nil)
		cs := pciFoFailOver(t, ctx, c, clock, a, b)

		for _, n := range []*Node{a, b} {
			if vm := vmOn(t, n, pciFoVM); vm == nil || vm.HostName != victim.Name {
				t.Fatalf("%s: %s on %+v; no survivor has an H100, so it must stay on %s", n.Name, pciFoVM, vm, victim.Name)
			}
		}
		held, err := health.HeldForHostOf(ctx, a.DB, pciFoVM)
		if err != nil || held == nil {
			t.Fatalf("no vm_failover_held condition for %s (%v)", pciFoVM, err)
		}
		if !strings.Contains(held.Detail, "10de:2330") || !strings.Contains(held.Fix, "litevirt.failover_without_devices") {
			t.Errorf("the hold does not name the device it waits for or the opt-in that drops it:\ndetail: %s\nfix: %s", held.Detail, held.Fix)
		}
		for _, n := range []*Node{a, b} {
			pciFoStart(t, ctx, n)
			if n.Virt.DefinedXML(pciFoVM) != "" {
				t.Errorf("%s defined %s, held on %s", n.Name, pciFoVM, victim.Name)
			}
		}
		if o := pciFoOwner(t, ctx, a, a.Name, "0000:81:00.0"); o != "" {
			t.Errorf("the L40S on %s is owned by %q", a.Name, o)
		}

		// The remedy the hold names: an H100 free on a survivor. The next
		// pass recovers the VM there, and the hold is over.
		if err := corrosion.UpsertPCIDevice(ctx, a.DB, corrosion.PCIDeviceRecord{
			HostName: b.Name, Address: "0000:c1:00.0", VendorID: h100.vendor, DeviceID: h100.device,
			DeviceName: h100.name, Type: h100.typ, Driver: "vfio-pci", IOMMUGroup: 70,
		}); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout, a, b)
		pciFoTick(t, ctx, c, cs, clock, a, b)
		if vm := vmOn(t, a, pciFoVM); vm == nil || vm.HostName != b.Name {
			t.Fatalf("%s on %+v once %s has a free H100; want it recovered there", pciFoVM, vm, b.Name)
		}
		if held, err := health.HeldForHostOf(ctx, a.DB, pciFoVM); err != nil || held != nil {
			t.Errorf("%s was recovered, and its hold is still open: %+v (%v)", pciFoVM, held, err)
		}
	})
}

// One survivor has a free H100: the VM is recovered there and started with
// it. The other survivor's GPU at the VM's old address is a different model
// and is left alone.
func TestFleet_PCIFailover_LandsOnTheHostWithAMatchingDevice(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		clock := NewVirtualClock(time.Now().UTC())
		const there = "0000:81:00.0"
		c, a, b, victim := pciFoFleet(t, clock, latched, nil,
			[]pciFoDevice{l40s.at(pciFoBDF)}, []pciFoDevice{h100.at(there)})
		pciFoFailOver(t, ctx, c, clock, a, b)

		vm := vmOn(t, a, pciFoVM)
		if vm == nil || vm.HostName != b.Name {
			t.Fatalf("%s on %+v; want it recovered onto %s, the survivor with an H100", pciFoVM, vm, b.Name)
		}
		pciFoStart(t, ctx, b)
		if v := vmOn(t, b, pciFoVM); v == nil || v.State != "running" {
			t.Fatalf("%s did not start on %s: %+v", pciFoVM, b.Name, v)
		}
		if o := pciFoOwner(t, ctx, b, b.Name, there); o != pciFoVM {
			t.Errorf("the H100 at %s on %s is owned by %q, want %s", there, b.Name, o, pciFoVM)
		}
		if buses := pciFoHostdevBuses(b.Virt.DefinedXML(pciFoVM)); len(buses) != 1 || buses[0] != "0x81" {
			t.Errorf("%s's domain on %s passes through buses %v; want the H100 at %s alone:\n%s",
				pciFoVM, b.Name, buses, there, b.Virt.DefinedXML(pciFoVM))
		}
		c.WaitConverged(t, convergeTimeout, a, b)
		if o := pciFoOwner(t, ctx, a, a.Name, pciFoBDF); o != "" {
			t.Errorf("the L40S at %s on %s is owned by %q", pciFoBDF, a.Name, o)
		}
		_ = victim
	})
}

// The survivors have devices at the VM's old address, but of another kind.
// Placement does not take either. A start on a survivor that the VM was
// moved to anyway does not bind the device at that address either: the
// start is refused, the device stays free, and nothing is passed through.
func TestFleet_PCIFailover_SameBDFDifferentDeviceIsNotBound(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		clock := NewVirtualClock(time.Now().UTC())
		c, a, b, victim := pciFoFleet(t, clock, latched, nil,
			[]pciFoDevice{nvme.at(pciFoBDF)}, []pciFoDevice{l40s.at(pciFoBDF)})
		pciFoFailOver(t, ctx, c, clock, a, b)

		for _, n := range []*Node{a, b} {
			if vm := vmOn(t, n, pciFoVM); vm == nil || vm.HostName != victim.Name {
				t.Fatalf("%s: %s on %+v; the devices at %s on the survivors are not H100s, so it must stay on %s",
					n.Name, pciFoVM, vm, pciFoBDF, victim.Name)
			}
		}

		// Moved to b anyway, as a coordinator that ignores devices would.
		if err := corrosion.RescheduleVMHost(ctx, a.DB, pciFoVM, b.Name, "pending"); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout, a, b)
		pciFoStart(t, ctx, b)
		if v := vmOn(t, b, pciFoVM); v != nil && v.State == "running" {
			t.Errorf("%s reported running on %s, which has no H100", pciFoVM, b.Name)
		}
		if o := pciFoOwner(t, ctx, b, b.Name, pciFoBDF); o != "" {
			t.Errorf("the L40S at %s on %s was claimed by %q", pciFoBDF, b.Name, o)
		}
		if buses := pciFoHostdevBuses(b.Virt.DefinedXML(pciFoVM)); len(buses) != 0 {
			t.Errorf("%s's domain on %s passes through %v:\n%s", pciFoVM, b.Name, buses, b.Virt.DefinedXML(pciFoVM))
		}
		if st, _ := b.Virt.DomainState(pciFoVM); st == "running" {
			t.Errorf("%s's domain runs on %s", pciFoVM, b.Name)
		}
	})
}

// Its spec opts in to running without its devices: the VM is recovered onto a
// survivor that has none for it, started there without them, and its state
// detail says so.
func TestFleet_PCIFailover_OptInRecoversWithoutDevices(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		clock := NewVirtualClock(time.Now().UTC())
		c, a, b, victim := pciFoFleet(t, clock, latched, map[string]string{corrosion.LabelFailoverWithoutDevices: "true"},
			[]pciFoDevice{l40s.at(pciFoBDF)}, []pciFoDevice{nvme.at(pciFoBDF)})
		pciFoFailOver(t, ctx, c, clock, a, b)

		vm := vmOn(t, a, pciFoVM)
		if vm == nil || vm.HostName == victim.Name {
			t.Fatalf("%s on %+v; its spec opts in to recovery without its devices", pciFoVM, vm)
		}
		if held, err := health.HeldForHostOf(ctx, a.DB, pciFoVM); err != nil || held != nil {
			t.Errorf("an opted-in VM is held: %+v (%v)", held, err)
		}
		n := c.Node(vm.HostName)
		pciFoStart(t, ctx, n)
		v := vmOn(t, n, pciFoVM)
		if v == nil || v.State != "running" {
			t.Fatalf("%s did not start on %s: %+v", pciFoVM, n.Name, v)
		}
		if !strings.Contains(v.StateDetail, "running without its PCI passthrough devices") {
			t.Errorf("%s runs on %s without its H100 and its state detail does not say so: %q", pciFoVM, n.Name, v.StateDetail)
		}
		if buses := pciFoHostdevBuses(n.Virt.DefinedXML(pciFoVM)); len(buses) != 0 {
			t.Errorf("%s's domain on %s passes through %v", pciFoVM, n.Name, buses)
		}
		if o := pciFoOwner(t, ctx, n, n.Name, pciFoBDF); o != "" {
			t.Errorf("the device at %s on %s was claimed by %q", pciFoBDF, n.Name, o)
		}
	})
}
