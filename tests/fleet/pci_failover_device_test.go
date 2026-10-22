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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/placement"
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
	return pciFoFleetWith(t, clock, pciFoSetup{latched: latched, labels: labels, onA: onA, onB: onB})
}

// pciFoSetup is a pciFoFleet scenario. victimDevs (default: the H100 at
// pciFoBDF) are the VM's devices on the victim; devs (default: each of them
// by address) its spec's selectors.
type pciFoSetup struct {
	latched    bool
	labels     map[string]string
	onA, onB   []pciFoDevice
	victimDevs []pciFoDevice
	devs       []*pb.DeviceSpec
}

func pciFoFleetWith(t *testing.T, clock *VirtualClock, o pciFoSetup) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	ctx := context.Background()
	if len(o.victimDevs) == 0 {
		o.victimDevs = []pciFoDevice{h100.at(pciFoBDF)}
	}
	if len(o.devs) == 0 {
		for _, d := range o.victimDevs {
			o.devs = append(o.devs, &pb.DeviceSpec{Address: d.addr})
		}
	}
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
		hostdevs := ""
		for i, d := range o.victimDevs {
			put(victim.Name, d, pciFoVM, 40+i)
			bus, slot, fn := d.addr[5:7], d.addr[8:10], d.addr[11:12]
			hostdevs += `<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x0000' bus='0x` + bus +
				`' slot='0x` + slot + `' function='0x` + fn + `'/></source></hostdev>`
		}
		for i, d := range o.onA {
			put(a.Name, d, "", 50+i)
		}
		for i, d := range o.onB {
			put(b.Name, d, "", 60+i)
		}
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: pciFoVM, HostName: victim.Name, State: "running",
			CPUActual: 1, MemActual: 256,
			Spec: vmSpecJSON(t, &pb.VMSpec{Name: pciFoVM, Cpu: 1, MemoryMib: 256, Labels: o.labels, Devices: o.devs})},
			nil, []corrosion.DiskRecord{{VMName: pciFoVM, DiskName: "root", HostName: victim.Name, Path: disk, StorageType: "nfs"}}); err != nil {
			t.Fatal(err)
		}
		if !o.latched {
			// The intents CreateVM writes beside the claim, whatever the latch.
			occ := map[string]int{}
			for _, dev := range o.devs {
				kind, key := corrosion.ClassifyPCISelector(dev)
				payload, err := protojson.Marshal(dev)
				if err != nil {
					t.Fatal(err)
				}
				canon := corrosion.CanonicalPCISelector(dev)
				if err := corrosion.UpsertPCIIntent(ctx, a.DB, corrosion.PCIIntentRecord{
					VMName: pciFoVM, DeviceID: corrosion.DeterministicPCIIntentID(canon, occ[canon]),
					HostName: victim.Name, SelectorKind: kind, SelectorPayload: string(payload), ExclusiveKey: key,
				}); err != nil {
					t.Fatal(err)
				}
				occ[canon]++
			}
			return
		}
		// The VM's domain on the victim passes its devices through: the
		// audit adopts the VM from it and writes its intents.
		c.WaitConverged(t, convergeTimeout)
		if err := victim.Virt.DefineDomain(`<domain type='kvm'><name>` + pciFoVM + `</name><devices>` + hostdevs + `</devices></domain>`); err != nil {
			t.Fatal(err)
		}
		latchHardwareV2(t, c, gateAll(t, c))
		c.WaitConverged(t, convergeTimeout)
		intents, err := corrosion.ListVMPCIIntents(ctx, a.DB, pciFoVM)
		if err != nil || len(intents) != len(o.devs) {
			t.Fatalf("after the latch %s has intents %+v (%v); want %d", pciFoVM, intents, err, len(o.devs))
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
		pciFoDropRecorded(t, ctx, n)
	})
}

// pciFoDropRecorded checks that n recorded pciFoVM's start without its
// devices: a vm.passthrough_dropped event and an audit row of the drop.
func pciFoDropRecorded(t *testing.T, ctx context.Context, n *Node) {
	t.Helper()
	evs, err := corrosion.ListVMEvents(ctx, n.DB, pciFoVM, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	ev := false
	for _, e := range evs {
		ev = ev || e.Type == "vm.passthrough_dropped"
	}
	if !ev {
		t.Errorf("no vm.passthrough_dropped event for %s on %s: %+v", pciFoVM, n.Name, evs)
	}
	rows, err := n.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'vm.passthrough_dropped' AND target = ?`, pciFoVM)
	if err != nil || len(rows) == 0 {
		t.Errorf("no vm.passthrough_dropped audit row for %s on %s (%v)", pciFoVM, n.Name, err)
	}
}

// pciFoLanded fails the VM over onto b, which has the H100 at pciFoThere,
// and starts it there.
const pciFoThere = "0000:81:00.0"

func pciFoLanded(t *testing.T, ctx context.Context, latched bool) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim = pciFoFleet(t, clock, latched, nil, nil, []pciFoDevice{h100.at(pciFoThere)})
	pciFoFailOver(t, ctx, c, clock, a, b)
	pciFoStart(t, ctx, b)
	if v := vmOn(t, b, pciFoVM); v == nil || v.State != "running" || v.HostName != b.Name {
		t.Fatalf("setup: %s did not start on %s: %+v", pciFoVM, b.Name, v)
	}
	return c, a, b, victim
}

// pciFoRestart has pciFoVM's domain on n die and n's reconciler start it
// again, as after a guest crash.
func pciFoRestart(t *testing.T, ctx context.Context, c *Cluster, a, n *Node) *corrosion.VMRecord {
	t.Helper()
	_ = n.Virt.DestroyDomain(pciFoVM)
	if err := corrosion.RescheduleVMHost(ctx, a.DB, pciFoVM, n.Name, "pending"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout, a, n)
	pciFoStart(t, ctx, n)
	return vmOn(t, n, pciFoVM)
}

// After a failover onto b the failed host's GPU leaves its inventory (it was
// the bad part, pulled in the repair). A restart on b, which owns an H100,
// is not refused: the device that realizes the VM's intent on b says what
// kind it needs, not the row it was first recorded on.
func TestFleet_PCIFailover_RestartAfterOriginInventoryGone(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		c, a, b, victim := pciFoLanded(t, ctx, latched)
		if err := corrosion.SoftDeletePCIDevice(ctx, a.DB, victim.Name, pciFoBDF); err != nil {
			t.Fatal(err)
		}
		if v := pciFoRestart(t, ctx, c, a, b); v == nil || v.State != "running" {
			t.Fatalf("restart on %s refused although it owns an H100 there: %+v", b.Name, v)
		}
		if buses := pciFoHostdevBuses(b.Virt.DefinedXML(pciFoVM)); len(buses) != 1 || buses[0] != "0x81" {
			t.Errorf("%s restarted on %s with buses %v, want the H100 at %s", pciFoVM, b.Name, buses, pciFoThere)
		}
	})
}

// After a failover onto b the failed host comes back with another card in
// the GPU's slot, and its rescan rewrites the row (still recording the VM as
// its owner). The kind the VM needs does not follow the row: a restart on b
// takes b's H100 again.
func TestFleet_PCIFailover_RescannedOriginDoesNotChangeTheKind(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		c, a, b, victim := pciFoLanded(t, ctx, latched)
		if err := corrosion.ObservePCIDevice(ctx, a.DB, corrosion.PCIDeviceRecord{
			HostName: victim.Name, Address: pciFoBDF, VendorID: l40s.vendor, DeviceID: l40s.device,
			DeviceName: l40s.name, Type: l40s.typ, Driver: "vfio-pci", IOMMUGroup: 40,
		}); err != nil {
			t.Fatal(err)
		}
		// What a further failover would need of a host: an H100 still.
		c.WaitConverged(t, convergeTimeout, a, b)
		if vm := vmOn(t, a, pciFoVM); vm != nil {
			reqs, descs, err := placement.FailoverDeviceRequests(ctx, a.DB, *vm)
			if err != nil || len(reqs) != 1 || reqs[0].Vendor != h100.vendor || reqs[0].DeviceID != h100.device {
				t.Errorf("a failover of %s off %s would need %+v (%v, %v); want an H100", pciFoVM, b.Name, reqs, descs, err)
			}
		}
		// b has a free L40S too: a kind read from the rewritten row would take it.
		if err := corrosion.UpsertPCIDevice(ctx, a.DB, corrosion.PCIDeviceRecord{
			HostName: b.Name, Address: "0000:c1:00.0", VendorID: l40s.vendor, DeviceID: l40s.device,
			DeviceName: l40s.name, Type: l40s.typ, Driver: "vfio-pci", IOMMUGroup: 71,
		}); err != nil {
			t.Fatal(err)
		}
		if v := pciFoRestart(t, ctx, c, a, b); v == nil || v.State != "running" {
			t.Fatalf("restart on %s refused although it owns an H100 there: %+v", b.Name, v)
		}
		if buses := pciFoHostdevBuses(b.Virt.DefinedXML(pciFoVM)); len(buses) != 1 || buses[0] != "0x81" {
			t.Errorf("%s restarted on %s with buses %v, want the H100 at %s alone", pciFoVM, b.Name, buses, pciFoThere)
		}
		if o := pciFoOwner(t, ctx, b, b.Name, "0000:c1:00.0"); o != "" {
			t.Errorf("the L40S on %s was claimed by %q", b.Name, o)
		}
	})
}

// Two devices of one kind, named by address: each takes its own device on
// the new host.
func TestFleet_PCIFailover_TwoDevicesOfOneKindTakeTwoDevices(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		clock := NewVirtualClock(time.Now().UTC())
		c, a, b, _ := pciFoFleetWith(t, clock, pciFoSetup{latched: latched,
			victimDevs: []pciFoDevice{h100.at(pciFoBDF), h100.at("0000:42:00.0")},
			onB:        []pciFoDevice{h100.at("0000:81:00.0"), h100.at("0000:82:00.0")}})
		pciFoFailOver(t, ctx, c, clock, a, b)
		if vm := vmOn(t, a, pciFoVM); vm == nil || vm.HostName != b.Name {
			t.Fatalf("%s on %+v; want it on %s, which has two H100s", pciFoVM, vm, b.Name)
		}
		pciFoStart(t, ctx, b)
		if v := vmOn(t, b, pciFoVM); v == nil || v.State != "running" {
			t.Fatalf("%s did not start on %s: %+v", pciFoVM, b.Name, v)
		}
		buses := pciFoHostdevBuses(b.Virt.DefinedXML(pciFoVM))
		if len(buses) != 2 || buses[0] == buses[1] {
			t.Errorf("%s on %s passes through buses %v, want both H100s once each:\n%s", pciFoVM, b.Name, buses, b.Virt.DefinedXML(pciFoVM))
		}
		for _, addr := range []string{"0000:81:00.0", "0000:82:00.0"} {
			if o := pciFoOwner(t, ctx, b, b.Name, addr); o != pciFoVM {
				t.Errorf("%s on %s is owned by %q, want %s", addr, b.Name, o, pciFoVM)
			}
		}
	})
}

// A start on the new host that fails gives back the device claimed for it.
func TestFleet_PCIFailover_FailedStartGivesTheDeviceBack(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		clock := NewVirtualClock(time.Now().UTC())
		c, a, b, _ := pciFoFleet(t, clock, latched, nil, nil, []pciFoDevice{h100.at(pciFoThere)})
		pciFoFailOver(t, ctx, c, clock, a, b)
		b.Virt.FailStartDomain = func(string) error { return errors.New("qemu: injected start failure") }
		pciFoStart(t, ctx, b)
		if v := vmOn(t, b, pciFoVM); v != nil && v.State == "running" {
			t.Fatalf("%s running on %s although its start failed", pciFoVM, b.Name)
		}
		if o := pciFoOwner(t, ctx, b, b.Name, pciFoThere); o != "" {
			t.Errorf("the H100 on %s is still owned by %q after the start failed", b.Name, o)
		}
	})
}

// The device the VM owns on its host has vanished from the inventory: the
// VM is not rebuilt there without it.
func TestFleet_PCIFailover_VanishedOwnedDeviceRefusesTheRestart(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		c, a, b, _ := pciFoLanded(t, ctx, latched)
		// As b's own rescan would, the device being gone from its bus.
		if err := corrosion.SoftDeletePCIDevice(ctx, b.DB, b.Name, pciFoThere); err != nil {
			t.Fatal(err)
		}
		v := pciFoRestart(t, ctx, c, a, b)
		if v != nil && v.State == "running" {
			t.Fatalf("%s restarted on %s without the H100 it owns there, which vanished", pciFoVM, b.Name)
		}
		if !latched && (v == nil || !strings.Contains(v.StateDetail, "vanished")) {
			t.Errorf("%s's state detail does not say its device vanished: %+v", pciFoVM, v)
		}
	})
}

// A stopped GPU VM on shared storage is moved, still stopped, onto a survivor
// with an H100 (before the latch); its definition there is built from its
// spec. `lv start` there passes the survivor's H100 through, or refuses when
// what it needs cannot be told (a spec device with no intent naming the host
// it was recorded on), unless the spec opts in to starting without it. It
// never boots the VM silently without its GPU.
func TestFleet_PCIFailover_StartOfAMovedStoppedVMGivesItItsDevice(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	optOut := `,"labels":{"` + corrosion.LabelFailoverWithoutDevices + `":"true"}`
	for _, tc := range []struct {
		name         string
		intent       bool
		labels       string
		failStart    bool
		failReadBack bool
	}{
		{"with its intent", true, "", false, false},
		{"with its intent, start fails", true, "", true, false},
		{"spec device only", false, "", false, false},
		{"opted out", false, optOut, false, false},
		// The domain starts and the read of the VM after it fails: the
		// start still counts, and the drop is still recorded.
		{"opted out, read-back fails", false, optOut, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 3, SharedCRDT: true})
			ctx := context.Background()
			a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			sharedDiskVM(t, c, a, "sg", victim.Name, "stopped", "operator-stop")
			if _, _, err := corrosion.MutateDesiredSpec(ctx, a.DB, "sg", func(string) (string, error) {
				return `{"name":"sg","cpu":1,"memory_mib":256,"on_host_failure":"restart-any","devices":[{"address":"0000:41:00.0"}]` + tc.labels + `}`, nil
			}); err != nil {
				t.Fatal(err)
			}
			put := func(host, addr string, grp int) {
				if err := corrosion.UpsertPCIDevice(ctx, a.DB, corrosion.PCIDeviceRecord{
					HostName: host, Address: addr, VendorID: h100.vendor, DeviceID: h100.device,
					DeviceName: h100.name, Type: "gpu", Driver: "vfio-pci", IOMMUGroup: grp,
				}); err != nil {
					t.Fatal(err)
				}
			}
			put(victim.Name, "0000:41:00.0", 40) // released when the VM stopped
			put(a.Name, "0000:81:00.0", 50)
			put(b.Name, "0000:81:00.0", 60)
			if tc.intent {
				dev := &pb.DeviceSpec{Address: "0000:41:00.0"}
				kind, key := corrosion.ClassifyPCISelector(dev)
				payload, _ := protojson.Marshal(dev)
				if err := corrosion.UpsertPCIIntent(ctx, a.DB, corrosion.PCIIntentRecord{
					VMName: "sg", DeviceID: corrosion.DeterministicPCIIntentID(corrosion.CanonicalPCISelector(dev), 0),
					HostName: victim.Name, SelectorKind: kind, SelectorPayload: string(payload), ExclusiveKey: key,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if got := fenceVictim(t, c, a, victim, a, b); got != 1 {
				t.Fatalf("fencer fired %d times", got)
			}
			vm, _ := corrosion.GetVM(ctx, a.DB, "sg")
			if vm == nil || vm.HostName == victim.Name || vm.State != "stopped" {
				t.Fatalf("sg was not moved off %s still stopped: %+v", victim.Name, vm)
			}
			dest := c.Node(vm.HostName)
			reconcileAll(t, c, a, b)
			if x := dest.Virt.DefinedXML("sg"); x == "" || len(pciFoHostdevBuses(x)) != 0 {
				t.Fatalf("setup: sg's definition on %s is not the device-less one a re-key defines:\n%s", dest.Name, x)
			}

			if tc.failStart {
				dest.Virt.FailStartDomain = func(string) error { return errors.New("qemu: injected start failure") }
			}
			if tc.failReadBack {
				dest.Server.FailVMReadBackForTests(func(string) error { return errors.New("corrosion: injected read failure") })
				defer dest.Server.FailVMReadBackForTests(nil)
			}
			_, err := c.SelfClient(dest).StartVM(ctx, &pb.StartVMRequest{Name: "sg"})
			st, _ := dest.Virt.DomainState("sg")
			buses := pciFoHostdevBuses(dest.Virt.DefinedXML("sg"))
			owner := ""
			if devs, lerr := corrosion.ListPCIDevices(ctx, dest.DB, dest.Name, ""); lerr == nil {
				for _, d := range devs {
					if d.Address == "0000:81:00.0" {
						owner = d.VMName
					}
				}
			}
			switch {
			case tc.failStart:
				// What the start claimed is given back, and the definition
				// is as it was: a later start does not boot devices the
				// inventory says are free.
				if err == nil || st == "running" || len(buses) != 0 || owner != "" {
					t.Errorf("failed lv start on %s: err=%v state=%s buses=%v owner=%q; want an error, the H100 free and no hostdev left defined",
						dest.Name, err, st, buses, owner)
				}
			case tc.intent:
				if err != nil || st != "running" || len(buses) != 1 || buses[0] != "0x81" || owner != "sg" {
					t.Errorf("lv start on %s: err=%v state=%s buses=%v owner=%q; want sg running with the H100 at 0000:81:00.0",
						dest.Name, err, st, buses, owner)
				}
			case tc.labels == "":
				if err == nil || st == "running" || len(buses) != 0 || owner != "" {
					t.Errorf("lv start on %s: err=%v state=%s buses=%v owner=%q; want it refused, nothing claimed", dest.Name, err, st, buses, owner)
				}
			default:
				v, _ := corrosion.GetVM(ctx, dest.DB, "sg")
				if tc.failReadBack && err != nil {
					err = nil // the read-back's, not the start's
				}
				if err != nil || st != "running" || len(buses) != 0 || v == nil ||
					!strings.Contains(v.StateDetail, "running without its PCI passthrough devices") {
					t.Errorf("lv start on %s: err=%v state=%s buses=%v vm=%+v; want it running without devices, saying so", dest.Name, err, st, buses, v)
				}
				if rows, qerr := dest.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'vm.passthrough_dropped' AND target = 'sg'`); qerr != nil || len(rows) == 0 {
					t.Errorf("no vm.passthrough_dropped audit row for sg's start on %s (%v)", dest.Name, qerr)
				}
			}
		})
	}
}

// A VM with a type selector, recovered onto b, restarts there with the GPU it
// already owns there: owned, that GPU is not free, and a fresh pick would
// find none.
func TestFleet_PCIFailover_RestartKeepsTheDeviceItOwns(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		ctx := context.Background()
		clock := NewVirtualClock(time.Now().UTC())
		c, a, b, _ := pciFoFleetWith(t, clock, pciFoSetup{latched: latched,
			devs: []*pb.DeviceSpec{{Type: "gpu", Vendor: h100.vendor}},
			onB:  []pciFoDevice{h100.at(pciFoThere)}})
		pciFoFailOver(t, ctx, c, clock, a, b)
		pciFoStart(t, ctx, b)
		if v := vmOn(t, b, pciFoVM); v == nil || v.State != "running" || v.HostName != b.Name {
			t.Fatalf("setup: %s did not start on %s: %+v", pciFoVM, b.Name, v)
		}
		if v := pciFoRestart(t, ctx, c, a, b); v == nil || v.State != "running" {
			t.Fatalf("restart on %s of a VM owning its GPU there refused: %+v", b.Name, v)
		}
		if buses := pciFoHostdevBuses(b.Virt.DefinedXML(pciFoVM)); len(buses) != 1 || buses[0] != "0x81" {
			t.Errorf("%s restarted on %s with buses %v, want its H100 at %s", pciFoVM, b.Name, buses, pciFoThere)
		}
	})
}

// Before the latch, a VM that failed over onto b is stopped and started there
// by an operator: the stop releases its device, and the start does not claim
// it again. A crash restart on b still runs it with b's H100, and a further
// failover off b can still say it needs an H100.
func TestFleet_PCIFailover_StopStartOnTheNewHostKeepsItRecoverable(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	ctx := context.Background()
	c, a, b, _ := pciFoLanded(t, ctx, false)
	if _, err := c.SelfClient(b).StopVM(ctx, &pb.StopVMRequest{Name: pciFoVM}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: pciFoVM}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if o := pciFoOwner(t, ctx, b, b.Name, pciFoThere); o != "" {
		t.Fatalf("setup: after the stop and start the H100 on %s reads owned by %q; this scenario needs it free", b.Name, o)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	vm := vmOn(t, a, pciFoVM)
	reqs, descs, err := placement.FailoverDeviceRequests(ctx, a.DB, *vm)
	if err != nil || len(reqs) != 1 || reqs[0].DeviceID != h100.device {
		t.Errorf("a further failover of %s off %s would need %+v (%v, %v); want an H100", pciFoVM, b.Name, reqs, descs, err)
	}
	v := pciFoRestart(t, ctx, c, a, b)
	if v == nil || v.State != "running" {
		t.Fatalf("crash restart on %s refused: %+v", b.Name, v)
	}
	if buses := pciFoHostdevBuses(b.Virt.DefinedXML(pciFoVM)); len(buses) != 1 || buses[0] != "0x81" {
		t.Errorf("%s restarted on %s with buses %v, want the H100 at %s", pciFoVM, b.Name, buses, pciFoThere)
	}
}

// Before the latch, lv start of a stopped passthrough VM on its own host,
// whose definition passes its device through, starts it as it is: the
// device is not added a second time.
func TestFleet_PCIFailover_StartOnItsOwnHostKeepsOneHostdev(t *testing.T) {
	defer vfio.SetFS(vfioBoundSysfs{})()
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	n := c.Nodes[0]
	if err := corrosion.UpsertPCIDevice(ctx, n.DB, corrosion.PCIDeviceRecord{HostName: n.Name, Address: pciFoThere,
		VendorID: h100.vendor, DeviceID: h100.device, DeviceName: h100.name, Type: "gpu", Driver: "vfio-pci", IOMMUGroup: 50}); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(t.TempDir(), "ovm-root.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dev := &pb.DeviceSpec{Address: pciFoThere}
	if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{Name: "ovm", HostName: n.Name, State: "stopped", StateDetail: "operator-stop",
		CPUActual: 1, MemActual: 256, Spec: vmSpecJSON(t, &pb.VMSpec{Name: "ovm", Cpu: 1, MemoryMib: 256, Devices: []*pb.DeviceSpec{dev}})},
		nil, []corrosion.DiskRecord{{VMName: "ovm", DiskName: "root", HostName: n.Name, Path: disk, StorageType: "nfs"}}); err != nil {
		t.Fatal(err)
	}
	kind, key := corrosion.ClassifyPCISelector(dev)
	payload, err := protojson.Marshal(dev)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertPCIIntent(ctx, n.DB, corrosion.PCIIntentRecord{VMName: "ovm",
		DeviceID: corrosion.DeterministicPCIIntentID(corrosion.CanonicalPCISelector(dev), 0), HostName: n.Name,
		SelectorKind: kind, SelectorPayload: string(payload), ExclusiveKey: key}); err != nil {
		t.Fatal(err)
	}
	if err := n.Virt.DefineDomain(`<domain type='kvm'><name>ovm</name><devices>` +
		`<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x0000' bus='0x81' slot='0x00' function='0x0'/></source></hostdev>` +
		`</devices></domain>`); err != nil {
		t.Fatal(err)
	}
	_, err = c.SelfClient(n).StartVM(ctx, &pb.StartVMRequest{Name: "ovm"})
	if buses := pciFoHostdevBuses(n.Virt.DefinedXML("ovm")); err != nil || len(buses) != 1 {
		t.Errorf("lv start of ovm on its own host: err=%v buses=%v; want it started with its one hostdev", err, buses)
	}
}
