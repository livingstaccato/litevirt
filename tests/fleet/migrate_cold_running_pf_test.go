// Fleet scenario: `lv migrate --cold` of a RUNNING VM that holds a PF
// passthrough device.
//
// --cold moves a stopped VM. A running one still goes through libvirt's
// migration, which cannot move a PF, so it used to pass the live-only PF guard,
// prepare the target (disk stubs, domain-side work) and fail inside libvirt.
// It is now refused before anything is asked of the target, and the message
// gives the pre-hardware_v2 advice. A stopped VM's cold migration is unaffected, and a
// VF is detached and reattached as before.

package fleet

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hotplugreq"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/vfio"
)

// noRouteYet is the pre-hardware_v2 advice: stopped-VM detach and attach are
// refused until it is active, so no route is advised.
const noRouteYet = "no supported way to move this VM until it is"

// vfSysfs reports one address as a VF (it has a physfn link); everything else
// reads as absent.
type vfSysfs struct{ vf string }

func (vfSysfs) ReadFile(string) ([]byte, error)             { return nil, os.ErrNotExist }
func (vfSysfs) WriteFile(string, []byte, os.FileMode) error { return os.ErrPermission }
func (vfSysfs) ReadDir(string) ([]os.DirEntry, error)       { return nil, os.ErrNotExist }
func (f vfSysfs) Readlink(p string) (string, error) {
	if f.vf != "" && strings.Contains(p, f.vf) && strings.HasSuffix(p, "/physfn") {
		return "/sys/bus/pci/devices/0000:01:00.0", nil
	}
	return "", os.ErrNotExist
}

func (sc *coldStoppedScenario) assignPCI(t *testing.T, addr string) {
	t.Helper()
	if err := corrosion.UpsertPCIDevice(context.Background(), sc.src.DB, corrosion.PCIDeviceRecord{
		HostName: sc.src.Name, Address: addr, Type: "gpu", VendorID: "10de", IOMMUGroup: -1, VMName: "os1",
	}); err != nil {
		t.Fatalf("seed PCI device: %v", err)
	}
}

func (sc *coldStoppedScenario) setState(t *testing.T, state string) {
	t.Helper()
	if err := corrosion.UpdateVMState(context.Background(), sc.src.DB, "os1", state, ""); err != nil {
		t.Fatalf("set state: %v", err)
	}
	if state == "running" {
		if err := sc.src.Virt.StartDomain("os1"); err != nil {
			t.Fatalf("start source domain: %v", err)
		}
	}
}

func (sc *coldStoppedScenario) migrateColdStorage(t *testing.T) error {
	t.Helper()
	st, err := sc.c.SelfClient(sc.src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "os1", TargetHost: sc.dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD, WithStorage: true,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

// A running VM with a PF is refused up front, naming the device and saying to
// stop the VM first; the target has nothing of it afterwards.
//
// Mutation: restore the live-only condition on the PF guard — the migration
// goes on to prepare the target and this goes red.
func TestFleet_ColdMigrationOfARunningVMWithAPFIsRefusedUpFront(t *testing.T) {
	const pf = "0000:41:00.0"
	sc := newColdStoppedScenario(t)
	sc.src.Server.SetAllowUnencryptedStorageMigration(true)
	sc.assignPCI(t, pf)
	sc.setState(t, "running")

	err := sc.migrateColdStorage(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), pf) ||
		!strings.Contains(err.Error(), noRouteYet) {
		t.Fatalf("cold migrate of a running VM with a PF = %v; want FailedPrecondition naming %s and the pre-hardware_v2 advice", err, pf)
	}
	if _, serr := os.Stat(sc.file(sc.dst, sc.disk)); !os.IsNotExist(serr) {
		t.Errorf("the refused migration left a disk stub on %s (stat: %v)", sc.dst.Name, serr)
	}
	if sc.dst.Virt.DomainExists("os1") {
		t.Errorf("domain os1 was defined on %s by a refused migration", sc.dst.Name)
	}
	if ev := sc.dst.Virt.EventLog(); len(ev) > 0 {
		t.Errorf("the target's libvirt was touched by a refused migration: %+v", ev)
	}
	if vm := sc.vm(t); vm.HostName != sc.src.Name || vm.State != "running" {
		t.Errorf("VM row = host %s state %s, want it untouched on %s running", vm.HostName, vm.State, sc.src.Name)
	}

	// The live refusal gives the same advice.
	st, lerr := sc.c.SelfClient(sc.src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "os1", TargetHost: sc.dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE, WithStorage: true,
	})
	for lerr == nil {
		_, lerr = st.Recv()
	}
	if status.Code(lerr) != codes.FailedPrecondition || !strings.Contains(lerr.Error(), noRouteYet) {
		t.Errorf("live migrate of a VM with a PF = %v; want a refusal that gives the pre-hardware_v2 advice", lerr)
	}
}

// A STOPPED VM holding a PF takes the stopped-VM cold path, whose own
// hostdev refusal is unchanged: it is not the running-VM message, which would
// send the operator in a circle.
func TestFleet_ColdMigrationOfAStoppedVMWithAPFKeepsItsOwnRefusal(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.assignPCI(t, "0000:41:00.0")
	err := sc.migrateCold(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "migrating a stopped VM with hostdevs") {
		t.Fatalf("cold migrate of a stopped VM with a PF = %v; want the stopped path's hostdev refusal", err)
	}
	if !strings.Contains(err.Error(), noRouteYet) || strings.Contains(err.Error(), "lv detach-pci") {
		t.Fatalf("pre-hardware_v2 the stopped refusal must not advise a route that cannot run: %v", err)
	}
	if strings.Contains(err.Error(), "is running") {
		t.Fatalf("a stopped VM was told it is running: %v", err)
	}
}

// A VF on a running VM is not a PF: the PF refusal does not fire for it.
func TestFleet_ColdMigrationPFRefusalIgnoresVFs(t *testing.T) {
	const vf = "0000:41:00.1"
	defer vfio.SetFS(vfSysfs{vf: vf})()
	sc := newColdStoppedScenario(t)
	sc.src.Server.SetAllowUnencryptedStorageMigration(true)
	sc.assignPCI(t, vf)
	sc.setState(t, "running")

	err := sc.migrateColdStorage(t)
	if err != nil && strings.Contains(err.Error(), "which cannot be moved while the guest runs") {
		t.Fatalf("a VF was refused as a PF: %v", err)
	}
}

// latchPCIScenario brings the scenario to an active hardware_v2 with the device
// in both hosts' inventories and an IOMMU group for it.
func latchPCIScenario(t *testing.T, sc *coldStoppedScenario, addr string) {
	t.Helper()
	ctx := context.Background()
	gates := runCheckers(t, sc.c)
	latchOperationProtocol(t, sc.c, gates)

	root := t.TempDir()
	groups := filepath.Join(root, "kernel", "iommu_groups")
	devices := filepath.Join(root, "bus", "pci", "devices")
	for _, d := range []string{filepath.Join(groups, "41"), filepath.Join(devices, addr)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(pci.SetSysIOMMUGroups(groups))
	t.Cleanup(pci.SetSysDevices(devices))
	for _, n := range []*Node{sc.src, sc.dst} {
		if err := corrosion.UpsertPCIDevice(ctx, n.DB, corrosion.PCIDeviceRecord{
			HostName: n.Name, Address: addr, VendorID: "10de", DeviceID: "1eb8", Type: "gpu", IOMMUGroup: 41,
		}); err != nil {
			t.Fatalf("seed device on %s: %v", n.Name, err)
		}
	}
	backfillAll(t, sc.c)
	for _, n := range sc.c.Nodes {
		eventually(t, 10*time.Second, "hardware_v2 to latch on "+n.Name, func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.HardwareV2)
		})
	}
}

// attachCLI sends what `lv attach-pci <vm> --address <addr>` sends, built by the
// CLI's own request builder.
func attachCLI(t *testing.T, n *Node, c *Cluster, vm, addr string) error {
	t.Helper()
	req, err := hotplugreq.AttachPCI(vm, hotplugreq.AttachPCIOptions{Address: addr, Type: "gpu", Count: 1})
	if err != nil {
		t.Fatalf("build the attach-pci request: %v", err)
	}
	_, err = c.SelfClient(n).AttachDevice(context.Background(), req)
	return err
}

// The route the refusals advise, once hardware_v2 is active: stop, detach the
// device, cold-migrate, attach one on the target. Each step is run over the real
// RPCs with the CLI's request shapes, and the same migration is refused while
// the device is still assigned, so the detach is what makes it work. The
// target's device is a DIFFERENT address from the source's.
func TestFleet_PCIMoveRouteTheRefusalsAdviseWorks(t *testing.T) {
	const addr, targetAddr = "0000:41:00.0", "0000:42:00.0"
	sc := newColdStoppedScenario(t)
	ctx := context.Background()
	latchPCIScenario(t, sc, addr)
	if err := os.MkdirAll(filepath.Join(pci.SysDevicesPath(), targetAddr), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertPCIDevice(ctx, sc.dst.DB, corrosion.PCIDeviceRecord{
		HostName: sc.dst.Name, Address: targetAddr, VendorID: "10de", DeviceID: "1eb8", Type: "gpu", IOMMUGroup: 42,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pci.IOMMUGroupsPath(), "42"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := attachCLI(t, sc.src, sc.c, "os1", addr); err != nil {
		t.Fatalf("attach: %v", err)
	}
	err := sc.migrateCold(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv detach-pci os1 "+addr) ||
		!strings.Contains(err.Error(), "lv migrate os1 "+sc.dst.Name+" --cold") ||
		!strings.Contains(err.Error(), "--address") || !strings.Contains(err.Error(), "not carried") {
		t.Fatalf("cold migrate of a stopped VM holding a device = %v; want the refusal naming the whole route", err)
	}

	if _, err := sc.c.SelfClient(sc.src).DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "os1", PciAddress: addr}); err != nil {
		t.Fatalf("detach-pci: %v", err)
	}
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("cold migrate after the detach: %v", err)
	}
	if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != "stopped" {
		t.Fatalf("VM row = host %s state %s, want %s stopped", vm.HostName, vm.State, sc.dst.Name)
	}
	if err := attachCLI(t, sc.dst, sc.c, "os1", targetAddr); err != nil {
		t.Fatalf("attach-pci --address on the target: %v", err)
	}
	devs, _ := corrosion.ListPCIDevices(ctx, sc.dst.DB, sc.dst.Name, "")
	owned := map[string]string{}
	for _, d := range devs {
		owned[d.Address] = d.VMName
	}
	if owned[targetAddr] != "os1" {
		t.Fatalf("target's %s is not os1's after the attach: %v", targetAddr, owned)
	}
}

// The stopped-VM hostdev refusal of the cold path (a device recorded for the VM
// with no PCI intent row) gives the same route, with the real target name.
//
// Mutation: drop the route from that message — red.
func TestFleet_ColdMoveStoppedHostdevRefusalGivesTheRoute(t *testing.T) {
	const addr = "0000:41:00.0"
	sc := newColdStoppedScenario(t)
	latchPCIScenario(t, sc, addr)
	sc.assignPCI(t, addr)
	err := sc.migrateCold(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "migrating a stopped VM with hostdevs") ||
		!strings.Contains(err.Error(), "lv migrate os1 "+sc.dst.Name+" --cold") || strings.Contains(err.Error(), "<target>") {
		t.Fatalf("cold move of a stopped VM with a recorded device = %v; want the route naming the real target", err)
	}
}

// Before hardware_v2 is active the stopped-VM detach and attach the route
// would need are refused, and the refusals say there is no route yet rather
// than advising one. Both halves are asserted: the steps really are refused,
// and no refusal advises them.
func TestFleet_PCIMoveRouteIsNotAdvisedBeforeHardwareV2(t *testing.T) {
	const addr = "0000:41:00.0"
	sc := newColdStoppedScenario(t)
	sc.assignPCI(t, addr)
	ctx := context.Background()

	if err := attachCLI(t, sc.src, sc.c, "os1", "0000:42:00.0"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("stopped-VM attach pre-latch = %v; the advice relies on it being refused", err)
	}
	_, derr := sc.c.SelfClient(sc.src).DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "os1", PciAddress: addr})
	if status.Code(derr) != codes.FailedPrecondition {
		t.Errorf("stopped-VM detach pre-latch = %v; the advice relies on it being refused", derr)
	}
	err := sc.migrateCold(t)
	if err == nil || !strings.Contains(err.Error(), noRouteYet) || strings.Contains(err.Error(), "lv detach-pci") {
		t.Fatalf("pre-latch cold move refusal = %v; want the no-route-yet advice and no detach-pci step", err)
	}
}
