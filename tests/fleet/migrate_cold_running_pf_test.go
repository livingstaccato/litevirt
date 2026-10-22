// Fleet scenario: `lv migrate --cold` of a RUNNING VM that holds a PF
// passthrough device.
//
// --cold moves a stopped VM. A running one still goes through libvirt's
// migration, which cannot move a PF, so it used to pass the live-only PF guard,
// prepare the target (disk stubs, domain-side work) and fail inside libvirt.
// It is now refused before anything is asked of the target, and the message
// says to stop the VM first. A stopped VM's cold migration is unaffected, and a
// VF is detached and reattached as before.

package fleet

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

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
		!strings.Contains(err.Error(), "stop the VM first") {
		t.Fatalf("cold migrate of a running VM with a PF = %v; want FailedPrecondition naming %s and saying to stop the VM first", err, pf)
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
	if status.Code(lerr) != codes.FailedPrecondition || !strings.Contains(lerr.Error(), "stop the VM first") {
		t.Errorf("live migrate of a VM with a PF = %v; want a refusal that says to stop the VM first", lerr)
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
	if err != nil && strings.Contains(err.Error(), "stop the VM first") {
		t.Fatalf("a VF was refused as a PF: %v", err)
	}
}
