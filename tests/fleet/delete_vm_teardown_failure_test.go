package fleet

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// The VM row is the cluster's only handle on a domain. DeleteVM used to log a
// failed libvirt undefine and carry on — deleting the disks and tombstoning the
// row — so the VM was reported deleted while its domain was still defined on the
// host, with nothing left in the cluster that pointed at it. A failed teardown
// must fail the delete and keep the handle, so the delete can be retried.

// deployOneVM deploys composeFailOne and returns the recorded disk paths of hb-1.
func deployOneVM(t *testing.T, ctx context.Context, node *Node, client pb.LiteVirtClient) []string {
	t.Helper()
	msgs := deployCollect(t, ctx, client, composeFailOne)
	if p := errorPhaseFor(msgs, "hb-1"); p != nil {
		t.Fatalf("setup deploy failed: %s", p.Error)
	}
	rows, err := node.DB.Query(ctx, `SELECT path FROM vm_disks WHERE vm_name = 'hb-1' AND deleted_at IS NULL`)
	if err != nil {
		t.Fatalf("read hb-1 disks: %v", err)
	}
	var paths []string
	for _, r := range rows {
		if p := r.String("path"); p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		t.Fatal("hb-1 has no recorded disk")
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("hb-1 disk %s missing before the delete: %v", p, err)
		}
	}
	return paths
}

// assertDeleteKeptHandle checks that a failed delete left the row, the domain
// and the disks in place.
func assertDeleteKeptHandle(t *testing.T, ctx context.Context, node *Node, disks []string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(ctx, node.DB, "hb-1")
	if err != nil || vm == nil {
		t.Fatalf("hb-1's row was dropped although its domain was not removed: vm=%v err=%v", vm, err)
	}
	if !node.Virt.DomainExists("hb-1") {
		t.Fatal("the domain is gone — the injection did not hold")
	}
	for _, p := range disks {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("disk %s of a still-defined domain was deleted: %v", p, err)
		}
	}
	return vm
}

func TestFleet_DeleteVMFailedUndefineKeepsTheRecord(t *testing.T) {
	for _, keepDisks := range []bool{false, true} {
		name := "delete"
		if keepDisks {
			name = "keep-disks"
		}
		t.Run(name, func(t *testing.T) {
			_, node, client := newComposeFailNode(t)
			ctx := context.Background()
			disks := deployOneVM(t, ctx, node, client)

			injected := errors.New("injected: undefine refused")
			node.Virt.FailUndefineDomain = func(string, bool) error { return injected }
			node.Virt.FailUndefinePreserv = func(string) error { return injected }

			_, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1", KeepDisks: keepDisks})
			if err == nil {
				t.Fatal("DeleteVM reported success although the domain could not be undefined")
			}
			if !strings.Contains(err.Error(), "undefine") {
				t.Errorf("DeleteVM error %q does not say the undefine failed", err)
			}
			vm := assertDeleteKeptHandle(t, ctx, node, disks)
			// The domain was destroyed on the way, so the row must not go on
			// claiming it runs — and must not be restarted by a restart policy.
			if vm.State != "stopped" || vm.StateDetail != "operator-stop" {
				t.Errorf("hb-1 recorded as %q/%q after its domain was destroyed, want stopped/operator-stop",
					vm.State, vm.StateDetail)
			}

			// The cause is gone: the same delete now completes.
			node.Virt.FailUndefineDomain = nil
			node.Virt.FailUndefinePreserv = nil
			if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1", KeepDisks: keepDisks}); err != nil {
				t.Fatalf("retried DeleteVM: %v", err)
			}
			if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm != nil {
				t.Error("hb-1's row survived a successful retry")
			}
			if node.Virt.DomainExists("hb-1") {
				t.Error("hb-1's domain survived a successful retry")
			}
		})
	}
}

// A domain that could not be stopped must not be undefined: libvirt turns an
// undefined ACTIVE domain into a transient one that keeps running, so the delete
// would free the disks under a live guest and drop its row.
func TestFleet_DeleteVMFailedDestroyKeepsTheRecord(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	disks := deployOneVM(t, ctx, node, client)

	node.Virt.FailDestroyDomain = func(string) error { return errors.New("injected: destroy refused") }
	_, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"})
	if err == nil {
		t.Fatal("DeleteVM reported success although the running domain could not be stopped")
	}
	if !strings.Contains(err.Error(), "stop") {
		t.Errorf("DeleteVM error %q does not say the stop failed", err)
	}
	assertDeleteKeptHandle(t, ctx, node, disks)
	for _, e := range node.Virt.EventLog() {
		if e.Domain == "hb-1" && e.Op == "undefine" {
			t.Error("DeleteVM undefined hb-1 although it could not stop it")
		}
	}
	if st, _ := node.Virt.DomainState("hb-1"); st != "running" {
		t.Errorf("hb-1 domain state = %q, want running (nothing was stopped)", st)
	}
}

// A paused domain is ACTIVE although its row does not say "running"; undefining
// it without a stop leaves it alive as a transient domain. DeleteVM must stop
// it first.
func TestFleet_DeleteVMStopsAPausedDomainBeforeUndefine(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	deployOneVM(t, ctx, node, client)

	node.Virt.SetState("hb-1", libvirtfake.StatePaused)
	if err := node.DB.Execute(ctx, `UPDATE vms SET state = 'paused' WHERE name = 'hb-1'`); err != nil {
		t.Fatalf("record hb-1 paused: %v", err)
	}
	before := len(node.Virt.EventLog())
	if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err != nil {
		t.Fatalf("DeleteVM of a paused VM: %v", err)
	}
	var ops []string
	for _, e := range node.Virt.EventLog()[before:] {
		if e.Domain == "hb-1" {
			ops = append(ops, e.Op)
		}
	}
	if len(ops) < 2 || ops[0] != "destroy" || ops[1] != "undefine" {
		t.Errorf("libvirt ops on hb-1 = %v, want destroy before undefine", ops)
	}
}

// stuckSysfs makes vfio unable to read one device's driver link, so
// releaseDevices cannot prove it unbound and fails closed. Every other path
// reads as absent (no vfio-bound devices, no IOMMU groups).
type stuckSysfs struct{ addr string }

func (f stuckSysfs) ReadFile(string) ([]byte, error)             { return nil, os.ErrNotExist }
func (f stuckSysfs) WriteFile(string, []byte, os.FileMode) error { return os.ErrPermission }
func (f stuckSysfs) ReadDir(string) ([]os.DirEntry, error)       { return nil, os.ErrNotExist }
func (f stuckSysfs) Readlink(p string) (string, error) {
	if strings.Contains(p, f.addr) {
		return "", errors.New("injected: sysfs driver link unreadable")
	}
	return "", os.ErrNotExist
}

// The PCI release (and the remote-owner check after it) run after the domain
// has been stopped. A delete that fails there keeps the row — but the row went
// on saying "running" over a destroyed domain, where a restart policy would
// bring back a VM that is being deleted, and the failure left no audit row.
func TestFleet_DeleteVMFailedDeviceReleaseRecordsTheStop(t *testing.T) {
	const addr = "0000:41:00.0"
	for _, tc := range []struct {
		name, owner, wantErr string
		stuck                bool
	}{
		{name: "local-release", owner: "node-0", wantErr: "could not be released", stuck: true},
		{name: "remote-owner", owner: "node-9", wantErr: "still own its PCI"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, node, client := newComposeFailNode(t)
			ctx := context.Background()
			disks := deployOneVM(t, ctx, node, client)
			if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm == nil || vm.State != "running" {
				t.Fatalf("precondition: hb-1 should be running, got %+v", vm)
			}

			if tc.owner != node.Name {
				// Only a live host's reservation counts as a remote owner.
				if err := corrosion.InsertHost(ctx, node.DB, corrosion.HostRecord{
					Name: tc.owner, Address: "10.9.9.9", State: "maintenance",
				}); err != nil {
					t.Fatalf("seed host %s: %v", tc.owner, err)
				}
			}
			if err := corrosion.UpsertPCIDevice(ctx, node.DB, corrosion.PCIDeviceRecord{
				HostName: tc.owner, Address: addr, Type: "gpu", VendorID: "10de", IOMMUGroup: -1, VMName: "hb-1",
			}); err != nil {
				t.Fatalf("seed PCI device owned by hb-1: %v", err)
			}
			if tc.stuck {
				restore := vfio.SetFS(stuckSysfs{addr: addr})
				defer restore()
			}

			_, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"})
			if err == nil {
				t.Fatal("DeleteVM reported success although the VM's PCI device was not released")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("DeleteVM error %q, want it to say %q", err, tc.wantErr)
			}
			vm := assertDeleteKeptHandle(t, ctx, node, disks)
			if st, _ := node.Virt.DomainState("hb-1"); st == "running" {
				t.Fatal("the domain is still running — the delete did not reach the device release")
			}
			if vm.State != "stopped" || vm.StateDetail != "operator-stop" {
				t.Errorf("hb-1 recorded as %q/%q after its domain was destroyed, want stopped/operator-stop",
					vm.State, vm.StateDetail)
			}
			if res, detail := lastAuditResult(t, ctx, node.DB, "vm.delete", "hb-1"); res != "error" {
				t.Errorf("vm.delete audit result = %q (%s), want error", res, detail)
			}
		})
	}
}
