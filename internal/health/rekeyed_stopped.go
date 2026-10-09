package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A stopped VM failover re-keyed onto this host.
//
// The failover coordinator moves a VM stopped by intent whose disks are all
// on shared storage off a failed host, still stopped
// (corrosion.RekeyStoppedVM), so it is off the dead host on its real disks
// and never started. Its row arrives here stopped, marked
// corrosion.StoppedRekeyDetail, with no domain on this host — and `lv start`
// starts a defined domain, it does not define one. So the reconciler defines
// it here, shut off, from its spec and disk rows, the way a failover start
// does but without starting it, and then records the stop as an operator
// stop. From then on it is a stopped VM like any other.

// defineRekeyedStoppedVM defines vm's domain on this host, shut off, and
// replaces the re-key marker with an operator stop. A step that fails leaves
// the marker, and the next pass tries again; nothing here starts the VM.
func (r *Reconciler) defineRekeyedStoppedVM(ctx context.Context, vm corrosion.VMRecord) {
	if r.virt == nil {
		return
	}
	if !r.acquireVMLock(ctx, vm.Name) {
		return
	}
	defer r.releaseVMLock(context.WithoutCancel(ctx), vm.Name)
	fresh, err := corrosion.GetVM(ctx, r.db, vm.Name)
	if err != nil || fresh == nil || fresh.HostName != r.hostName || fresh.State != "stopped" ||
		!corrosion.IsStoppedRekeyDetail(fresh.StateDetail) {
		return
	}
	if r.virt.DomainExists(vm.Name) {
		if st, serr := r.virt.DomainState(vm.Name); serr != nil || st == "running" {
			// Defined and running here is not a re-key to finish; the
			// running-state reconcile owns that case.
			return
		}
	} else {
		disks, err := corrosion.ListDisks(ctx, r.db, vm.Name)
		if err != nil {
			slog.Warn("reconciler: re-keyed stopped VM: list disks; retrying", "vm", vm.Name, "error", err)
			return
		}
		if corrosion.VMHasHostLocalDisk(disks) {
			slog.Error("reconciler: re-keyed stopped VM has a host-local disk; not defining it here", "vm", vm.Name)
			return
		}
		spec := &pb.VMSpec{}
		if fresh.Spec != "" {
			if err := json.Unmarshal([]byte(fresh.Spec), spec); err != nil {
				slog.Error("reconciler: re-keyed stopped VM: parse spec", "vm", vm.Name, "error", err)
				return
			}
		}
		var diskConfigs []lv.DiskConfig
		for _, d := range disks {
			if _, err := os.Stat(d.Path); err != nil {
				slog.Warn("reconciler: re-keyed stopped VM: shared disk not visible on this host yet; retrying",
					"vm", vm.Name, "disk", d.DiskName, "path", d.Path, "error", err)
				return
			}
			bus := "virtio"
			for _, sd := range spec.Disks {
				if sd.Name == d.DiskName && sd.Bus != "" {
					bus = sd.Bus
					break
				}
			}
			diskConfigs = append(diskConfigs, lv.DiskConfig{Name: d.DiskName, Path: d.Path, Bus: bus})
		}
		domXML, _, failure := r.domainXMLFor(ctx, *fresh, spec, diskConfigs)
		if failure != "" {
			slog.Warn("reconciler: re-keyed stopped VM: build its domain; retrying", "vm", vm.Name, "error", failure)
			return
		}
		if err := r.virt.DefineDomain(domXML); err != nil {
			slog.Warn("reconciler: re-keyed stopped VM: define its domain; retrying", "vm", vm.Name, "error", err)
			return
		}
		slog.Info("reconciler: defined a stopped VM failover moved here; it stays stopped until started",
			"vm", vm.Name, "from", fresh.StateDetail[len(corrosion.StoppedRekeyDetailPrefix):])
	}
	if err := corrosion.UpdateVMStateAtEpoch(ctx, r.db, vm.Name, "stopped", operatorStopDetail, fresh.OwnerEpoch); err != nil {
		slog.Warn("reconciler: re-keyed stopped VM: record its stop", "vm", vm.Name, "error", err)
		r.noteStateWriteFail(corrosion.OpVMState, err)
	}
}
