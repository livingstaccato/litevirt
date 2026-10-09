package health

import (
	"context"
	"encoding/json"
	"fmt"
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
// corrosion.StoppedRekeyDetail, with no domain on this host that can be
// trusted — and `lv start` starts a defined domain, it does not define one.
// So the reconciler defines it here, shut off, from its current spec and
// disk rows, the way a failover start does but without starting it.
//
// The marker stays on the row until the VM is started (it reads as a stop by
// intent everywhere, health.IsOperatorStop), so whichever host the row
// finally names defines it: with recovery claims off, two coordinators can
// re-key one VM to two hosts, and each target defines it while its own
// replica names it. The one the row does not end up naming undefines the
// definition it made (cleanupRekeyLeftovers). Nothing here starts a VM.

// noteRekeyOnce logs a re-key define problem once per VM and cause, so a
// condition that persists does not repeat on every pass.
func (r *Reconciler) noteRekeyOnce(name, cause string, args ...any) {
	r.rekeyMu.Lock()
	if r.rekeyLogged == nil {
		r.rekeyLogged = map[string]string{}
	}
	seen := r.rekeyLogged[name] == cause
	r.rekeyLogged[name] = cause
	r.rekeyMu.Unlock()
	if !seen {
		slog.Warn("reconciler: re-keyed stopped VM not defined here yet: "+cause, append([]any{"vm", name}, args...)...)
	}
}

// defineRekeyedStoppedVM (re)defines vm's domain on this host, shut off, from
// its current spec, once per version of its row per process. A definition
// already here is not trusted — it can be a leftover from an earlier stay,
// with an old disk set — and is replaced. A step that fails is retried on the
// next pass.
func (r *Reconciler) defineRekeyedStoppedVM(ctx context.Context, vm corrosion.VMRecord) {
	if r.virt == nil {
		return
	}
	fresh, err := corrosion.GetVM(ctx, r.db, vm.Name)
	if err != nil || fresh == nil || fresh.HostName != r.hostName || fresh.State != "stopped" ||
		!corrosion.IsStoppedRekeyDetail(fresh.StateDetail) {
		return
	}
	r.rekeyMu.Lock()
	at, done := r.rekeyDefined[vm.Name]
	r.rekeyMu.Unlock()
	if done && at == fresh.UpdatedAt && r.virt.DomainExists(vm.Name) {
		return
	}
	if r.virt.DomainExists(vm.Name) {
		if st, serr := r.virt.DomainState(vm.Name); serr != nil || st == "running" {
			// Running here is not a re-key to finish; the running-state
			// reconcile and Layer 3 own that case.
			return
		}
	}
	if !r.acquireVMLock(ctx, vm.Name) {
		return
	}
	defer r.releaseVMLock(context.WithoutCancel(ctx), vm.Name)

	disks, err := corrosion.ListDisks(ctx, r.db, vm.Name)
	if err != nil {
		r.noteRekeyOnce(vm.Name, "cannot read its disks", "error", err)
		return
	}
	if corrosion.VMHasHostLocalDisk(disks) {
		r.noteRekeyOnce(vm.Name, "it has a host-local disk, which a re-key never carries")
		return
	}
	spec := &pb.VMSpec{}
	if fresh.Spec != "" {
		if err := json.Unmarshal([]byte(fresh.Spec), spec); err != nil {
			r.noteRekeyOnce(vm.Name, "its spec does not parse", "error", err)
			return
		}
	}
	var diskConfigs []lv.DiskConfig
	for _, d := range disks {
		if _, err := os.Stat(d.Path); err != nil {
			r.noteRekeyOnce(vm.Name, "a shared disk is not visible on this host", "disk", d.DiskName, "path", d.Path)
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
		r.noteRekeyOnce(vm.Name, "its domain cannot be built: "+failure)
		return
	}
	if r.virt.DomainExists(vm.Name) {
		// Replace, never trust: a leftover may name an old disk set.
		r.virt.UndefineDomainPreservingState(vm.Name)
	}
	if err := r.virt.DefineDomain(domXML); err != nil {
		r.noteRekeyOnce(vm.Name, fmt.Sprintf("define failed: %v", err))
		return
	}
	r.rekeyMu.Lock()
	if r.rekeyDefined == nil {
		r.rekeyDefined = map[string]string{}
	}
	r.rekeyDefined[vm.Name] = fresh.UpdatedAt
	delete(r.rekeyLogged, vm.Name)
	r.rekeyMu.Unlock()
	slog.Info("reconciler: defined a stopped VM failover moved here; it stays stopped until started",
		"vm", vm.Name, "from", fresh.StateDetail[len(corrosion.StoppedRekeyDetailPrefix):])
}

// cleanupRekeyLeftovers undefines, shut off, each domain this process defined
// for a re-keyed stopped VM whose row no longer names this host — the losing
// target of two coordinators' re-keys — and forgets VMs that have since been
// started or deleted. Disks are never touched: they are shared, and the VM's
// owner uses them.
func (r *Reconciler) cleanupRekeyLeftovers(ctx context.Context) {
	if r.virt == nil {
		return
	}
	r.rekeyMu.Lock()
	names := make([]string, 0, len(r.rekeyDefined))
	for n := range r.rekeyDefined {
		names = append(names, n)
	}
	r.rekeyMu.Unlock()
	for _, name := range names {
		row, err := corrosion.GetVM(ctx, r.db, name)
		if err != nil {
			continue
		}
		if row != nil && row.HostName == r.hostName {
			if row.State != "stopped" || !corrosion.IsStoppedRekeyDetail(row.StateDetail) {
				r.forgetRekey(name) // started, or otherwise moved on, here
			}
			continue
		}
		if r.virt.DomainExists(name) {
			if st, serr := r.virt.DomainState(name); serr != nil || st == "running" {
				continue
			}
			r.virt.UndefineDomainPreservingState(name)
			slog.Info("reconciler: undefined a re-keyed stopped VM's domain; its row names another host",
				"vm", name, "owner", map[bool]string{true: row.HostName, false: "(deleted)"}[row != nil])
		}
		r.forgetRekey(name)
	}
}

func (r *Reconciler) forgetRekey(name string) {
	r.rekeyMu.Lock()
	delete(r.rekeyDefined, name)
	delete(r.rekeyLogged, name)
	r.rekeyMu.Unlock()
}
