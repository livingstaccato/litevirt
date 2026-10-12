package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// SweepUnattachedPCIOwnership releases this host's PCI devices that a live VM owns
// but provably does not use, and reports the ones it cannot prove. It is the
// cleanup for lab finding L1: before the fix, a failed SR-IOV attach left the VF
// owned by the VM though it was back on its host driver and in neither copy of
// the domain, and nothing reclaimed it. A fixed build no longer leaks one; this
// clears what an older build left behind. SweepStrandedPCIOwnership covers the
// other half, a device whose VM no longer exists.
//
// A device is released only when every one of these holds, and reported
// otherwise:
//   - the VM's row lives on this host in state running or stopped, and no
//     operation holds its mutation barrier;
//   - the VM's lock is free (taken without waiting, and held through the
//     release), so no attach, start or detach is between its claim and its
//     attach;
//   - no durable device lease is open for the VM: that is recovery's to settle;
//   - the VM has no PCI intents. A hardware_v2 reservation is owned while the VM
//     is off and is in neither copy of the domain until it starts, and an intent
//     names only its primary BDF, not the IOMMU-group siblings it also owns, so a
//     VM with any intent is left alone;
//   - both copies of the domain can be read, and neither carries the device;
//   - the device is not bound to vfio-pci. A leaked claim never reached the bind
//     or was rolled back from it; a bound device that no domain holds is
//     something else, and is reported.
//
// The release goes through unbindAndReleaseOwnership, which for an unbound device
// only clears a stale override and owner-releases the row.
func (s *Server) SweepUnattachedPCIOwnership(ctx context.Context) (released, reported []string) {
	if s.virt == nil {
		return nil, nil
	}
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		slog.Warn("pci unattached sweep: list devices", "error", err)
		return nil, nil
	}
	byVM := map[string][]string{}
	var vms []string
	for _, d := range devices {
		if d.VMName == "" {
			continue
		}
		if _, ok := byVM[d.VMName]; !ok {
			vms = append(vms, d.VMName)
		}
		byVM[d.VMName] = append(byVM[d.VMName], d.Address)
	}
	for _, vm := range vms {
		rel, rep := s.sweepUnattachedForVM(ctx, vm, byVM[vm])
		released = append(released, rel...)
		reported = append(reported, rep...)
	}
	for _, r := range reported {
		slog.Warn("pci unattached sweep: device owned by a VM that does not hold it, left owned", "detail", r)
	}
	for _, a := range released {
		s.publish("device.reclaimed", s.hostName, a+" freed: owned by a VM whose domain does not hold it")
	}
	return released, reported
}

func (s *Server) sweepUnattachedForVM(ctx context.Context, vmName string, addrs []string) (released, reported []string) {
	report := func(addr, why string) {
		reported = append(reported, fmt.Sprintf("%s (owner %s): %s; release it with `lv detach-pci %s %s` once that is resolved", addr, vmName, why, vmName, addr))
	}
	reportAll := func(why string) ([]string, []string) {
		for _, a := range addrs {
			report(a, why)
		}
		return nil, reported
	}

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil {
		return reportAll(fmt.Sprintf("cannot read the VM: %v", err))
	}
	if vm == nil {
		return nil, nil // SweepStrandedPCIOwnership's case
	}
	if vm.HostName != s.hostName {
		return nil, nil // another host's VM: its devices here are a migration's business
	}
	unlock, ok := s.tryLockVM(vmName)
	if !ok {
		return reportAll("the VM is locked by an operation in progress")
	}
	defer unlock()

	// Re-read under the lock.
	if vm, err = corrosion.GetVM(ctx, s.db, vmName); err != nil || vm == nil {
		return reportAll("cannot re-read the VM under its lock")
	}
	if vm.State != "running" && vm.State != "stopped" {
		return reportAll(fmt.Sprintf("the VM is %s", vm.State))
	}
	if vm.ActiveOperationID != "" {
		return reportAll(fmt.Sprintf("operation %s holds the VM", vm.ActiveOperationID))
	}
	if s.opJournal != nil {
		if _, found, jerr := s.opJournal.Read(deviceLeaseOpID(vmName)); jerr != nil || found {
			return reportAll("a device lease is open for the VM; startup recovery settles it")
		}
	}
	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, vmName)
	if err != nil {
		return reportAll(fmt.Sprintf("cannot read the VM's PCI intents: %v", err))
	}
	if len(intents) > 0 {
		return reportAll("the VM has PCI intents, whose reservations are held while it is off")
	}
	live, err := s.virt.DumpXML(vmName)
	if err != nil {
		return reportAll(fmt.Sprintf("cannot read the live domain: %v", err))
	}
	persistent, err := s.virt.DumpXMLInactive(vmName)
	if err != nil {
		return reportAll(fmt.Sprintf("cannot read the persistent domain: %v", err))
	}

	var leaked []string
	for _, a := range addrs {
		if hostdevBDFInXML(live, a) || hostdevBDFInXML(persistent, a) {
			continue // in use
		}
		bound, berr := vfio.IsBoundToVFIO(a)
		switch {
		case berr != nil:
			report(a, fmt.Sprintf("cannot read its driver: %v", berr))
		case bound:
			report(a, "it is bound to vfio-pci though no copy of the domain holds it")
		default:
			leaked = append(leaked, a)
		}
	}
	for _, a := range leaked {
		if rerr := s.unbindAndReleaseOwnership(ctx, vmName, []string{a}); rerr != nil {
			report(a, fmt.Sprintf("release failed: %v", rerr))
			continue
		}
		slog.Info("pci unattached sweep: released a device its owner's domain does not hold", "vm", vmName, "address", a)
		released = append(released, a)
	}
	return released, reported
}
