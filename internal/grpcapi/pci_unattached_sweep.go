package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/vfio"
)

// SweepUnattachedPCIOwnership releases this host's PCI devices that a live VM owns
// but provably does not use. It is the cleanup for lab finding L1: before the fix,
// a failed SR-IOV attach left the VF owned by the VM though it was back on its
// host driver and in neither copy of the domain, and nothing reclaimed it. A fixed
// build no longer leaks one; this clears what an older build left behind.
// SweepStrandedPCIOwnership covers the other half, a device whose VM no longer
// exists.
//
// A VM is SKIPPED, silently (Debug only), unless every one of these holds — each
// is a reason its devices may be legitimately owned and out of the domain, or a
// reason the domain cannot be judged, and none of them is an operator's problem:
//   - the VM's row lives on this host in state running or stopped, and no
//     operation holds its mutation barrier;
//   - the VM's lock is free (taken without waiting, and held through the
//     release), so no attach, start or detach is between its claim and its
//     attach;
//   - no durable device lease is open for the VM: that is recovery's to settle;
//   - the VM has no PCI intents. A hardware_v2 reservation is owned while the VM
//     is off and is in neither copy of the domain until it starts, and an intent
//     names only its primary BDF, not the IOMMU-group siblings it also owns;
//   - both copies of the domain can be read AND parsed. An unparseable document
//     proves nothing about what it holds.
//
// For a VM that passes, a device in either copy of the domain is in use and left
// alone. A device proven absent from both copies is released when it is not bound
// to vfio-pci (a leaked claim never reached the bind, or was rolled back from it).
// Only a device proven absent that still cannot be released — it is bound to
// vfio-pci, its driver cannot be read, or the release failed — is REPORTED, with
// the detach that releases it.
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
		slog.Warn("pci unattached sweep: device owned by a VM whose domain does not hold it, left owned", "detail", r)
	}
	for _, a := range released {
		s.publish("device.reclaimed", s.hostName, a+" freed: owned by a VM whose domain does not hold it")
	}
	return released, reported
}

func (s *Server) sweepUnattachedForVM(ctx context.Context, vmName string, addrs []string) (released, reported []string) {
	skip := func(why string) ([]string, []string) {
		slog.Debug("pci unattached sweep: skipping VM", "vm", vmName, "devices", addrs, "reason", why)
		return nil, nil
	}

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil {
		return skip(fmt.Sprintf("cannot read the VM: %v", err))
	}
	if vm == nil {
		return nil, nil // SweepStrandedPCIOwnership's case
	}
	if vm.HostName != s.hostName {
		return skip("the VM lives on another host")
	}
	unlock, ok := s.tryLockVM(vmName)
	if !ok {
		return skip("the VM is locked by an operation in progress")
	}
	defer unlock()

	// Re-read under the lock.
	if vm, err = corrosion.GetVM(ctx, s.db, vmName); err != nil || vm == nil {
		return skip("cannot re-read the VM under its lock")
	}
	if vm.State != "running" && vm.State != "stopped" {
		return skip("the VM is " + vm.State)
	}
	if vm.ActiveOperationID != "" {
		return skip("operation " + vm.ActiveOperationID + " holds the VM")
	}
	if s.opJournal != nil {
		if _, found, jerr := s.opJournal.Read(deviceLeaseOpID(vmName)); jerr != nil || found {
			return skip("a device lease is open for the VM, or cannot be read")
		}
	}
	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, vmName)
	if err != nil {
		return skip(fmt.Sprintf("cannot read the VM's PCI intents: %v", err))
	}
	if len(intents) > 0 {
		return skip("the VM has PCI intents, whose reservations are held while it is off")
	}
	held := map[string]bool{}
	for _, copyOf := range []struct {
		name string
		dump func(string) (string, error)
	}{{"live", s.virt.DumpXML}, {"persistent", s.virt.DumpXMLInactive}} {
		x, derr := copyOf.dump(vmName)
		if derr != nil {
			return skip(fmt.Sprintf("cannot read the %s domain: %v", copyOf.name, derr))
		}
		bdfs, perr := libvirt.ParseHostdevSourcePCIAddresses(x)
		if perr != nil {
			return skip(fmt.Sprintf("cannot parse the %s domain: %v", copyOf.name, perr))
		}
		for _, raw := range bdfs {
			held[canonicalBDFOrRaw(raw)] = true
		}
	}

	report := func(addr, why string) {
		reported = append(reported, fmt.Sprintf("%s (owner %s, in neither copy of its domain): %s; release it with `lv detach-pci %s %s` once that is resolved", addr, vmName, why, vmName, addr))
	}
	var leaked []string
	for _, a := range addrs {
		if held[canonicalBDFOrRaw(a)] {
			continue // in use
		}
		bound, berr := vfio.IsBoundToVFIO(a)
		switch {
		case berr != nil:
			report(a, fmt.Sprintf("cannot read its driver: %v", berr))
		case bound:
			report(a, "it is still bound to vfio-pci")
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

// canonicalBDFOrRaw is the same normalisation hostdevBDFInXML applies.
func canonicalBDFOrRaw(addr string) string {
	if c, ok := pci.CanonicalBDF(addr); ok {
		return c
	}
	return strings.ToLower(strings.TrimSpace(addr))
}
