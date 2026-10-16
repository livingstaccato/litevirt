package grpcapi

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// guardRetiredBy is the set_by of a record retired with its NIC.
const guardRetiredBy = "litevirt"

// retireNICGuard retires the guard record of vm's NIC mac (a no-op when it
// has none). Callers retire a record only once its NIC is gone from the
// domain, so a live NIC is never left without its guard.
func (s *Server) retireNICGuard(ctx context.Context, vm, mac string) error {
	return corrosion.RetireNICGuard(ctx, s.db, vm, mac, guardRetiredBy)
}

// retireFailedCreateGuards retires the guard records recs that a create of
// vm as the incarnation uuid wrote, once that create has failed: no VM of
// that incarnation exists, and a record it left live would be demanded in
// force by the next create of the name. A record another incarnation has
// written over since is left as it is. The request may be what failed, so it
// runs detached from it, bounded.
func (s *Server) retireFailedCreateGuards(ctx context.Context, vm, uuid string, recs []corrosion.NICGuardRecord) {
	if len(recs) == 0 {
		return
	}
	macs := make([]string, 0, len(recs))
	for _, r := range recs {
		macs = append(macs, r.MAC)
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := corrosion.RetireNICGuardsOfIncarnation(rctx, s.db, vm, uuid, macs, guardRetiredBy); err != nil {
		slog.Warn("NIC guard: could not retire the guard records of a failed create; they guard nothing, and the next "+
			"create of the name does not demand them", "vm", vm, "error", err)
	}
}

// retireOrphanNICGuards retires the guard records of vm whose NIC exists
// nowhere: records an earlier build left live after a detach or a failed
// attach, which every later arm of the VM would demand in force and no host
// can render (lab 2, C3). It runs on the VM's owner, under the VM's lock,
// with no operation in flight on the VM but ownOp (the caller's own, or "").
//
// A record of the incarnation that runs now is retired only when all of
// these hold for its MAC:
//   - no live NIC row of the VM has it (the vm_nics/vm_interfaces overlay):
//     its row is tombstoned or never existed, so no host renders the NIC; and
//   - neither the live nor the persistent definition of the VM's domain on
//     this host has it, so no guest here carries it or will at its next start.
//
// Anything it cannot read leaves every record as it is: the arm then refuses
// as before, which is the safe side.
func (s *Server) retireOrphanNICGuards(ctx context.Context, vmName, ownOp string) {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil || vm.HostName != s.hostName ||
		(vm.ActiveOperationID != "" && vm.ActiveOperationID != ownOp) {
		return
	}
	recs, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		return
	}
	uuid := specUUID(vm.Spec)
	var own []corrosion.NICGuardRecord
	for _, r := range recs {
		if r.VMName == vmName && (r.VMUUID == "" || uuid == "" || r.VMUUID == uuid) {
			own = append(own, r)
		}
	}
	if len(own) == 0 {
		return
	}
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vmName)
	if err != nil {
		return
	}
	live := map[string]bool{}
	for _, n := range nics {
		live[strings.ToLower(n.MAC)] = true
	}
	active, aerr := s.virt.DumpXML(vmName)
	inactive, ierr := s.virt.DumpXMLInactive(vmName)
	if aerr != nil || ierr != nil {
		return
	}
	for _, r := range own {
		mac := strings.ToLower(r.MAC)
		if live[mac] || nicMacInXML(active, mac) || nicMacInXML(inactive, mac) {
			continue
		}
		if err := s.retireNICGuard(ctx, vmName, mac); err != nil {
			slog.Warn("NIC guard: could not retire the record of a NIC the VM no longer has", "vm", vmName, "mac", mac, "error", err)
			continue
		}
		slog.Warn("NIC guard: retired the record of a NIC the VM no longer has (left by an earlier build's detach or failed attach)",
			"vm", vmName, "mac", mac)
	}
}
