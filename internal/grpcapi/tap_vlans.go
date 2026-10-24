package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A NIC on the `trunk:` feature has its VLANs on its host tap, not in the
// domain XML: libvirt makes a fresh tap (vnetN, or the name its MAC fixes) at
// every start and on a live migration's target, and a new port of a
// VLAN-filtering bridge carries only VLAN 1, as pvid, untagged. An access
// port (trunk: with one VLAN) left like that is on VLAN 1, the untagged
// segment every plain NIC and the host share, instead of its own.
//
// So the VLANs go on in ONE place for every way a guest comes to run here,
// before it runs:
//
//   - a start, whatever path asks for it (create, `lv start`, the
//     reconciler's failover, reschedule and onboot starts, a health restart,
//     promote, clone, replace, restore, import, a snapshot revert): every one
//     goes through libvirt.Client's start guard, and NICStartGuard starts a
//     guest with tap VLANs paused, puts them on in readyGuestHere, and only
//     then lets it run;
//   - a guest that arrived here paused (a live move handed over paused, a
//     live firmware move's release, an adopted hold): readyGuestHere before
//     the resume. A live move of a guest with tap VLANs is always handed over
//     paused (armMigrationTarget), so libvirt never lets it run on arrival.
//
// ConvergeTapVLANs re-applies every running guest's on a timer, so a tap
// changed behind litevirt's back, or one a path above missed, is put right.

// tapVLANNIC is one NIC whose VLANs live on its host tap.
type tapVLANNIC struct {
	Bridge string
	MAC    string
	// VLANs: one is an access port on it (pvid, untagged, and nothing
	// else); more is a trunk carrying them tagged.
	VLANs []int
}

func (n tapVLANNIC) access() bool { return len(n.VLANs) == 1 }

// pendingTapVLANs is the tap VLANs of a guest a start on this host is bringing
// up before its row is written (a create, a clone, a restore), so the start
// guard can put them on: vm name -> *[]tapVLANNIC.

// notePendingTapVLANs registers nics as vm's tap VLANs until the returned func
// runs (call it once the rows are written, or the start failed). A second
// note for the name does not take the first one's over.
func (s *Server) notePendingTapVLANs(vm string, nics []tapVLANNIC) func() {
	if vm == "" || len(nics) == 0 {
		return func() {}
	}
	p := &nics
	if _, taken := s.pendingTapVLANs.LoadOrStore(vm, p); taken {
		return func() {}
	}
	return func() { s.pendingTapVLANs.CompareAndDelete(vm, p) }
}

// pendingTapVLANsFor is notePendingTapVLANs from a spec not yet stored: each
// NIC with a trunk, on the bridge its network resolves to here, with the MAC
// the spec or recs (by ordinal) gives it.
func (s *Server) pendingTapVLANsFor(ctx context.Context, vm string, spec *pb.VMSpec, recs []corrosion.InterfaceRecord) func() {
	return s.notePendingTapVLANs(vm, tapVLANNICs(ctx, s.db, spec, recs))
}

// tapVLANNICs is each NIC of spec with a trunk, with its bridge here and its
// MAC (the spec's, else the one recs gives its ordinal). A NIC with no MAC or
// bridge, or on a direct (macvtap) network, has no tap to configure.
func tapVLANNICs(ctx context.Context, db *corrosion.Client, spec *pb.VMSpec, recs []corrosion.InterfaceRecord) []tapVLANNIC {
	var out []tapVLANNIC
	var macByOrdinal map[int]string
	for i, n := range spec.GetNetwork() {
		if len(n.GetTrunk()) == 0 {
			continue
		}
		if macByOrdinal == nil {
			macByOrdinal = make(map[int]string, len(recs))
			for _, r := range recs {
				macByOrdinal[r.Ordinal] = r.MAC
			}
		}
		mac := n.GetMac()
		if mac == "" {
			mac = macByOrdinal[i]
		}
		bridge := resolveBridge(ctx, db, n.GetName())
		if mac == "" || bridge == "" || strings.HasPrefix(bridge, "direct:") {
			continue
		}
		vlans := make([]int, len(n.GetTrunk()))
		for j, v := range n.GetTrunk() {
			vlans[j] = int(v)
		}
		out = append(out, tapVLANNIC{Bridge: bridge, MAC: mac, VLANs: vlans})
	}
	return out
}

// tapVLANsOf is the tap VLANs of vm's NICs here: a start's pending ones, else
// from its stored spec. A VM with no row, or a spec that cannot be read, has
// none. An error: its row could not be read.
func (s *Server) tapVLANsOf(ctx context.Context, vm string) ([]tapVLANNIC, error) {
	if p, ok := s.pendingTapVLANs.Load(vm); ok {
		return *(p.(*[]tapVLANNIC)), nil
	}
	if s.db == nil {
		return nil, nil
	}
	rec, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return nil, fmt.Errorf("read %s's NIC VLANs: %w", vm, err)
	}
	return s.tapVLANsOfRecord(ctx, rec)
}

// tapVLANsOfRecord is tapVLANsOf for a row already read.
func (s *Server) tapVLANsOfRecord(ctx context.Context, rec *corrosion.VMRecord) ([]tapVLANNIC, error) {
	if rec == nil || rec.Spec == "" {
		return nil, nil
	}
	spec := &pb.VMSpec{}
	if json.Unmarshal([]byte(rec.Spec), spec) != nil {
		return nil, nil
	}
	if !specHasTrunk(spec) {
		return nil, nil
	}
	ifaces, err := corrosion.GetVMInterfaces(ctx, s.db, rec.Name)
	if err != nil {
		return nil, fmt.Errorf("read %s's NICs: %w", rec.Name, err)
	}
	return tapVLANNICs(ctx, s.db, spec, ifaces), nil
}

func specHasTrunk(spec *pb.VMSpec) bool {
	for _, n := range spec.GetNetwork() {
		if len(n.GetTrunk()) > 0 {
			return true
		}
	}
	return false
}

// HasTapVLANs reports whether a start of vm here must put VLANs on its taps
// before the guest runs; true when that cannot be read. The daemon's start
// wait asks it (startWaitNeeded): such a start waits for the start guard.
func (s *Server) HasTapVLANs(ctx context.Context, vm string) bool {
	nics, err := s.tapVLANsOf(ctx, vm)
	return err != nil || len(nics) > 0
}

// VMHasTapVLANs is HasTapVLANs from the replicated rows alone, for a start
// before this host's server is wired.
func VMHasTapVLANs(ctx context.Context, db *corrosion.Client, vm string) bool {
	rec, err := corrosion.GetVM(ctx, db, vm)
	if err != nil {
		return true
	}
	if rec == nil || rec.Spec == "" {
		return false
	}
	spec := &pb.VMSpec{}
	if json.Unmarshal([]byte(rec.Spec), spec) != nil {
		return false
	}
	return specHasTrunk(spec)
}

// applyTapVLANs puts the VLANs of vm's NICs on its taps here: an access port's
// VLAN as its only one, pvid, untagged; a trunk's VLANs tagged, and no others
// (libvirt.Client.ConfigureVLANTap, NegotiateTrunkVLANs). Each converges from
// a read, so a tap already right is not written.
//
// An access port that cannot be configured is an error: its guest would run
// on VLAN 1. A trunk that cannot be is logged: its guest loses only the VLANs
// it was to carry, and the next pass of ConvergeTapVLANs tries again.
func (s *Server) applyTapVLANs(ctx context.Context, vm string) error {
	if s.virt == nil {
		return nil
	}
	nics, err := s.tapVLANsOf(ctx, vm)
	if err != nil {
		return err
	}
	return s.applyTapVLANNICs(vm, nics)
}

func (s *Server) applyTapVLANNICs(vm string, nics []tapVLANNIC) error {
	var errs []error
	for _, n := range nics {
		if n.access() {
			if err := s.virt.ConfigureVLANTap(vm, n.Bridge, n.MAC, n.VLANs[0]); err != nil {
				errs = append(errs, fmt.Errorf("put NIC %s on VLAN %d: %w", n.MAC, n.VLANs[0], err))
			}
			continue
		}
		if err := s.virt.NegotiateTrunkVLANs(vm, n.Bridge, n.MAC, n.VLANs); err != nil {
			slog.Warn("VLAN trunk tap config failed; the guest lacks those VLANs until the next convergence",
				"vm", vm, "mac", n.MAC, "vlans", n.VLANs, "error", err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("the access-VLAN NICs of %s could not be put on their VLANs on %s, so it is not run here: %w",
			vm, s.hostName, errors.Join(errs...))
	}
	return nil
}

// readyGuestHere is what must hold on this host before vm's guest runs here,
// for a start (NICStartGuard, once the domain exists paused) and for a guest
// that arrived paused (resumeHeld, ArmNICFirewall's resume, a live firmware
// move's release, an adopted hold): its NIC firewall in force (ArmNICsFor),
// then its NICs' VLANs on its taps (applyTapVLANs). Every resume of a guest
// that came here from elsewhere calls it before the resume
// (TestResumesOfAMovedGuestGoThroughReadyGuestHere).
func (s *Server) readyGuestHere(ctx context.Context, vm string) error {
	actx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.ArmNICsFor(actx, vm); err != nil {
		return err
	}
	return s.applyTapVLANs(actx, vm)
}

// TapVLANConvergeInterval is how often ConvergeTapVLANs runs.
const TapVLANConvergeInterval = 30 * time.Second

// ConvergeTapVLANs puts the VLANs of every guest active on this host back on
// its taps, from its stored spec: a tap a path missed, or one changed behind
// litevirt's back (`bridge vlan add` by hand, a bridge re-created), is put
// right within one interval. Each tap is read first and only written when it
// is wrong (configureAccessBridgeVLAN), so a converged host costs one read
// per VLAN NIC. A failure is logged and tried again next interval.
func (s *Server) ConvergeTapVLANs(ctx context.Context) {
	if s.virt == nil || s.db == nil {
		return
	}
	// Every VM row with a trunk NIC, whichever host it names: a guest held
	// paused here by a move it is still finishing has another host's row.
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		slog.Warn("tap VLANs: cannot list the VMs; not converging this pass", "error", err)
		return
	}
	for i := range vms {
		if ctx.Err() != nil {
			return
		}
		vm := &vms[i]
		if vm.IsTemplate {
			continue
		}
		// The spec first, which is local: libvirt is asked only about a VM
		// with a trunk NIC, not about every VM of the cluster.
		nics, err := s.tapVLANsOfRecord(ctx, vm)
		if err != nil {
			slog.Warn("tap VLANs: cannot read a VM's NICs; not converging it this pass", "vm", vm.Name, "error", err)
			continue
		}
		if len(nics) == 0 {
			continue
		}
		if active, err := s.virt.DomainIsActive(vm.Name); err != nil || !active {
			continue // not defined here, or not running
		}
		if err := s.applyTapVLANNICs(vm.Name, nics); err != nil {
			slog.Error("tap VLANs: a running guest's access-VLAN NIC is not on its VLAN; retrying next pass", "vm", vm.Name, "error", err)
		}
	}
}
