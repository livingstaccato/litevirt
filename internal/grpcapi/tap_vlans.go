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
	"github.com/litevirt/litevirt/internal/network"
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
	Network string
	Bridge  string
	MAC     string
	// VLANs: one is an access port on it (pvid, untagged, and nothing
	// else); more is a trunk carrying them tagged.
	VLANs []int
}

func (n tapVLANNIC) access() bool { return len(n.VLANs) == 1 }

// pendingTapVLANs is the tap VLANs of a guest a start on this host is bringing
// up before its row is written (a create, a clone, a restore, a renamed
// promotion), so the start guard can put them on: vm name -> *pendingVLANs.
type pendingVLANs struct {
	nics []tapVLANNIC
	// err: the NICs could not all be resolved (tapVLANNICs); the guard
	// refuses the start rather than run an access NIC on VLAN 1.
	err error
}

// notePendingTapVLANs registers nics as vm's tap VLANs until the returned func
// runs (call it once the rows are written, or the start failed). A second
// note for the name does not take the first one's over.
func (s *Server) notePendingTapVLANs(vm string, nics []tapVLANNIC) func() {
	if vm == "" || len(nics) == 0 {
		return func() {}
	}
	return s.notePending(vm, &pendingVLANs{nics: nics})
}

func (s *Server) notePending(vm string, p *pendingVLANs) func() {
	if _, taken := s.pendingTapVLANs.LoadOrStore(vm, p); taken {
		return func() {}
	}
	return func() { s.pendingTapVLANs.CompareAndDelete(vm, p) }
}

// pendingTapVLANsFor is notePendingTapVLANs from a spec not yet stored: each
// NIC with a trunk, on the bridge its network resolves to here, with the MAC
// the spec or recs (by ordinal) gives it. An access NIC that cannot be
// resolved is registered as an error, which refuses the start.
func (s *Server) pendingTapVLANsFor(ctx context.Context, vm string, spec *pb.VMSpec, recs []corrosion.InterfaceRecord) func() {
	nics, err := tapVLANNICs(ctx, s.db, spec, recs)
	if vm == "" || (len(nics) == 0 && err == nil) {
		return func() {}
	}
	return s.notePending(vm, &pendingVLANs{nics: nics, err: err})
}

// tapVLANNICs is each NIC of spec with a trunk, with its bridge here and its
// MAC (the spec's, else the one recs gives its ordinal). A NIC on a direct
// (macvtap) network has no tap on a bridge, and is left out. An access NIC
// with no MAC or no bridge is an error (review NB-R2): its VLAN could not be
// put on, and its guest would run on VLAN 1. A trunk NIC like that is left out
// (its guest only lacks the VLANs).
func tapVLANNICs(ctx context.Context, db *corrosion.Client, spec *pb.VMSpec, recs []corrosion.InterfaceRecord) ([]tapVLANNIC, error) {
	var out []tapVLANNIC
	var errs []error
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
		if strings.HasPrefix(bridge, "direct:") {
			continue
		}
		if mac == "" || bridge == "" {
			if len(n.GetTrunk()) == 1 {
				errs = append(errs, fmt.Errorf("NIC %d on network %s (VLAN %d): its MAC or bridge cannot be resolved, so its VLAN cannot be put on its tap",
					i, n.GetName(), n.GetTrunk()[0]))
			}
			continue
		}
		vlans := make([]int, len(n.GetTrunk()))
		for j, v := range n.GetTrunk() {
			vlans[j] = int(v)
		}
		out = append(out, tapVLANNIC{Network: n.GetName(), Bridge: bridge, MAC: mac, VLANs: vlans})
	}
	return out, errors.Join(errs...)
}

// tapVLANsOf is the tap VLANs of vm's NICs here: a start's pending ones, else
// from its stored spec. A VM with no row, or a spec that cannot be read, has
// none. An error: its row could not be read, or an access NIC of it cannot be
// resolved (tapVLANNICs).
func (s *Server) tapVLANsOf(ctx context.Context, vm string) ([]tapVLANNIC, error) {
	if p, ok := s.pendingTapVLANs.Load(vm); ok {
		pv := p.(*pendingVLANs)
		return pv.nics, pv.err
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
	return tapVLANNICs(ctx, s.db, spec, ifaces)
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

// guestComing is how a guest comes to run here, for applyTapVLANNICs.
type guestComing int

const (
	// startingHere: a start, whatever path asked for it. An access NIC's
	// bridge here must filter VLANs.
	startingHere guestComing = iota
	// arrivedHere: a guest moved here (a hand-over, a firmware move's
	// release, an adopted hold) or already running here (the convergence).
	// Its network's opt-in to unfiltered moves
	// (NetworkDef.AllowUnfilteredAccessVLANMoves) lets it run on a bridge
	// that does not filter VLANs.
	arrivedHere
)

// applyTapVLANs puts the VLANs of vm's NICs on its taps here: an access port's
// VLAN as its only one, pvid, untagged; a trunk's VLANs tagged, and no others
// (libvirt.Client.ConfigureVLANTap, NegotiateTrunkVLANs). Each converges from
// a read, so a tap already right is not written. For a guest that already
// runs or arrived here (arrivedHere).
func (s *Server) applyTapVLANs(ctx context.Context, vm string) error {
	return s.applyTapVLANsComing(ctx, vm, arrivedHere)
}

func (s *Server) applyTapVLANsComing(ctx context.Context, vm string, how guestComing) error {
	if s.virt == nil {
		return nil
	}
	nics, err := s.tapVLANsOf(ctx, vm)
	if err != nil {
		return fmt.Errorf("the NIC VLANs of %s cannot be put on its taps on %s, so it is not run here: %w", vm, s.hostName, err)
	}
	return s.applyTapVLANNICs(ctx, vm, nics, how)
}

// applyTapVLANNICs puts nics' VLANs on vm's taps. An access port is refused
// when its bridge here does not filter VLANs (network.AccessVLANBridgeProblem:
// the pvid would be ignored, and the guest would be on the bridge's untagged
// segment) — on every start, by whatever path (review R-B2), and for a guest
// that arrived here unless its network allows unfiltered moves — or when its
// tap cannot be configured: its guest would run on VLAN 1. A trunk that
// cannot be configured is logged: its guest loses only the VLANs it was to
// carry, and the next pass of ConvergeTapVLANs tries again.
func (s *Server) applyTapVLANNICs(ctx context.Context, vm string, nics []tapVLANNIC, how guestComing) error {
	var errs []error
	for _, n := range nics {
		if n.access() {
			if problem := network.AccessVLANBridgeProblem(n.Bridge, n.VLANs[0], s.bridgeVLANFilteringOf); problem != nil {
				if how != arrivedHere || !s.networkAllowsUnfilteredMoves(ctx, n.Network) {
					errs = append(errs, problem)
					continue
				}
				slog.Warn("tap VLANs: an access-VLAN NIC runs here on a bridge that does not carry its VLAN, on its untagged segment: "+
					"its network allows unfiltered moves", "vm", vm, "network", n.Network, "problem", problem)
			}
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

// networkAllowsUnfilteredMoves reports whether network name allows moving its
// access-VLAN VMs onto bridges that do not filter VLANs; false when its row
// cannot be read.
func (s *Server) networkAllowsUnfilteredMoves(ctx context.Context, name string) bool {
	def, err := lookupNetworkDef(ctx, s.db, name)
	return err == nil && def != nil && def.AllowUnfilteredAccessVLANMoves
}

// readyGuestHere is what must hold on this host before vm's guest runs here,
// for a start (NICStartGuard, once the domain exists paused: startingHere)
// and for a guest that arrived paused (resumeHeld, ArmNICFirewall's resume, a
// live firmware move's release, an adopted hold: arrivedHere): its NIC
// firewall in force (ArmNICsFor), then its NICs' VLANs on its taps, an access
// NIC's bridge filtering VLANs (applyTapVLANNICs). Every resume in this
// package calls it before the resume
// (TestResumesOfAMovedGuestGoThroughReadyGuestHere).
func (s *Server) readyGuestHere(ctx context.Context, vm string, how guestComing) error {
	actx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.ArmNICsFor(actx, vm); err != nil {
		return err
	}
	return s.applyTapVLANsComing(actx, vm, how)
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
		if err := s.applyTapVLANNICs(ctx, vm.Name, nics, arrivedHere); err != nil {
			slog.Error("tap VLANs: a running guest's access-VLAN NIC is not on its VLAN; retrying next pass", "vm", vm.Name, "error", err)
		}
	}
}
