package firewall

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Arming is the set of VMs whose NICs this host renders ahead of what its
// rows say: a VM about to start or migrate in here (its row may still name the
// host it comes from), and NICs whose rows are not written yet (a create or a
// hot-attach writes them after the NIC is live). The loader renders their NICs
// under the tap names their MACs fix (nictap.Name), so the guard is in force
// before the guest's first frame (re-review I-10).
//
// An armed VM stays armed for armTTL — long enough for any start or migration
// to finish, after which its row says where it runs. One that arrived here and
// then left (its row names another host, nothing of it runs here) is disarmed
// by Settle at once.
type Arming struct {
	mu        sync.Mutex
	armed     map[string]time.Time
	arrived   map[string]bool   // armed VMs whose row named this host while they ran here
	gen       map[string]uint64 // bumped by every Arm and SetPending of a VM
	genSeq    uint64
	pending   map[string][]corrosion.HostVMNIC
	pendingCT map[string][]corrosion.ContainerInterfaceRecord
	now       func() time.Time
}

const armTTL = 30 * time.Minute

// NewArming returns an empty set.
func NewArming() *Arming {
	return &Arming{armed: map[string]time.Time{}, arrived: map[string]bool{}, gen: map[string]uint64{}, pending: map[string][]corrosion.HostVMNIC{},
		pendingCT: map[string][]corrosion.ContainerInterfaceRecord{}, now: time.Now}
}

// SetPendingContainer records the NICs of a container being created, before
// its rows exist; ClearPendingContainer forgets them.
func (a *Arming) SetPendingContainer(ct string, nics []corrosion.ContainerInterfaceRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pendingCT[ct] = append([]corrosion.ContainerInterfaceRecord(nil), nics...)
}

// ClearPendingContainer forgets a container's pending NICs.
func (a *Arming) ClearPendingContainer(ct string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.pendingCT, ct)
}

// PendingContainers is every pending container NIC.
func (a *Arming) PendingContainers() []corrosion.ContainerInterfaceRecord {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	names := make([]string, 0, len(a.pendingCT))
	for n := range a.pendingCT {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []corrosion.ContainerInterfaceRecord
	for _, n := range names {
		out = append(out, a.pendingCT[n]...)
	}
	return out
}

// Arm adds vm to the set.
func (a *Arming) Arm(vm string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.armed[vm] = a.now().Add(armTTL)
	a.restampLocked(vm)
}

// restampLocked gives vm a new generation and forgets that it arrived: what a
// pass read before this call says nothing about the arming made by it.
func (a *Arming) restampLocked(vm string) {
	a.genSeq++
	a.gen[vm] = a.genSeq
	delete(a.arrived, vm)
}

// Generations is each armed VM's generation now. Read it before the row and
// tap snapshots Settle is given.
func (a *Arming) Generations() map[string]uint64 {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]uint64, len(a.gen))
	for k, v := range a.gen {
		out[k] = v
	}
	return out
}

// Disarm removes vm.
func (a *Arming) Disarm(vm string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.armed, vm)
	delete(a.arrived, vm)
	delete(a.gen, vm)
}

// Settle disarms every armed VM that arrived here (a pass saw its row name
// here) and whose row now names another host, once it no longer runs here.
// rowHost is the host each armed VM's row names (a VM with no row is absent
// and left alone); runsHere says whether libvirt has the VM's NICs running on
// this host. A VM still running here, or one whose migration in has not landed
// yet, stays armed until armTTL.
//
// A VM is arrived only when its row names here AND it runs here. Settle skips
// a VM armed again since gens was read (an Arm after the snapshots makes both
// stale).
func (a *Arming) Settle(here string, gens map[string]uint64, rowHost map[string]string, runsHere func(vm string) bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for vm := range a.armed {
		h, ok := rowHost[vm]
		if g, seen := gens[vm]; !seen || g != a.gen[vm] {
			continue
		}
		switch {
		case !ok:
		case h == here:
			if runsHere(vm) {
				a.arrived[vm] = true
			}
		case a.arrived[vm] && !runsHere(vm):
			delete(a.armed, vm)
			delete(a.arrived, vm)
			delete(a.pending, vm)
			delete(a.gen, vm)
		}
	}
}

// SetPending records vm's NICs whose rows are not written yet; ClearPending
// forgets them once they are (or the create failed).
func (a *Arming) SetPending(vm string, nics []corrosion.HostVMNIC) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending[vm] = append([]corrosion.HostVMNIC(nil), nics...)
	a.armed[vm] = a.now().Add(armTTL)
	a.restampLocked(vm)
}

// ClearPending forgets vm's pending NICs.
func (a *Arming) ClearPending(vm string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.pending, vm)
}

// Armed is the armed VMs, sorted; expired ones are dropped.
func (a *Arming) Armed() []string {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	var out []string
	for vm, until := range a.armed {
		if now.After(until) {
			delete(a.armed, vm)
			delete(a.arrived, vm)
			delete(a.gen, vm)
			delete(a.pending, vm)
			continue
		}
		out = append(out, vm)
	}
	sort.Strings(out)
	return out
}

// Pending is every pending NIC.
func (a *Arming) Pending() []corrosion.HostVMNIC {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []corrosion.HostVMNIC
	vms := make([]string, 0, len(a.pending))
	for vm := range a.pending {
		vms = append(vms, vm)
	}
	sort.Strings(vms)
	for _, vm := range vms {
		out = append(out, a.pending[vm]...)
	}
	return out
}

// SetArming wires the set the loader reads (LoaderOptions.Arming) into the
// reconciler, for Arm and SetPending.
func (r *Reconciler) SetArming(a *Arming) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.arming = a
}

// Arm puts vm's NIC firewall in force here now: it arms vm and waits for a
// pass that started after it did. Passes are coalesced — every Arm that
// arrives while one runs shares the next (re-review m3) — and each sends the
// tables even when they render as last time, since the kernel's copy may have
// been flushed out of band (m9). The error is the pass's, a refused per-NIC
// table included; GuardsInForce says whether the VM's guards made it.
func (r *Reconciler) Arm(ctx context.Context, vm string) error {
	r.mu.Lock()
	a := r.arming
	r.mu.Unlock()
	if a != nil {
		a.Arm(vm)
	}
	r.armMu.Lock()
	if r.armNext == nil {
		r.armNext = &armRound{done: make(chan struct{})}
	}
	round := r.armNext
	if r.armRunning == nil {
		r.startArmRoundLocked()
	}
	r.armMu.Unlock()
	select {
	case <-round.done:
		return round.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// startArmRoundLocked runs armNext. Caller holds armMu.
func (r *Reconciler) startArmRoundLocked() {
	round := r.armNext
	r.armRunning, r.armNext = round, nil
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		round.err = r.ReconcileForce(ctx)
		cancel()
		close(round.done)
		r.armMu.Lock()
		r.armRunning = nil
		if r.armNext != nil {
			r.startArmRoundLocked()
		}
		r.armMu.Unlock()
	}()
}

// GuardsInForce reports whether the per-NIC table last applied holds the
// guard of every MAC of workload in macs.
func (r *Reconciler) GuardsInForce(workload string, macs []string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.NICTableError != "" {
		return false
	}
	for _, m := range macs {
		if !r.state.Guarded[workload][strings.ToLower(m)] {
			return false
		}
	}
	return true
}

// SetPending records NICs of vm whose rows are not written yet (Arming).
func (r *Reconciler) SetPending(vm string, nics []corrosion.HostVMNIC) {
	r.mu.Lock()
	a := r.arming
	r.mu.Unlock()
	if a != nil {
		a.SetPending(vm, nics)
	}
}

// SetPendingContainer records a container's NICs before its rows exist.
func (r *Reconciler) SetPendingContainer(ct string, nics []corrosion.ContainerInterfaceRecord) {
	r.mu.Lock()
	a := r.arming
	r.mu.Unlock()
	if a != nil {
		a.SetPendingContainer(ct, nics)
	}
}

// ClearPendingContainer forgets a container's pending NICs.
func (r *Reconciler) ClearPendingContainer(ct string) {
	r.mu.Lock()
	a := r.arming
	r.mu.Unlock()
	if a != nil {
		a.ClearPendingContainer(ct)
	}
}

// ClearPending forgets vm's pending NICs.
func (r *Reconciler) ClearPending(vm string) {
	r.mu.Lock()
	a := r.arming
	r.mu.Unlock()
	if a != nil {
		a.ClearPending(vm)
	}
}
