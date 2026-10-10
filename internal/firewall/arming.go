package firewall

import (
	"context"
	"sort"
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
// to finish, after which its row says where it runs.
type Arming struct {
	mu      sync.Mutex
	armed   map[string]time.Time
	pending map[string][]corrosion.HostVMNIC
	now     func() time.Time
}

const armTTL = 30 * time.Minute

// NewArming returns an empty set.
func NewArming() *Arming {
	return &Arming{armed: map[string]time.Time{}, pending: map[string][]corrosion.HostVMNIC{}, now: time.Now}
}

// Arm adds vm to the set.
func (a *Arming) Arm(vm string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.armed[vm] = a.now().Add(armTTL)
}

// Disarm removes vm.
func (a *Arming) Disarm(vm string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.armed, vm)
}

// SetPending records vm's NICs whose rows are not written yet; ClearPending
// forgets them once they are (or the create failed).
func (a *Arming) SetPending(vm string, nics []corrosion.HostVMNIC) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending[vm] = append([]corrosion.HostVMNIC(nil), nics...)
	a.armed[vm] = a.now().Add(armTTL)
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

// Arm puts vm's NIC firewall in force here now: it arms vm and runs a pass.
// The error is the pass's — a refused per-NIC table included — so a caller
// can refuse to run a guarded VM unguarded.
func (r *Reconciler) Arm(ctx context.Context, vm string) error {
	r.mu.Lock()
	a := r.arming
	r.mu.Unlock()
	if a != nil {
		a.Arm(vm)
	}
	return r.Reconcile(ctx)
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

// ClearPending forgets vm's pending NICs.
func (r *Reconciler) ClearPending(vm string) {
	r.mu.Lock()
	a := r.arming
	r.mu.Unlock()
	if a != nil {
		a.ClearPending(vm)
	}
}
