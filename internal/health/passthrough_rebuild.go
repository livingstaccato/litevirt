package health

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// The reconciler rebuilds a VM's domain from its stored spec: after a
// failover, and whenever it finds the domain not running under a running row.
// The spec's PCI passthrough devices are a claim on this host's hardware,
// which the reconciler cannot make itself; the daemon wires the gRPC
// server's PassthroughForRebuild (SetPassthroughForRebuild).
//
// Before hardware_v2 latches, the hook claims and binds a device of the kind
// each spec names on this host, and the domain is built with them. A VM
// whose devices this host cannot give it is not started: it is not "running"
// without its GPU. After the latch the start preflight does that work
// (PrepareHardwareForStart), and the hook only decides whether an opted-in
// VM starts without them.

// PassthroughRebuild is what the hook decided for one rebuild.
type PassthroughRebuild struct {
	// Addresses are the PCI devices the domain is built with, claimed and
	// bound for this start.
	Addresses []string
	// Dropped, when not empty, is why the VM starts without its PCI
	// passthrough devices: its spec opts in to that
	// (corrosion.LabelFailoverWithoutDevices) and this host has none for it.
	Dropped string
	// Done is called once the start is decided: started false gives back
	// what was claimed for it. nil: nothing to do.
	Done func(started bool)
}

func (p PassthroughRebuild) done(started bool) {
	if p.Done != nil {
		p.Done(started)
	}
}

// SetPassthroughForRebuild wires the PCI passthrough hook. nil: a rebuilt
// domain has no PCI hostdevs, as before.
func (r *Reconciler) SetPassthroughForRebuild(fn func(ctx context.Context, vm *corrosion.VMRecord) (PassthroughRebuild, error)) {
	r.passthroughForRebuild = fn
}

func (r *Reconciler) rebuildPassthrough(ctx context.Context, vm *corrosion.VMRecord) (PassthroughRebuild, error) {
	if r.passthroughForRebuild == nil {
		return PassthroughRebuild{}, nil
	}
	return r.passthroughForRebuild(ctx, vm)
}

// reportPassthroughDropped records that vm runs here without its PCI
// passthrough devices: in its state detail, which a running row otherwise
// reads as a VM with all of its hardware, and as a warning event.
func (r *Reconciler) reportPassthroughDropped(ctx context.Context, vm, why string) {
	detail := "running without its PCI passthrough devices: " + why
	slog.Warn("reconciler: "+detail, "vm", vm)
	if err := r.publishRunning(ctx, vm, "running", func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, r.db, vm, "running", detail)
	}); err != nil {
		LogPublishRefusal("reconciler: the running-without-devices detail was not written", vm, err)
		r.noteStateWriteFail(corrosion.OpVMState, err)
	}
	if err := corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vm, HostName: r.hostName, Type: "vm.passthrough_dropped",
		Result: "ok", Severity: "warn", Detail: detail, Username: "reconciler",
	}); err != nil {
		slog.Warn("reconciler: record the running-without-devices event", "vm", vm, "error", err)
	}
}

type passthroughDroppedKey struct{}

// WithPassthroughDropped marks ctx as the start of a VM that starts without
// its PCI passthrough devices, by its own opt-in: the hardware pre-start
// does not realize them.
func WithPassthroughDropped(ctx context.Context) context.Context {
	return context.WithValue(ctx, passthroughDroppedKey{}, true)
}

// PassthroughDropped reports whether ctx is such a start.
func PassthroughDropped(ctx context.Context) bool {
	v, _ := ctx.Value(passthroughDroppedKey{}).(bool)
	return v
}
