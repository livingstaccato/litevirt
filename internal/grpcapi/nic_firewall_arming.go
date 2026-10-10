package grpcapi

// Putting a VM's per-NIC firewall — its NIC guards above all — in force on
// this host before the VM's first frame here (re-review I-10). A NIC litevirt
// defines names its tap after its MAC (nictap), so the firewall can render it
// before it runs; the daemon arms a VM in the libvirt before-start hook
// (every start: API, restart policy, failover reschedule, restore), and a
// migration source asks the target to arm it before handing the guest over.

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/nictap"
	"github.com/litevirt/litevirt/internal/placement"
)

// nicArmer is what the daemon's firewall reconciler offers beyond
// FirewallReconciler (firewall.Arming); test fakes need not.
type nicArmer interface {
	Arm(ctx context.Context, vm string) error
	SetPending(vm string, nics []corrosion.HostVMNIC)
	ClearPending(vm string)
}

// guardsInForcer says whether a workload's guards are in the table in force
// (firewall.Reconciler.GuardsInForce).
type guardsInForcer interface {
	GuardsInForce(workload string, macs []string) bool
}

// pendingContainerArmer registers a container's NICs before its rows exist.
type pendingContainerArmer interface {
	SetPendingContainer(ct string, nics []corrosion.ContainerInterfaceRecord)
	ClearPendingContainer(ct string)
}

// ArmNICsFor puts vm's NIC firewall in force on this host now. It fails when
// vm has a NIC guard on that is not in force after the pass (or whether it has
// one could not be read): a guarded VM is not run unguarded. A pass that
// failed for another reason with the guards in force does not refuse (re-review
// m3). For a VM with no guard a failed pass is logged and the VM runs as it
// would have before guards.
func (s *Server) ArmNICsFor(ctx context.Context, vm string) error {
	return s.armWorkload(ctx, vm, vm)
}

// armWorkload arms the guard records of owner (a VM name or a
// ContainerGuardOwner) for the workload the table names display.
func (s *Server) armWorkload(ctx context.Context, owner, display string) error {
	a, ok := s.fwRec().(nicArmer)
	if !ok || owner == "" {
		return nil
	}
	err := a.Arm(ctx, display)
	macs, gerr := s.guardedMACs(ctx, owner)
	switch {
	case gerr != nil:
		return fmt.Errorf("whether %s has NIC guards could not be read, so it is not run here: %w", display, gerr)
	case len(macs) == 0:
		if err != nil {
			slog.Warn("firewall: could not put a workload's per-NIC rules in force before it runs; it has no NIC guard and runs as before",
				"workload", display, "error", err)
		}
		return nil
	}
	if f, ok := a.(guardsInForcer); ok {
		if f.GuardsInForce(display, macs) {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("its guards are not in the table in force")
		}
	}
	if err != nil {
		return fmt.Errorf("the NIC guards of %s could not be put in force on %s, so it is not run here: %w", display, s.hostName, err)
	}
	return nil
}

// startContainerArmed starts a container on this host through the runtime,
// its NIC firewall in force first: a guarded container whose guards are not
// is not started (re-review m10). Every container start goes through it.
func (s *Server) startContainerArmed(ctx context.Context, name string) error {
	if err := s.armWorkload(ctx, corrosion.ContainerGuardOwner(s.hostName, name), name); err != nil {
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return s.containerRuntime.StartContainer(ctx, name)
}

// vmGuarded reports whether any NIC of vm has its guard on.
func (s *Server) vmGuarded(ctx context.Context, vm string) (bool, error) {
	macs, err := s.guardedMACs(ctx, vm)
	return len(macs) > 0, err
}

// guardedMACs is the MACs of owner's NICs whose guard is on — only records of
// the incarnation that exists now: one an earlier VM of the same name left, or
// one tombstoned with its VM, guards nothing (re-review m1).
func (s *Server) guardedMACs(ctx context.Context, owner string) ([]string, error) {
	all, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		return nil, err
	}
	uuid := ""
	if vm, err := corrosion.GetVM(ctx, s.db, owner); err == nil && vm != nil {
		uuid = specUUID(vm.Spec)
	}
	var out []string
	for _, r := range all {
		if r.VMName != owner || !r.Guarded() {
			continue
		}
		if r.VMUUID != "" && uuid != "" && r.VMUUID != uuid {
			continue
		}
		out = append(out, strings.ToLower(r.MAC))
	}
	sort.Strings(out)
	return out, nil
}

// needsPausedStart reports whether vm has a guarded NIC whose definition names
// no tap of its own (a domain an older release defined: libvirt gives it
// vnetN at start), so its guard can only be put in force under that tap once
// the domain exists — paused (re-review R2-I4). live reads the running
// definition (a migration), else the persistent one (a start). An unreadable
// definition pauses.
func (s *Server) needsPausedStart(ctx context.Context, vm string, live bool) bool {
	macs, err := s.guardedMACs(ctx, vm)
	if err != nil || len(macs) == 0 {
		return err != nil
	}
	var x string
	if live {
		x, err = s.virt.DumpXML(vm)
	} else {
		x, err = s.virt.DumpXMLInactive(vm)
	}
	if err != nil {
		return true
	}
	targets := lv.InterfaceTargets(x)
	for _, m := range macs {
		if targets[m] != nictap.Name(m) {
			return true
		}
	}
	return false
}

// NICStartGuard is the libvirt start guard the daemon wires
// (libvirt.Client.SetStartGuard): every start of a VM first puts its NIC
// firewall in force — before the start under the tap name its MACs fix, or,
// for a guarded NIC that names no tap, while the domain is paused under the
// tap it got.
func (s *Server) NICStartGuard(ctx context.Context) lv.StartGuard {
	arm := func(name string) error {
		actx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return s.ArmNICsFor(actx, name)
	}
	return lv.StartGuard{
		Before: func(name string) (bool, error) {
			if s.needsPausedStart(ctx, name, false) {
				return true, nil
			}
			return false, arm(name)
		},
		AfterPaused: arm,
	}
}

// pendingNICs registers NICs of vm whose rows are not written yet, so the
// firewall renders them from the moment the domain starts; the returned func
// forgets them (call it once the rows are written, or the create failed).
func (s *Server) pendingNICs(vm, uuid string, recs []corrosion.InterfaceRecord, trunks map[int][]int) func() {
	a, ok := s.fwRec().(nicArmer)
	if !ok || len(recs) == 0 {
		return func() {}
	}
	nics := make([]corrosion.HostVMNIC, 0, len(recs))
	for _, r := range recs {
		nics = append(nics, corrosion.HostVMNIC{
			VMName: vm, VMState: "running", NetworkName: r.NetworkName, MAC: r.MAC, Ordinal: r.Ordinal,
			SecurityGroups: r.SecurityGroups, IP: r.IP, TrunkVIDs: trunks[r.Ordinal], VMUUID: uuid,
		})
	}
	a.SetPending(vm, nics)
	return func() { a.ClearPending(vm) }
}

// ArmNICFirewall is the RPC a migration source calls on the target before
// handing the guest over. Peer only.
func (s *Server) ArmNICFirewall(ctx context.Context, req *pb.ArmNICFirewallRequest) (*emptypb.Empty, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.GetVmName() == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}
	if err := s.ArmNICsFor(ctx, req.GetVmName()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if req.GetResume() {
		r, ok := s.virt.(interface{ ResumeDomain(string) error })
		if !ok {
			return nil, status.Error(codes.Unimplemented, "this host cannot resume a domain")
		}
		if err := r.ResumeDomain(req.GetVmName()); err != nil {
			return nil, status.Errorf(codes.Internal, "resume %s: %v", req.GetVmName(), err)
		}
	}
	return &emptypb.Empty{}, nil
}

// armedMigration is a live move's arming of its target.
type armedMigration struct {
	s      *Server
	target corrosion.HostRecord
	vm     string
	// paused: the guest is handed over paused and the target resumes it
	// once its guards are in force under the taps it got there (resume).
	paused bool
}

// armMigrationTarget prepares a live move of vm to target (re-review I-10,
// R2-I3, R2-I4, m8): the target must advertise NIC guards when vm is guarded
// and the release is not yet everywhere; it puts vm's NIC firewall in force
// before the guest arrives; and a guarded NIC whose definition names no tap
// of its own makes the move hand the guest over paused. Every live move —
// `lv migrate` and `lv host drain` — goes through it.
func (s *Server) armMigrationTarget(ctx context.Context, target *corrosion.HostRecord, vm string) (*armedMigration, error) {
	if err := s.refuseUnguardedTarget(ctx, vm, *target); err != nil {
		return nil, err
	}
	am := &armedMigration{s: s, target: *target, vm: vm, paused: s.needsPausedStart(ctx, vm, true)}
	if err := am.call(ctx, false); err != nil {
		return nil, err
	}
	return am, nil
}

// apply sets what the move needs in libvirt's parameters.
func (am *armedMigration) apply(p *lv.MigrateParams) {
	if am != nil {
		p.Paused = am.paused
	}
}

// finish lets a guest handed over paused run, its guards in force on the
// target first. A failure leaves it paused there.
func (am *armedMigration) finish(ctx context.Context) error {
	if am == nil || !am.paused {
		return nil
	}
	if err := am.call(ctx, true); err != nil {
		slog.Error("migrate: the guest arrived paused and its target could not put its NIC guards in force; it stays paused there",
			"vm", am.vm, "target", am.target.Name, "error", err)
		return err
	}
	return nil
}

func (am *armedMigration) call(ctx context.Context, resume bool) error {
	s := am.s
	conn, err := s.dialPeerAddr(peerTarget(am.target.Address, am.target.GRPCPort))
	if err != nil {
		return s.armTargetFailed(ctx, am.vm, am.target.Name, err)
	}
	defer conn.Close()
	_, err = pb.NewLiteVirtClient(conn).ArmNICFirewall(ctx, &pb.ArmNICFirewallRequest{VmName: am.vm, Resume: resume})
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.Unimplemented:
		// A target on a build without guards: refuseUnguardedTarget let it
		// through only for a VM with no guard, which needs nothing there.
		if g, gerr := s.vmGuarded(ctx, am.vm); gerr == nil && !g {
			return nil
		}
	}
	return s.armTargetFailed(ctx, am.vm, am.target.Name, err)
}

func (s *Server) armTargetFailed(ctx context.Context, vm, target string, cause error) error {
	if guarded, gerr := s.vmGuarded(ctx, vm); gerr == nil && !guarded {
		slog.Warn("migrate: the target could not put the VM's per-NIC rules in force ahead of it; it has no NIC guard, so it moves anyway",
			"vm", vm, "target", target, "error", cause)
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"the target %s could not put the NIC guards of %s in force before the guest arrives; not migrating: %v", target, vm, cause)
}

// guardHostLabels is the host label a placement of vm must require: until
// every host runs a build that knows NIC guards (the release latch), a
// guarded VM goes only to a host that advertises them (corrosion.
// LabelNICGuards) — on any other it would run unguarded while `nic-guard ls`
// says on (re-review m8).
func (s *Server) guardHostLabels(ctx context.Context, vm string) (map[string]string, error) {
	if s.firewallReleaseActive() {
		return nil, nil
	}
	g, err := s.vmGuarded(ctx, vm)
	if err != nil || !g {
		return nil, err
	}
	return map[string]string{corrosion.LabelNICGuards: "true"}, nil
}

// GuardHostLabels is guardHostLabels for a placement outside this package
// (failover.Coordinator.SetPlacementLabels); an unreadable answer requires
// the label, which can only narrow the choice.
func (s *Server) GuardHostLabels(ctx context.Context, vm string) map[string]string {
	labels, err := s.guardHostLabels(ctx, vm)
	if err != nil {
		return map[string]string{corrosion.LabelNICGuards: "true"}
	}
	return labels
}

// requireGuardHost adds guardHostLabels to a placement request.
func (s *Server) requireGuardHost(ctx context.Context, req *placement.Request, vm string) {
	labels, err := s.guardHostLabels(ctx, vm)
	if err != nil {
		// Unknown: require it, which can only narrow the choice.
		labels = map[string]string{corrosion.LabelNICGuards: "true"}
	}
	for k, v := range labels {
		if req.RequireLabels == nil {
			req.RequireLabels = map[string]string{}
		}
		req.RequireLabels[k] = v
	}
}

// refuseUnguardedTarget refuses an explicit target that guardHostLabels rules
// out.
func (s *Server) refuseUnguardedTarget(ctx context.Context, vm string, target corrosion.HostRecord) error {
	labels, err := s.guardHostLabels(ctx, vm)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read the NIC guards of %s: %v", vm, err)
	}
	for k, v := range labels {
		if target.Labels[k] != v {
			return status.Errorf(codes.FailedPrecondition,
				"%s has NIC guards and host %s does not advertise them (an older build): it would run there unguarded; "+
					"move it once every host runs this release", vm, target.Name)
		}
	}
	return nil
}
