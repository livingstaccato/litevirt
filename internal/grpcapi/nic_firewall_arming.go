package grpcapi

// Putting a VM's per-NIC firewall — its NIC guards above all — in force on
// this host before the VM's first frame here (re-review I-10). A NIC litevirt
// defines names its tap after its MAC (nictap), so the firewall can render it
// before it runs; the daemon arms a VM in the libvirt before-start hook
// (every start: API, restart policy, failover reschedule, restore), and a
// migration source asks the target to arm it before handing the guest over.

import (
	"context"
	"errors"
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
	"github.com/litevirt/litevirt/internal/firewall"
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
// m3). A VM with no guard starts as it did before guards (m3): no pass is run
// or waited for ahead of it, and the next tick renders its NICs.
func (s *Server) ArmNICsFor(ctx context.Context, vm string) error {
	return s.armWorkload(ctx, vm, func() ([]string, error) { return s.guardedMACs(ctx, vm) })
}

// armWorkload puts the workload the table names display in force here, when
// guarded (its guarded MACs, read by macs) says it has a guard.
func (s *Server) armWorkload(ctx context.Context, display string, macs func() ([]string, error)) error {
	a, ok := s.fwRec().(nicArmer)
	if !ok || display == "" {
		return nil
	}
	guarded, gerr := macs()
	switch {
	case gerr != nil:
		return fmt.Errorf("whether %s has NIC guards could not be read, so it is not run here: %w", display, gerr)
	case len(guarded) == 0:
		return nil
	}
	err := a.Arm(ctx, display)
	if f, ok := a.(guardsInForcer); ok {
		if f.GuardsInForce(display, guarded) {
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
	if err := s.armWorkload(ctx, name, func() ([]string, error) { return s.containerGuardedMACs(ctx, name) }); err != nil {
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return s.containerRuntime.StartContainer(ctx, name)
}

// containerGuardedMACs is the MACs of this host's container name whose guard
// is on, resolved as the loader resolves them (firewall.ContainerGuard): the
// record this host wrote, or, for a NIC of a container that migrated or was
// relocated here, the record its earlier host wrote (re-review m1).
func (s *Server) containerGuardedMACs(ctx context.Context, name string) ([]string, error) {
	all, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	add := func(mac string) {
		mac = strings.ToLower(mac)
		if !seen[mac] {
			seen[mac] = true
			out = append(out, mac)
		}
	}
	own := corrosion.ContainerGuardOwner(s.hostName, name)
	for _, r := range all {
		if r.VMName == own && r.Guarded() {
			add(r.MAC)
		}
	}
	nics, err := corrosion.GetContainerInterfaces(ctx, s.db, s.hostName, name)
	if err != nil {
		return nil, err
	}
	// A NIC whose rows are not written yet is a create's, whose records are
	// this host's own (above).
	for _, n := range nics {
		if rec, ok := firewall.ContainerGuard(all, s.hostName, name, n.MAC); ok && rec.Guarded() {
			add(n.MAC)
		}
	}
	sort.Strings(out)
	return out, nil
}

// vmGuarded reports whether any NIC of vm has its guard on.
func (s *Server) vmGuarded(ctx context.Context, vm string) (bool, error) {
	macs, err := s.guardedMACs(ctx, vm)
	return len(macs) > 0, err
}

// guardedMACs is the MACs of owner's NICs whose guard is on
// (corrosion.GuardedMACsOf).
func (s *Server) guardedMACs(ctx context.Context, owner string) ([]string, error) {
	return corrosion.GuardedMACsOf(ctx, s.db, owner)
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
// handing the guest over, and, for a guest handed over paused, after. Peer
// only.
func (s *Server) ArmNICFirewall(ctx context.Context, req *pb.ArmNICFirewallRequest) (*emptypb.Empty, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.GetVmName() == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}
	if req.GetResume() {
		// The guest arrived paused: its guards in force under the taps it got
		// here, then it runs (resumeHeld). A guest this host does not hold —
		// a source of an earlier round, or a record lost — is armed and
		// resumed as before.
		err := s.resumeHeld(ctx, req.GetVmName())
		switch {
		case err == nil:
			return &emptypb.Empty{}, nil
		case !errors.Is(err, errNotHeld):
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		if st, serr := s.virt.DomainStateReason(req.GetVmName()); serr == nil && st.State == "running" {
			return &emptypb.Empty{}, nil // let run already (this host's resumer, or a retry)
		}
		if err := s.ArmNICsFor(ctx, req.GetVmName()); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		r, ok := s.virt.(interface{ ResumeDomain(string) error })
		if !ok {
			return nil, status.Error(codes.Unimplemented, "this host cannot resume a domain")
		}
		if err := r.ResumeDomain(req.GetVmName()); err != nil {
			return nil, status.Errorf(codes.Internal, "resume %s: %v", req.GetVmName(), err)
		}
		return &emptypb.Empty{}, nil
	}
	if req.GetPausedHandover() {
		// Before anything arrives: from here on this host owns letting the
		// guest run (re-review R3-I2), whatever becomes of the source.
		if err := s.holdForHandOver(ctx, req.GetVmName(), callerMTLSCommonName(ctx)); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition,
				"cannot record that %s will be held here for its NIC guards: %v", req.GetVmName(), err)
		}
	}
	if err := s.ArmNICsFor(ctx, req.GetVmName()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
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
// of its own makes the move hand the guest over paused — which the target
// records, so it lets the guest run itself if the source's resume never
// comes (R3-I2). Every live move — `lv migrate` and `lv host drain` — goes
// through it.
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

// Hand-over timing (re-review R3-I2): each resume attempt is bounded, and the
// source keeps trying until handOverDeadline; vars so tests can shorten them.
var (
	armCallTimeout   = 45 * time.Second // longer than the target's 30 s arm
	handOverBackoff  = time.Second
	handOverDeadline = 2 * time.Minute
)

// SetHandOverTimingForTests shortens the source's retry of a paused
// hand-over's resume; the returned func restores it.
func SetHandOverTimingForTests(backoff, deadline time.Duration) func() {
	ob, od := handOverBackoff, handOverDeadline
	handOverBackoff, handOverDeadline = backoff, deadline
	return func() { handOverBackoff, handOverDeadline = ob, od }
}

// finish lets a guest handed over paused run, its guards in force on the
// target first, retrying until handOverDeadline. An error means the guest is
// still held paused there; the target lets it run itself once its guards are
// in force, and says so in firewall.nic.held meanwhile.
func (am *armedMigration) finish(ctx context.Context) error {
	if am == nil || !am.paused {
		return nil
	}
	deadline := time.Now().Add(handOverDeadline)
	wait := handOverBackoff
	for {
		err := am.call(ctx, true)
		if err == nil {
			return nil
		}
		if time.Now().Add(wait).After(deadline) || ctx.Err() != nil {
			slog.Error("migrate: the guest arrived paused and its target could not put its NIC guards in force; "+
				"it stays paused there until they are", "vm", am.vm, "target", am.target.Name, "error", err)
			return fmt.Errorf("held paused on %s until its NIC guards are in force there (`lv firewall nic-guard resume %s`): %w",
				am.target.Name, am.vm, err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
		if wait *= 2; wait > 15*time.Second {
			wait = 15 * time.Second
		}
	}
}

func (am *armedMigration) call(ctx context.Context, resume bool) error {
	s := am.s
	conn, err := s.dialPeerAddr(peerTarget(am.target.Address, am.target.GRPCPort))
	if err != nil {
		if resume {
			return err // finish reports the hand-over
		}
		return s.armTargetFailed(ctx, am.vm, am.target.Name, err)
	}
	defer conn.Close()
	cctx, cancel := context.WithTimeout(ctx, armCallTimeout)
	defer cancel()
	_, err = pb.NewLiteVirtClient(conn).ArmNICFirewall(cctx, &pb.ArmNICFirewallRequest{
		VmName: am.vm, Resume: resume, PausedHandover: am.paused && !resume})
	if resume {
		return err
	}
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

// guardHostNeeded reports whether a placement of vm must land on a host that
// enforces NIC guards (corrosion.HostEnforcesNICGuards): until every host runs
// a build that knows them (the release latch), a guarded VM does — on any
// other it would run unguarded while `nic-guard ls` says on (re-review m8).
func (s *Server) guardHostNeeded(ctx context.Context, vm string) (bool, error) {
	if s.firewallReleaseActive() {
		return false, nil
	}
	return s.vmGuarded(ctx, vm)
}

// GuardHostNeeded is guardHostNeeded for a placement outside this package
// (failover.Coordinator.SetNICGuardPlacement); an unreadable answer requires
// such a host, which can only narrow the choice.
func (s *Server) GuardHostNeeded(ctx context.Context, vm string) bool {
	need, err := s.guardHostNeeded(ctx, vm)
	return need || err != nil
}

// requireGuardHost adds guardHostNeeded to a placement request.
func (s *Server) requireGuardHost(ctx context.Context, req *placement.Request, vm string) {
	if s.GuardHostNeeded(ctx, vm) {
		req.RequireNICGuards = true
	}
}

// refuseUnguardedTarget refuses an explicit target that guardHostNeeded rules
// out.
func (s *Server) refuseUnguardedTarget(ctx context.Context, vm string, target corrosion.HostRecord) error {
	need, err := s.guardHostNeeded(ctx, vm)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read the NIC guards of %s: %v", vm, err)
	}
	if need && !corrosion.HostEnforcesNICGuards(target) {
		return status.Errorf(codes.FailedPrecondition,
			"%s has NIC guards and host %s does not enforce them (an older build, or a kernel that refuses the per-NIC table): "+
				"it would run there unguarded; move it once every host runs this release", vm, target.Name)
	}
	return nil
}

// NICGuardLabelValue is the value a daemon of this build sets its host's
// corrosion.LabelNICGuards to at start (re-review m2): its own version —
// which a host rolled back to an older build no longer reports — or "" where
// the kernel refused the per-NIC table on the first pass, so no guard can be
// enforced here.
func NICGuardLabelValue(version string, st firewall.AppliedState) string {
	if st.NICTableError != "" {
		return ""
	}
	return version
}
