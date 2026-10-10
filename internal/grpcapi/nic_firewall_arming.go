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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// nicArmer is what the daemon's firewall reconciler offers beyond
// FirewallReconciler (firewall.Arming); test fakes need not.
type nicArmer interface {
	Arm(ctx context.Context, vm string) error
	SetPending(vm string, nics []corrosion.HostVMNIC)
	ClearPending(vm string)
}

// ArmNICsFor puts vm's NIC firewall in force on this host now. It fails when
// vm has a NIC guard on and the guard could not be put in force (or whether it
// has one could not be read): a guarded VM is not run unguarded. For any other
// VM a failed pass is logged and the VM runs as it would have before guards.
func (s *Server) ArmNICsFor(ctx context.Context, vm string) error {
	a, ok := s.fwReconciler.(nicArmer)
	if !ok || vm == "" {
		return nil
	}
	err := a.Arm(ctx, vm)
	if err == nil {
		return nil
	}
	guarded, gerr := s.vmGuarded(ctx, vm)
	if gerr != nil || guarded {
		return fmt.Errorf("the NIC guards of %s could not be put in force on %s, so it is not run here: %w", vm, s.hostName, err)
	}
	slog.Warn("firewall: could not put a VM's per-NIC rules in force before it runs; it has no NIC guard and runs as before",
		"vm", vm, "error", err)
	return nil
}

// vmGuarded reports whether any NIC of vm has its guard on.
func (s *Server) vmGuarded(ctx context.Context, vm string) (bool, error) {
	all, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		return false, err
	}
	for _, r := range all {
		if r.VMName == vm && r.Guarded() {
			return true, nil
		}
	}
	return false, nil
}

// pendingNICs registers NICs of vm whose rows are not written yet, so the
// firewall renders them from the moment the domain starts; the returned func
// forgets them (call it once the rows are written, or the create failed).
func (s *Server) pendingNICs(vm string, recs []corrosion.InterfaceRecord, trunks map[int][]int) func() {
	a, ok := s.fwReconciler.(nicArmer)
	if !ok || len(recs) == 0 {
		return func() {}
	}
	nics := make([]corrosion.HostVMNIC, 0, len(recs))
	for _, r := range recs {
		nics = append(nics, corrosion.HostVMNIC{
			VMName: vm, VMState: "running", NetworkName: r.NetworkName, MAC: r.MAC, Ordinal: r.Ordinal,
			SecurityGroups: r.SecurityGroups, IP: r.IP, TrunkVIDs: trunks[r.Ordinal],
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
	return &emptypb.Empty{}, nil
}

// armMigrationTarget asks the target host to put vm's NIC firewall in force
// before the guest is handed over. A target on a build without the RPC has no
// NIC guards to put in force, and is not asked again. A target that cannot
// arm a guarded VM refuses the migration: the guest would arrive unguarded.
func (s *Server) armMigrationTarget(ctx context.Context, target *corrosion.HostRecord, vm string) error {
	conn, err := s.dialPeerAddr(peerTarget(target.Address, target.GRPCPort))
	if err != nil {
		return s.armTargetFailed(ctx, vm, target.Name, err)
	}
	defer conn.Close()
	_, err = pb.NewLiteVirtClient(conn).ArmNICFirewall(ctx, &pb.ArmNICFirewallRequest{VmName: vm})
	switch status.Code(err) {
	case codes.OK, codes.Unimplemented:
		return nil
	}
	return s.armTargetFailed(ctx, vm, target.Name, err)
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
