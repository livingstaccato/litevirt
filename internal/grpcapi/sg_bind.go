package grpcapi

import (
	"context"
	"log/slog"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// BindSecurityGroups replaces the SG name list on one VM NIC. The
// firewall reconciler on every host re-renders its ruleset on the
// next 30s tick (or immediately via ReloadFirewall). RBAC: requires
// the network.update verb on the VM's path.
//
// this is the runtime entry point that lets operators
// adjust SG bindings without redeploying a stack — useful for
// incident response (drop a compromised VM into an isolation SG).
func (s *Server) BindSecurityGroups(ctx context.Context, req *pb.BindSecurityGroupsRequest) (*emptypb.Empty, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" || req.NetworkName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name and network_name required")
	}
	// Authorize against the VM's REAL project, which only its row can name. A
	// node that does not hold the row — it is still replicating, or the VM does
	// not exist — never authorizes on a guess (requirePermResolved). It used to
	// guess _default, so a caller whose only grant was on _default passed the
	// check for a VM in any other project, and the zero-row UPDATE that followed
	// was relayed to every node that does hold the row, which applied it. The
	// refusal is retryable: a replicating row arrives, and the retry is judged
	// against its project.
	vm, gerr := corrosion.GetVM(ctx, s.db, req.VmName)
	if gerr != nil {
		return nil, status.Errorf(codes.Unavailable, "look up vm %q: %v", req.VmName, gerr)
	}
	path := ""
	if vm != nil {
		path = vmRBACPath(vm)
	}
	if err := s.requirePermResolved(ctx, vm != nil, path, vmRBACPathFor("", req.VmName),
		"network.update", "operator", "vm "+strconv.Quote(req.VmName)); err != nil {
		return nil, err
	}
	// The binding this replaces is read first. This RPC is how an operator pulls
	// a compromised VM into an isolation group — or takes it out of one — so the
	// audit row has to be able to say which groups the NIC left
	// (colonelpanik/litevirt#182).
	//
	// It is read through the vm_nics/vm_interfaces overlay, the view the
	// firewall reconciler renders from. A NIC hot-attached after the
	// hardware_v2 latch has no vm_interfaces row at all, so a bind that wrote
	// only vm_interfaces updated nothing there and still answered OK.
	nics, nerr := corrosion.MergedVMNICs(ctx, s.db, req.VmName)
	if nerr != nil {
		s.audit(ctx, "sg.bind", req.VmName, "network="+req.NetworkName+" "+
			corrosion.AuditChange(corrosion.AuditUnknown(nerr), corrosion.AuditSGList(req.SecurityGroups)), "error")
		return nil, status.Errorf(codes.Unavailable, "read the NICs of vm %q: %v", req.VmName, nerr)
	}
	var matched []corrosion.NICRecord
	for _, n := range nics {
		if n.NetworkName == req.NetworkName {
			matched = append(matched, n)
		}
	}
	if len(matched) == 0 {
		s.audit(ctx, "sg.bind", req.VmName, "network="+req.NetworkName+" "+
			corrosion.AuditChange(corrosion.AuditStateNone, corrosion.AuditSGList(req.SecurityGroups)), "error")
		return nil, status.Errorf(codes.FailedPrecondition,
			"vm %q has no NIC on network %q; nothing to bind", req.VmName, req.NetworkName)
	}
	before := corrosion.AuditSGList(corrosion.DecodeSecurityGroups(matched[0].SecurityGroups))
	// The legacy row first, for peers on an older build (they render from
	// vm_interfaces only); a NIC without one makes this a no-op. Then each
	// matching vm_nics row, rewritten whole through the existing UpsertNIC
	// shape. Written last, the vm_nics row is the newer of the two, so the
	// hardware bridge — which copies a strictly newer legacy row over it —
	// leaves it alone, and the reconciler sees the bind on its next pass.
	change := "network=" + req.NetworkName + " " + corrosion.AuditChange(before, corrosion.AuditSGList(req.SecurityGroups))
	if err := corrosion.SetInterfaceSecurityGroups(ctx, s.db,
		req.VmName, req.NetworkName, req.SecurityGroups); err != nil {
		s.audit(ctx, "sg.bind", req.VmName, change, "error")
		return nil, status.Errorf(codes.Internal, "update binding: %v", err)
	}
	sgsJSON := encodeSecurityGroups(req.SecurityGroups)
	for _, n := range matched {
		n.SecurityGroups = sgsJSON
		if err := corrosion.UpsertNIC(ctx, s.db, n); err != nil {
			s.audit(ctx, "sg.bind", req.VmName, change, "error")
			return nil, status.Errorf(codes.Internal, "update binding of NIC %s: %v", n.MAC, err)
		}
	}
	s.audit(ctx, "sg.bind", req.VmName, change, "ok")
	slog.Info("vm-nic security groups updated",
		"vm", req.VmName, "network", req.NetworkName,
		"sgs", req.SecurityGroups, "by", callerUsername(ctx))
	return &emptypb.Empty{}, nil
}
