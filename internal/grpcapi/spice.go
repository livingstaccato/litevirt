package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetSpiceInfo returns the SPICE host:port for a running VM that has SPICE
// graphics enabled. Operators connect with `remote-viewer spice://<uri>`
// or any SPICE client (virt-manager, looking-glass, etc.).
//
// Unlike VNC, we do not currently proxy SPICE through the daemon — clients
// must reach the host's SPICE port directly. SPICE has a TCP-tunnel mode
// (`-T` in remote-viewer) that pairs well with an ordinary SSH port-forward
// to the host — there is no `lv` command for that, since the tunnel is to the
// HOST rather than to a VM (`lv ssh` connects to a VM). Bundling a
// browser-based SPICE client (spice-html5) is a future enhancement; this
// RPC is the minimum viable surface to make SPICE usable today.
//
// Because SPICE is not proxied, the response carries the console's password
// (docs/ui.md "Console passwords") for the client to present — to a caller
// that passed vm.console, and never logged.
func (s *Server) GetSpiceInfo(ctx context.Context, req *pb.GetSpiceInfoRequest) (*pb.GetSpiceInfoResponse, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	// SPICE is interactive console/graphics access to the guest; require
	// vm.console on the VM's tenancy project, checked on the entry host where
	// the caller identity is present (before any forward to the owning host).
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.console", "operator"); err != nil {
		return nil, err
	}
	if vm.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q is not running (state: %s)", req.VmName, vm.State)
	}

	// If the VM lives on another host, forward to that host's daemon. We
	// already authenticated; the inter-daemon mTLS handles the hop.
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.GetSpiceInfo(ctx, req)
	}

	port, err := s.virt.GetVMSpicePort(req.VmName)
	if err != nil || port < 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"SPICE not available for %q: %v", req.VmName, err)
	}

	// The console's password, if it has one (docs/ui.md "Console
	// passwords"). SPICE is not proxied, so the client presents it itself;
	// this caller passed the vm.console check above on its entry host. Read
	// from the RUNNING domain, and never logged.
	// A password that cannot be read degrades rather than refuses: the info
	// goes back without it, and the client prompts.
	password, err := s.virt.ConsolePassword(req.VmName, "spice")
	if err != nil {
		slog.Warn("spice console password unreadable; returning the connection info without it", "vm", req.VmName, "error", err)
		password = ""
	}

	host, err := corrosion.GetHost(ctx, s.db, vm.HostName)
	if err != nil || host == nil {
		return nil, status.Errorf(codes.Internal, "lookup host %q: %v", vm.HostName, err)
	}

	// JoinHostPort (not corrosion.PeerTarget, whose port-0 default is a gRPC
	// concern) so the URI handed to a client stays parseable for an IPv6 host.
	// Host/Port are still returned unbracketed for callers that build their own.
	uri := fmt.Sprintf("spice://%s", net.JoinHostPort(host.Address, strconv.Itoa(port)))
	return &pb.GetSpiceInfoResponse{
		Host:     host.Address,
		Port:     int32(port),
		Uri:      uri,
		Password: password,
	}, nil
}
