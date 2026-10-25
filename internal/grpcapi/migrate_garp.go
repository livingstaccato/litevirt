package grpcapi

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// GatewayAnnouncer announces a network's gateway out of a bridge on this
// host (network.AnnounceGateway in production).
type GatewayAnnouncer func(bridge string, gateway netip.Addr) (bool, error)

// SetGatewayAnnouncer replaces how this server announces a gateway (tests and
// the fleet harness; nil restores network.AnnounceGateway).
func (s *Server) SetGatewayAnnouncer(fn GatewayAnnouncer) { s.gatewayAnnouncer = fn }

func (s *Server) announceGateway(bridge string, gw netip.Addr) (bool, error) {
	if s.gatewayAnnouncer != nil {
		return s.gatewayAnnouncer(bridge, gw)
	}
	return network.AnnounceGateway(bridge, gw)
}

// AnnounceMigratedGuest runs on the TARGET of a completed live migration.
// First it puts the VLANs of the guest's NICs on the taps libvirt created
// here (applyTapVLANs), if they are not there yet: they live on the host tap,
// not in the domain XML, so the migration does not carry them. Then, for each network the guest has
// a NIC on, it announces the network's gateway out of this host's bridge,
// from this host's bridge MAC. The guest's ARP cache still holds the gateway
// at the source host's bridge, and a guest that is not otherwise talking to
// this host waits out that entry (some 18 s on a Linux guest) before it
// reaches its gateway again.
func (s *Server) AnnounceMigratedGuest(ctx context.Context, req *pb.AnnounceMigratedGuestRequest) (*emptypb.Empty, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.GetVmName() == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}
	// Only for a guest that runs here: libvirt answers that at once, where
	// the VM's row may not have replicated the move yet.
	if s.virt == nil {
		return nil, status.Error(codes.FailedPrecondition, "no hypervisor on this host")
	}
	if active, err := s.virt.DomainIsActive(req.GetVmName()); err != nil || !active {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q is not running on %s", req.GetVmName(), s.hostName)
	}
	// A guest with tap VLANs arrives paused and has them before it runs
	// (resumeHeld); this is the backstop for a source that did not hand it
	// over paused (an older build's), as ConvergeTapVLANs is.
	if err := s.applyTapVLANs(ctx, req.GetVmName()); err != nil {
		slog.Error("migrate: the arrived guest's NIC VLANs are not on its taps here; ConvergeTapVLANs retries", "vm", req.GetVmName(), "error", err)
	}
	s.announceGatewaysOf(ctx, req.GetVmName())
	return &emptypb.Empty{}, nil
}

// announceGatewaysOf announces, on this host, the gateway of each network vm
// has a NIC on that is not on a VLAN: the first address of the network's
// IPv4 subnet, out of the device this host serves the network on (servedDef;
// network.AnnounceGateway also skips a bridge with an uplink). Best effort;
// each bridge once.
func (s *Server) announceGatewaysOf(ctx context.Context, vm string) {
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm)
	if err != nil {
		slog.Warn("migrate: cannot read the NICs to announce the gateways of", "vm", vm, "error", err)
		return
	}
	done := map[string]bool{}
	for _, n := range nics {
		nr, err := corrosion.GetNetwork(ctx, s.db, n.NetworkName)
		if err != nil || nr == nil {
			continue // a flat bridge: litevirt is not its gateway
		}
		def, err := networkRowDef(networkRow{name: nr.Name, typ: nr.Type, config: nr.Config})
		if err != nil {
			continue
		}
		// The device this host serves the network on, where the guest
		// landed: after a move this host refused, the previous one.
		if served, ok := s.servedDef(nr.Name); ok {
			def = served
		}
		// On a VLAN the gateway is the VLAN's router, not this host.
		if def.VLAN > 0 {
			continue
		}
		gw, ok := network.SubnetGatewayV4(def.Subnet)
		if !ok {
			continue
		}
		bridge := network.BridgeName(nr.Name, def)
		if strings.HasPrefix(bridge, "direct:") || done[bridge+"/"+gw.String()] {
			continue
		}
		done[bridge+"/"+gw.String()] = true
		sent, err := s.announceGateway(bridge, gw)
		switch {
		case err != nil:
			slog.Warn("migrate: gratuitous ARP for the gateway failed (non-fatal)",
				"vm", vm, "network", nr.Name, "bridge", bridge, "gateway", gw.String(), "error", err)
		case sent:
			slog.Info("migrate: announced the gateway to the arrived guest",
				"vm", vm, "network", nr.Name, "bridge", bridge, "gateway", gw.String())
		}
	}
}

// announceOnTarget asks the target of a completed live migration to announce
// the guest's gateways there (AnnounceMigratedGuest). Best effort: a target on
// an older build answers Unimplemented, and the guest then recovers on its own.
func (s *Server) announceOnTarget(ctx context.Context, target *corrosion.HostRecord, vm string) {
	conn, err := s.dialPeerAddr(peerTarget(target.Address, target.GRPCPort))
	if err != nil {
		slog.Warn("migrate: dial the target to announce the guest's gateways", "host", target.Name, "vm", vm, "error", err)
		return
	}
	defer conn.Close()
	cctx, cancel := notifyDetachedContext(ctx, 10*time.Second)
	defer cancel()
	if _, err := pb.NewLiteVirtClient(conn).AnnounceMigratedGuest(cctx, &pb.AnnounceMigratedGuestRequest{VmName: vm}); err != nil {
		lvl := slog.LevelWarn
		if status.Code(err) == codes.Unimplemented {
			lvl = slog.LevelDebug
		}
		slog.Log(ctx, lvl, "migrate: the target did not announce the guest's gateways", "host", target.Name, "vm", vm, "error", err)
	}
}
