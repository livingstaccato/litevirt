package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// NetworkProvisioner sets up and tears down one network's host devices
// (bridge, gateway address, dnsmasq, VXLAN, NAT intent) on THIS host.
//
// Production uses package network directly. It is an interface so the fleet
// harness can run N nodes in one process and still see what each node set up:
// the real one shells out to `ip` and dnsmasq, needs root, and shares one
// process-wide exec seam across every node.
type NetworkProvisioner interface {
	Provision(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error)
	Deprovision(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) error
	// Provisioned reports whether this host still has what Provision set up
	// for the network (its bridge, and its dnsmasq where one runs). It must
	// be cheap: the network reconciler asks it for every network every pass.
	Provisioned(name string, def compose.NetworkDef) bool
	// RemoveUnusedBridge deletes bridge name from this host if it is a bridge
	// with no ports and no address beyond an IPv6 link-local one, and reports
	// whether it did. Absent is not an error; an invalid interface name or
	// unreadable addresses are.
	RemoveUnusedBridge(name string) (bool, error)
	// GuestPorts lists the guest devices (VM taps, container veths) plugged
	// into bridge on this host. An absent bridge has none.
	GuestPorts(bridge string) ([]string, error)
	// SyncFDB brings a provisioned vxlan network's forwarding entries to the
	// replicated state (network.SyncFDB); a no-op for other networks. The
	// network reconciler runs it every pass.
	SyncFDB(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) error
	// RetireDevice tears down what def's device carries for network name —
	// never anything keyed by the network, such as its firewall intent
	// (network.RetireDevice). It retires a device a network moved off.
	RetireDevice(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) error
	// ReleaseDeviceServices stops the network's dnsmasq and removes its
	// gateway address on def's device, and leaves the device.
	ReleaseDeviceServices(name string, def compose.NetworkDef)
	// ServingGateway reports whether this host serves the network's gateway
	// on def's device now.
	ServingGateway(name string, def compose.NetworkDef) bool
	// WouldServeGateway reports whether provisioning def here would put the
	// network's gateway on its device.
	WouldServeGateway(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) bool
}

type hostNetworkProvisioner struct{}

func (hostNetworkProvisioner) Provision(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	return network.SafeProvision(ctx, db, name, def, localIP, hostName)
}

func (hostNetworkProvisioner) Deprovision(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) error {
	return network.Deprovision(ctx, db, name, def, hostName)
}

func (hostNetworkProvisioner) Provisioned(name string, def compose.NetworkDef) bool {
	return network.ProvisionedHere(name, def)
}

func (hostNetworkProvisioner) RemoveUnusedBridge(name string) (bool, error) {
	return network.RemoveBridgeIfUnused(name)
}

func (hostNetworkProvisioner) GuestPorts(bridge string) ([]string, error) {
	return network.BridgeGuestPorts(bridge)
}

func (hostNetworkProvisioner) RetireDevice(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) error {
	return network.RetireDevice(ctx, db, name, def, hostName)
}

func (hostNetworkProvisioner) ReleaseDeviceServices(name string, def compose.NetworkDef) {
	network.ReleaseDeviceServices(name, def)
}

func (hostNetworkProvisioner) ServingGateway(name string, def compose.NetworkDef) bool {
	return network.ServingGateway(name, def)
}

func (hostNetworkProvisioner) WouldServeGateway(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) bool {
	return network.WouldServeGateway(ctx, db, name, def, hostName)
}

func (hostNetworkProvisioner) CreatedBridges() ([]string, error) {
	return network.CreatedBridges()
}

func (hostNetworkProvisioner) RemoveOrphanedBridge(name string) (bool, error) {
	return network.RemoveOrphanedBridge(name)
}

func (hostNetworkProvisioner) SyncFDB(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) error {
	return network.SyncFDB(ctx, db, name, def, hostName)
}

// SetNetworkProvisioner replaces the host network provisioner (tests only;
// nil restores the real one).
func (s *Server) SetNetworkProvisioner(p NetworkProvisioner) { s.netProvisioner = p }

func (s *Server) networkProvisioner() NetworkProvisioner {
	if s.netProvisioner != nil {
		return s.netProvisioner
	}
	return hostNetworkProvisioner{}
}

// ProvisionNetworkHere provisions one network on this host through the
// server's provisioner. It is a network.ProvisionFunc, handed to the health
// reconciler so a failover restart provisions exactly as a VM create does. A
// caller that hands it no localIP ("", as network.ProvisionForVMWith does) gets
// the tunnel endpoint resolved here (resolveVTEP).
func (s *Server) ProvisionNetworkHere(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	if localIP == "" {
		var err error
		if localIP, def, err = s.resolveVTEP(name, def); err != nil {
			return "", err
		}
	}
	dev, err := s.provisionDevice(ctx, db, name, def, localIP, hostName)
	if err == nil {
		s.pushVTEP(ctx, name, def, localIP)
	}
	return dev, err
}

// provisionHere provisions name on this host with its tunnel endpoint
// resolved (resolveVTEP), returning the device and the VTEP it used — "" for
// a network that is not vxlan.
func (s *Server) provisionHere(ctx context.Context, name string, def compose.NetworkDef) (dev, vtep string, err error) {
	vtep, def, err = s.resolveVTEP(name, def)
	if err != nil {
		return "", "", err
	}
	dev, err = s.provisionDevice(ctx, s.db, name, def, vtep, s.hostName)
	if err == nil {
		s.pushVTEP(ctx, name, def, vtep)
	}
	return dev, vtep, err
}

// pushVTEP tells every peer with a VTEP row for a vxlan network this host
// just provisioned to flood to vtep (SyncVTEP). Every provisioning path does
// it, so a host whose VTEP moved — at the latch, or on a VM create — reaches
// its peers' flood lists at once; their reconcile passes converge on the
// replicated row too (NetworkProvisioner.SyncFDB) if a push is lost.
func (s *Server) pushVTEP(ctx context.Context, name string, def compose.NetworkDef, vtep string) {
	if def.Type == "vxlan" && def.VNI != 0 && vtep != "" {
		s.notifyVTEPPeers(ctx, name, def.VNI, vtep)
	}
}

// provisionForVM provisions networkName on this host for a NIC and returns its
// device, or "" when the network has no record (flat bridge mode).
func (s *Server) provisionForVM(ctx context.Context, networkName string) (string, error) {
	return network.ProvisionForVMWith(ctx, s.db, networkName, s.hostName, s.ProvisionNetworkHere)
}

// SetHostAddress sets this host's cluster address: advertise_address when one
// is configured (the daemon passes its hostAddress). Once the release token
// has latched, a vxlan network on this host uses it as the tunnel's local
// address (network.ResolveVTEP).
func (s *Server) SetHostAddress(addr string) { s.hostAddr = addr }

// VTEPAddress is the host address set by SetHostAddress; "" when nothing set
// one. It has no fallback: a server that was never told its address refuses
// a vxlan network rather than guess one (ResolveVTEP).
func (s *Server) VTEPAddress() string { return s.hostAddr }

// VTEPResolver decides a vxlan network's tunnel endpoint: network.ResolveVTEP
// in production.
type VTEPResolver func(networkName string, def compose.NetworkDef, hostAddress string, switched bool) (local, dev string, err error)

// SetVTEPResolver replaces how this server resolves a vxlan tunnel endpoint
// (tests and the fleet harness, which have no host interfaces to read; nil
// restores network.ResolveVTEP).
func (s *Server) SetVTEPResolver(fn VTEPResolver) { s.vtepResolver = fn }

// vtepSwitched reports whether this host's vxlan tunnels use its host address
// yet: once the release token has latched. Before, every host keeps the
// default-route endpoint every earlier build used, so a host on this build
// still reaches its peers on the previous one.
func (s *Server) vtepSwitched() bool { return s.ReleaseTokenLatched() }

// resolveVTEP resolves a vxlan network's tunnel endpoint on this host and
// returns def with the underlay it chose. A network that is not vxlan has no
// endpoint (""). A refusal is published once per network as
// network.vtep_refused, and again only after the network has resolved.
func (s *Server) resolveVTEP(name string, def compose.NetworkDef) (string, compose.NetworkDef, error) {
	if def.Type != "vxlan" {
		return "", def, nil
	}
	resolve := s.vtepResolver
	if resolve == nil {
		resolve = network.ResolveVTEP
	}
	local, dev, err := resolve(name, def, s.hostAddr, s.vtepSwitched())
	var r *network.VTEPRefusal
	refused := errors.As(err, &r)
	s.vtepRefusedMu.Lock()
	first := refused && s.vtepRefused[name] != err.Error()
	switch {
	case first:
		if s.vtepRefused == nil {
			s.vtepRefused = map[string]string{}
		}
		s.vtepRefused[name] = err.Error()
	case err == nil:
		delete(s.vtepRefused, name)
	}
	s.vtepRefusedMu.Unlock()
	if first {
		slog.Error("vxlan: refusing to set up the network's tunnel on this host", "network", name, "device", r.Device, "reason", r.Reason)
		s.publish("network.vtep_refused", name, fmt.Sprintf("device=%s: %s", r.Device, r.Reason))
	}
	if err != nil {
		return "", def, err
	}
	def.Underlay = dev
	return local, def, nil
}
