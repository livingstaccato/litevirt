package grpcapi

import (
	"context"

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
	// with no ports and no IPv4 address, and reports whether it did. Absent is
	// not an error.
	RemoveUnusedBridge(name string) (bool, error)
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
// reconciler so a failover restart provisions exactly as a VM create does.
func (s *Server) ProvisionNetworkHere(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	return s.networkProvisioner().Provision(ctx, db, name, def, localIP, hostName)
}

// provisionForVM provisions networkName on this host for a NIC and returns its
// device, or "" when the network has no record (flat bridge mode).
func (s *Server) provisionForVM(ctx context.Context, networkName string) (string, error) {
	return network.ProvisionForVMWith(ctx, s.db, networkName, s.hostName, s.networkProvisioner().Provision)
}
