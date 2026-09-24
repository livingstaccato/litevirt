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
}

type hostNetworkProvisioner struct{}

func (hostNetworkProvisioner) Provision(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	return network.SafeProvision(ctx, db, name, def, localIP, hostName)
}

func (hostNetworkProvisioner) Deprovision(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) error {
	return network.Deprovision(ctx, db, name, def, hostName)
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

// provisionForVM provisions networkName on this host for a NIC and returns its
// device, or "" when the network has no record (flat bridge mode).
func (s *Server) provisionForVM(ctx context.Context, networkName string) (string, error) {
	return network.ProvisionForVMWith(ctx, s.db, networkName, s.hostName, s.networkProvisioner().Provision)
}
