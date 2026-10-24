package grpcapi

import (
	"net"

	"github.com/litevirt/litevirt/internal/network"
)

func (s *Server) ensureBridge(name string) error {
	if s.bridgeEnsure != nil {
		return s.bridgeEnsure(name)
	}
	if _, err := net.InterfaceByName(name); err != nil {
		return network.EnsureBridge(name)
	}
	return nil
}

// nicPreflight runs the NIC host-wiring preflight (network.RunPreFlight).
func (s *Server) nicPreflight(checks []network.PreFlightCheck) error {
	if s.netPreflight != nil {
		return s.netPreflight(checks)
	}
	return network.RunPreFlightWith(checks, s.bridgeVLANFilteringOf)
}

// bridgeVLANFilteringOf reads a bridge's VLAN filtering on this host
// (network.BridgeVLANFiltering, or the SetBridgeVLANFiltering seam).
func (s *Server) bridgeVLANFilteringOf(bridge string) (isBridge, on bool, err error) {
	if s.bridgeVLANFiltering != nil {
		return s.bridgeVLANFiltering(bridge)
	}
	return network.BridgeVLANFiltering(bridge)
}

// accessVLAN is the VLAN of an access-port NIC (trunk: with exactly one
// VLAN), 0 for any other.
func accessVLAN(trunk []int32) int {
	if len(trunk) == 1 {
		return int(trunk[0])
	}
	return 0
}

// bridgeExistsHere answers, for THIS host, the one host-local fact the NetBox
// bind-time DHCP refusal needs: whether the bridge already exists.
//
// It is a seam because the answer decides a refusal. A unit test that let the
// real host answer would pass or fail on which interfaces the test machine
// happens to carry, and the interesting cases are exactly the two answers.
func (s *Server) bridgeExistsHere(name string) bool {
	if s.bridgeExists != nil {
		return s.bridgeExists(name)
	}
	return network.BridgeExists(name)
}

// isBridgeHere reports whether name is a bridge on this host: a link that
// exists and is a bridge, not a NIC, bond or VLAN of that name.
func (s *Server) isBridgeHere(name string) bool {
	if s.isBridge != nil {
		return s.isBridge(name)
	}
	return network.IsBridge(name)
}

// bridgeHasUplinkHere answers the second host-local fact the DHCP finding needs:
// whether a bridge that DOES exist here carries anything off the host.
//
// Without it "the bridge exists" is the only input, and a bridge litevirt
// auto-created during a placement is indistinguishable from the infrastructure
// bridge an operator was asked to create — so the finding cleared itself while
// the guest sat on an uplink-less bridge. Same seam reasoning as
// bridgeExistsHere: the answer decides a refusal-shaped finding, so a unit test
// must be able to fix it.
func (s *Server) bridgeHasUplinkHere(name string) bool {
	if s.bridgeUplink != nil {
		return s.bridgeUplink(name)
	}
	return network.BridgeHasUplink(name)
}
