package network

import (
	"context"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ReleaseDeviceServices stops what litevirt serves on def's device for
// networkName — its dnsmasq and the gateway address — and leaves the device
// itself, its L2, for workloads still defined on it. It is how a network that
// moved to a new device on the same subnet takes its gateway there while
// stopped workloads still name the old one.
func ReleaseDeviceServices(networkName string, def compose.NetworkDef) {
	switch def.Type {
	case "", "bridge", "isolated":
		dev := BridgeName(networkName, def)
		if validLinkName(dev) != nil {
			return
		}
		stopDHCPAndForgetLeases(dnsmasqPidFile(dev), dev)
		if def.Subnet != "" {
			if gw, _, _, _, err := SubnetRange(def.Subnet); err == nil && gw != "" {
				execCommand("ip", "addr", "del", gw, "dev", dev) //nolint:errcheck
			}
		}
		RemoveProxyARP(dev)
	case "vxlan":
		if def.VNI == 0 {
			return
		}
		stopDHCPAndForgetLeases(dnsmasqPidFileVNI(def.VNI), vxlanBridgeName(def.VNI))
		if def.Subnet != "" {
			RemoveIRB(def.VNI, def.Subnet) //nolint:errcheck
		}
	}
}

// ServingGateway reports whether this host serves def's gateway for
// networkName on its device now: litevirt's dnsmasq runs there (it is what
// put the gateway address on the device).
func ServingGateway(networkName string, def compose.NetworkDef) bool {
	switch def.Type {
	case "", "bridge", "isolated":
		return litevirtServedDHCP(dnsmasqPidFile(BridgeName(networkName, def)))
	case "vxlan":
		return def.VNI != 0 && litevirtServedDHCP(dnsmasqPidFileVNI(def.VNI))
	}
	return false
}

// WouldServeGateway reports whether provisioning def here would put the
// network's gateway and dnsmasq on its device: DHCPWouldServe, with the facts
// Provision reads.
func WouldServeGateway(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, hostName string) bool {
	f := DHCPHostFacts{}
	switch def.Type {
	case "", "bridge":
		dev := BridgeName(networkName, def)
		f.BridgePreExisted = BridgeExists(dev) && !bridgeRecorded(dev) && !litevirtServedDHCP(dnsmasqPidFile(dev))
	case "vxlan":
		f.IsGatewayHost = db != nil && isGatewayHost(ctx, db, networkName, hostName)
	}
	return DHCPWouldServe(def, f)
}

// SameGateway reports whether two network definitions put the same gateway
// address on their devices.
func SameGateway(a, b compose.NetworkDef) bool {
	ga, okA := SubnetGatewayV4(a.Subnet)
	gb, okB := SubnetGatewayV4(b.Subnet)
	return okA && okB && ga == gb
}
