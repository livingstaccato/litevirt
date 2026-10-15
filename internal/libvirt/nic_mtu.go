package libvirt

import (
	"fmt"
	"net"
)

// NICMTUFromBridge is a NIC's stored MTU for `mtu: bridge`: render the
// bridge's own MTU (compose.NICMTUBridge).
const NICMTUFromBridge = 1

// BridgeMTUReader reads a bridge's MTU on this host. *Client reads the host's
// own; a test backend answers per node.
type BridgeMTUReader interface {
	BridgeMTU(bridge string) (int, error)
}

// ReadBridgeMTU reads bridge's MTU on this host.
func ReadBridgeMTU(bridge string) (int, error) {
	ifc, err := net.InterfaceByName(bridge)
	if err != nil {
		return 0, err
	}
	return ifc.MTU, nil
}

// BridgeMTU is ReadBridgeMTU: the bridges libvirt plugs this host's guests
// into are this host's.
func (c *Client) BridgeMTU(bridge string) (int, error) { return ReadBridgeMTU(bridge) }

// NICMTUMismatch is the refusal for a NIC whose MTU is not its bridge's.
func NICMTUMismatch(nic, mtu int, bridge string, bridgeMTU int, host string) string {
	return fmt.Sprintf("NIC %d MTU %d does not match bridge %s MTU %d on host %s (a guest MTU must equal its bridge's)",
		nic, mtu, bridge, bridgeMTU, host)
}

// ResolveNICMTU is the MTU NIC nic renders on bridge: the bridge's own for
// NICMTUFromBridge, else mtu, which must equal the bridge's. A larger one
// would exceed the bridge and drop frames; a smaller one would pull a bridge
// litevirt never pinned down to it, the host's own traffic on it included.
func ResolveNICMTU(nic, mtu int, bridge string, read func(string) (int, error), host string) (int, error) {
	if read == nil {
		read = ReadBridgeMTU
	}
	got, err := read(bridge)
	if err != nil {
		return 0, fmt.Errorf("NIC %d: read the MTU of bridge %s on host %s: %w", nic, bridge, host, err)
	}
	if mtu == NICMTUFromBridge {
		return got, nil
	}
	if mtu != got {
		return 0, fmt.Errorf("%s", NICMTUMismatch(nic, mtu, bridge, got, host))
	}
	return mtu, nil
}

// nicMTUElement renders NIC i's <mtu>, nil when it sets none.
func nicMTUElement(cfg VMConfig, i int, n NetworkConfig, model string) (*ifaceMTU, error) {
	if n.MTU == 0 {
		return nil, nil
	}
	if n.Direct != "" {
		return nil, fmt.Errorf("NIC %d: an MTU needs a bridged network (macvtap and SR-IOV networks are not supported)", i)
	}
	if model != "virtio" {
		return nil, fmt.Errorf("NIC %d: an MTU needs the virtio model (this NIC is %s)", i, model)
	}
	m, err := ResolveNICMTU(i, n.MTU, n.Bridge, cfg.BridgeMTU, cfg.HostName)
	if err != nil {
		return nil, err
	}
	return &ifaceMTU{Size: m}, nil
}

// ifaceMTU is the NIC's <mtu size='N'/>.
type ifaceMTU struct {
	Size int `xml:"size,attr"`
}
