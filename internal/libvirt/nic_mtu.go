package libvirt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
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

// NICMTUError is a NIC MTU this host cannot carry: an explicit MTU its bridge
// does not equal, a bridge whose MTU cannot be read, or a NIC that takes no
// MTU. It is the operator's to fix, never an internal failure.
type NICMTUError struct{ msg string }

func (e *NICMTUError) Error() string { return e.msg }

func nicMTUError(format string, args ...any) error {
	return &NICMTUError{msg: fmt.Sprintf(format, args...)}
}

// IsNICMTUError reports whether err is, or wraps, a NICMTUError.
func IsNICMTUError(err error) bool {
	var e *NICMTUError
	return errors.As(err, &e)
}

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
		return 0, nicMTUError("NIC %d: read the MTU of bridge %s on host %s: %v", nic, bridge, host, err)
	}
	if mtu == NICMTUFromBridge {
		return got, nil
	}
	if mtu != got {
		return 0, nicMTUError("%s", NICMTUMismatch(nic, mtu, bridge, got, host))
	}
	return mtu, nil
}

// nicMTUElement renders NIC i's <mtu>, nil when it sets none.
func nicMTUElement(cfg VMConfig, i int, n NetworkConfig, model string) (*ifaceMTU, error) {
	if n.MTU == 0 {
		return nil, nil
	}
	if n.Direct != "" {
		return nil, nicMTUError("NIC %d: an MTU needs a bridged network (macvtap and SR-IOV networks are not supported)", i)
	}
	if model != "virtio" {
		return nil, nicMTUError("NIC %d: an MTU needs the virtio model (this NIC is %s)", i, model)
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

// mtuTagRe matches a NIC's <mtu> element, in libvirt's self-closing form or
// as an empty pair.
var mtuTagRe = regexp.MustCompile(`(?s)\s*<mtu\b[^>]*?(/>|>\s*</mtu>)`)

// PatchInactiveNICMTU sets the <mtu> of the NIC with mac in a persistent
// definition, in place, so the addresses libvirt assigned survive. size 0
// removes it.
func PatchInactiveNICMTU(domXML, mac string, size int) (string, error) {
	want := strings.ToLower(strings.TrimSpace(mac))
	found := false
	out := ifaceBlock.ReplaceAllStringFunc(domXML, func(block string) string {
		m := macAttrRe.FindStringSubmatch(block)
		if m == nil || strings.ToLower(m[1]) != want {
			return block
		}
		found = true
		block = mtuTagRe.ReplaceAllString(block, "")
		if size <= 0 {
			return block
		}
		return strings.Replace(block, "</interface>", fmt.Sprintf("<mtu size='%d'/>\n    </interface>", size), 1)
	})
	if !found {
		return "", fmt.Errorf("no interface with MAC %q", mac)
	}
	return out, nil
}

// InterfaceMTU is one NIC of a domain definition: its MAC, its bridge (empty
// for any other kind) and its <mtu>, 0 when it has none.
type InterfaceMTU struct {
	MAC    string
	Bridge string
	MTU    int
}

// InterfaceMTUs lists every NIC of a domain definition with its MTU, in
// document order. Nil when the XML does not parse.
func InterfaceMTUs(domXML string) []InterfaceMTU {
	var d struct {
		Interfaces []struct {
			Type string `xml:"type,attr"`
			MAC  struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
			Source struct {
				Bridge string `xml:"bridge,attr"`
			} `xml:"source"`
			MTU struct {
				Size int `xml:"size,attr"`
			} `xml:"mtu"`
		} `xml:"devices>interface"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return nil
	}
	out := make([]InterfaceMTU, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		out = append(out, InterfaceMTU{MAC: strings.ToLower(i.MAC.Address), Bridge: i.Source.Bridge, MTU: i.MTU.Size})
	}
	return out
}
