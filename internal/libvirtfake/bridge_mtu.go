package libvirtfake

import "github.com/litevirt/litevirt/internal/libvirt"

var _ libvirt.BridgeMTUReader = (*Fake)(nil)

// defaultBridgeMTU is what a bridge nobody set answers: Linux's default.
const defaultBridgeMTU = 1500

// BridgeMTU answers this node's MTU for bridge: what SetBridgeMTU set, else
// 1500.
func (f *Fake) BridgeMTU(bridge string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.bridgeMTU[bridge]; ok {
		return m, nil
	}
	return defaultBridgeMTU, nil
}

// SetBridgeMTU sets bridge's MTU on this node, which a NIC MTU is checked
// against when a domain is defined or migrated here.
func (f *Fake) SetBridgeMTU(bridge string, mtu int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bridgeMTU == nil {
		f.bridgeMTU = map[string]int{}
	}
	f.bridgeMTU[bridge] = mtu
}
