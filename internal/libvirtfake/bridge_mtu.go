package libvirtfake

import "github.com/litevirt/litevirt/internal/libvirt"

var _ libvirt.BridgeMTUReader = (*Fake)(nil)

// defaultBridgeMTU is what a bridge nobody set answers: Linux's default.
const defaultBridgeMTU = 1500

// BridgeMTU answers this node's MTU for bridge: what SetBridgeMTU set, else
// 1500.
func (f *Fake) BridgeMTU(bridge string) (int, error) {
	f.daemon()
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.bridgeMTUErr[bridge]; err != nil {
		return 0, err
	}
	if m, ok := f.bridgeMTU[bridge]; ok {
		return m, nil
	}
	return defaultBridgeMTU, nil
}

// SetBridgeMTU sets bridge's MTU on this node, which a NIC MTU is checked
// against when a domain is defined or migrated here.
func (f *Fake) SetBridgeMTU(bridge string, mtu int) {
	f.daemon()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bridgeMTU == nil {
		f.bridgeMTU = map[string]int{}
	}
	f.bridgeMTU[bridge] = mtu
}

// FailBridgeMTU makes reading bridge's MTU on this node fail with err (a
// bridge being recreated, say); nil reads it again.
func (f *Fake) FailBridgeMTU(bridge string, err error) {
	f.daemon()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bridgeMTUErr == nil {
		f.bridgeMTUErr = map[string]error{}
	}
	f.bridgeMTUErr[bridge] = err
}
