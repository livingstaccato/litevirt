package fleet

import (
	"context"
	"sort"
	"sync"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// NetProvFake is the fleet stand-in for the host network provisioner: one per
// node, recording which networks that node has set up and on which device.
// The real provisioner shells out to `ip` and dnsmasq as root through one
// process-wide exec seam, so it can neither run here nor tell nodes apart.
//
// The device it reports is network.BridgeName — the name the real Provision
// returns — so a NIC that lands on it lands where production would put it.
// Mirrors n.Virt / n.CT / n.HostNet.
type NetProvFake struct {
	mu           sync.Mutex
	up           map[string]string // network → device, while provisioned
	provisions   map[string]int    // network → Provision calls
	deprovisions map[string]int    // network → Deprovision calls
	flat         map[string]bool   // bridges EnsureBridge created (flat-bridge fallback)
}

func NewNetProvFake() *NetProvFake {
	return &NetProvFake{
		up:           map[string]string{},
		provisions:   map[string]int{},
		deprovisions: map[string]int{},
		flat:         map[string]bool{},
	}
}

func (f *NetProvFake) Provision(_ context.Context, _ *corrosion.Client, name string, def compose.NetworkDef, _, _ string) (string, error) {
	dev := network.BridgeName(name, def)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up[name] = dev
	f.provisions[name]++
	return dev, nil
}

func (f *NetProvFake) Deprovision(_ context.Context, _ *corrosion.Client, name string, _ compose.NetworkDef, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.up, name)
	f.deprovisions[name]++
	return nil
}

// EnsureBridge is a Server.SetBridgeEnsure seam that records the flat bridges
// a NIC fell back to. Not wired by default: scenarios that want it opt in.
func (f *NetProvFake) EnsureBridge(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flat[name] = true
	return nil
}

// Up returns the device network is provisioned on here, and whether it is.
func (f *NetProvFake) Up(network string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dev, ok := f.up[network]
	return dev, ok
}

// Provisions and Deprovisions count calls for network on this node.
func (f *NetProvFake) Provisions(network string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.provisions[network]
}

func (f *NetProvFake) Deprovisions(network string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deprovisions[network]
}

// FlatBridges lists the bridges EnsureBridge was asked for, sorted.
func (f *NetProvFake) FlatBridges() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.flat))
	for b := range f.flat {
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}
