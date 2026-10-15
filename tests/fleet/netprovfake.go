package fleet

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/network/fdbfake"
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
	busy         map[string]bool   // flat bridges a scenario says have a port attached
	guestPorts   map[string][]string
	subnets      map[string]string // network → subnet, while provisioned with one
	// dhcpConflicts makes Provision fail the way the real dnsmasq does when
	// another network provisioned on this node already serves an overlapping
	// subnet: both listen on the same gateway address, so the second one
	// exits at once (exit status 2). Off by default; SetDHCPConflicts.
	dhcpConflicts bool
	failWith      map[string]error  // network → the error its Provision returns (FailProvision)
	vteps         map[string]string // network → the VTEP address its last Provision was handed
	fdbSyncs      map[string]int    // network → SyncFDB calls
	kernel        *fdbfake.Kernel   // this node's vxlan forwarding table (SyncFDB)
	vnis          map[string]int    // network → VNI, from SyncFDB
}

func NewNetProvFake() *NetProvFake {
	return &NetProvFake{
		up:           map[string]string{},
		provisions:   map[string]int{},
		deprovisions: map[string]int{},
		flat:         map[string]bool{},
		subnets:      map[string]string{},
	}
}

// FailProvision makes every Provision of network return err; nil clears it.
func (f *NetProvFake) FailProvision(network string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith == nil {
		f.failWith = map[string]error{}
	}
	if err == nil {
		delete(f.failWith, network)
		return
	}
	f.failWith[network] = err
}

// SetDHCPConflicts turns on the overlapping-subnet dnsmasq failure (see
// NetProvFake.dhcpConflicts).
func (f *NetProvFake) SetDHCPConflicts(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dhcpConflicts = on
}

// Provision records the network as set up here. A vxlan network also
// registers this node's VTEP in network_vteps, as the real Provision does, so
// the rows replicate and a scenario can see which address each node chose.
func (f *NetProvFake) Provision(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	dev := network.BridgeName(name, def)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failWith[name]; err != nil {
		return "", err
	}
	if def.Type == "vxlan" && def.VNI != 0 && db != nil {
		if err := network.UpsertVTEP(ctx, db, name, hostName, localIP, def.VNI); err != nil {
			return "", fmt.Errorf("upsert vtep: %w", err)
		}
	}
	if f.vteps == nil {
		f.vteps = map[string]string{}
	}
	f.vteps[name] = localIP
	if f.dhcpConflicts && def.Subnet != "" {
		if mine, err := netip.ParsePrefix(def.Subnet); err == nil {
			for other, sub := range f.subnets {
				if p, err := netip.ParsePrefix(sub); other != name && err == nil && p.Overlaps(mine) {
					return "", fmt.Errorf("start DHCP on %s: dnsmasq on %s exited immediately: exit status 2", dev, dev)
				}
			}
		}
	}
	f.up[name] = dev
	if def.Subnet != "" {
		f.subnets[name] = def.Subnet
	}
	f.provisions[name]++
	return dev, nil
}

func (f *NetProvFake) Deprovision(_ context.Context, _ *corrosion.Client, name string, _ compose.NetworkDef, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.up, name)
	delete(f.subnets, name)
	f.deprovisions[name]++
	return nil
}

// Provisioned answers whether network is still set up on this node.
func (f *NetProvFake) Provisioned(name string, _ compose.NetworkDef) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.up[name]
	return ok
}

// Lose models the host losing what provisioning set up for network — a
// dnsmasq that died, or a bridge someone deleted — without litevirt doing it.
func (f *NetProvFake) Lose(network string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.up, network)
	delete(f.subnets, network)
}

// EnsureBridge is a Server.SetBridgeEnsure seam that records the flat bridges
// a NIC fell back to. Not wired by default: scenarios that want it opt in.
func (f *NetProvFake) EnsureBridge(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flat[name] = true
	return nil
}

// RemoveUnusedBridge removes a flat bridge EnsureBridge made, unless a
// scenario marked it busy (SetBridgeBusy).
func (f *NetProvFake) RemoveUnusedBridge(name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.flat[name] || f.busy[name] {
		return false, nil
	}
	delete(f.flat, name)
	return true, nil
}

// GuestPorts lists the guest ports a scenario put on bridge (SetGuestPorts).
func (f *NetProvFake) GuestPorts(bridge string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.guestPorts[bridge]...), nil
}

// SetGuestPorts sets the guest devices plugged into bridge on this node; no
// ports clears them.
func (f *NetProvFake) SetGuestPorts(bridge string, ports ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.guestPorts == nil {
		f.guestPorts = map[string][]string{}
	}
	f.guestPorts[bridge] = ports
}

// SetBridgeBusy marks a flat bridge as having a port attached, so
// RemoveUnusedBridge leaves it.
func (f *NetProvFake) SetBridgeBusy(name string, busy bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.busy == nil {
		f.busy = map[string]bool{}
	}
	f.busy[name] = busy
}

// Up returns the device network is provisioned on here, and whether it is.
func (f *NetProvFake) Up(network string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dev, ok := f.up[network]
	return dev, ok
}

// HasDevice reports whether a provisioned network, or a flat bridge
// EnsureBridge made, is on dev here.
func (f *NetProvFake) HasDevice(dev string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.flat[dev] {
		return true
	}
	for _, d := range f.up {
		if d == dev {
			return true
		}
	}
	return false
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

// VTEP is the VTEP address network's last Provision on this node was handed.
func (f *NetProvFake) VTEP(network string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vteps[network]
}

// SyncFDB counts the network reconciler's forwarding-entry syncs and runs
// the real sync (network.SyncFDBWith) against this node's model of the
// kernel's forwarding table (fdbfake), where a second `add` of the flood
// entry is refused as it is on a host. Its own address is the VTEP its last
// Provision of the network was handed.
func (f *NetProvFake) SyncFDB(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) error {
	f.mu.Lock()
	if f.fdbSyncs == nil {
		f.fdbSyncs = map[string]int{}
	}
	if f.kernel == nil {
		f.kernel = fdbfake.New()
	}
	f.fdbSyncs[name]++
	k, self := f.kernel, f.vteps[name]
	if f.vnis == nil {
		f.vnis = map[string]int{}
	}
	f.vnis[name] = def.VNI
	f.mu.Unlock()
	return network.SyncFDBWith(ctx, db, name, def, hostName, k.Exec, []string{self})
}

// Flood is network's flood list in this node's kernel table, sorted.
func (f *NetProvFake) Flood(network string) []string {
	f.mu.Lock()
	k, vni := f.kernel, f.vnis[network]
	f.mu.Unlock()
	if k == nil {
		return nil
	}
	return k.Dsts(fmt.Sprintf("vxlan%d", vni), "00:00:00:00:00:00")
}

// FDBSyncs counts SyncFDB calls for network on this node.
func (f *NetProvFake) FDBSyncs(network string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fdbSyncs[network]
}

// LegacyVTEP is the tunnel address every fleet node resolves before the
// release token latches: the default-route source address, which the nodes
// share — they run on one machine, as every lab node sits behind the same
// qemu NAT (10.0.2.15).
const LegacyVTEP = "10.0.2.15"

// ResolveVTEP is the fleet stand-in for network.ResolveVTEP (the nodes have
// no interfaces of their own to read): before the latch, the shared
// LegacyVTEP on ens3; after it, the node's host address on net1, or a refusal
// with none.
func (f *NetProvFake) ResolveVTEP(name string, def compose.NetworkDef, hostAddress string, switched bool) (string, string, error) {
	if !switched {
		return LegacyVTEP, "ens3", nil
	}
	if hostAddress == "" {
		return "", "", &network.VTEPRefusal{Network: name, Reason: "this host's address is not known yet"}
	}
	return hostAddress, "net1", nil
}
