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
	// devSubnets is the subnet each device set up here serves (its gateway
	// address and dnsmasq), keyed by DEVICE: a network re-provisioned on
	// another device leaves the old one serving until something tears it
	// down, as on a host.
	devSubnets map[string]string
	// created are the bridges Provision made here (litevirt's own, as the
	// real EnsureBridge records them), minus those torn down or swept;
	// operator bridges a scenario named (SetOperatorBridge) are never in it.
	created  map[string]bool
	operator map[string]bool
	sweeps   map[string]int // bridge → RemoveOrphanedBridge removals
	// intents makes Provision and Deprovision write and delete the network's
	// host firewall intent (net:<name>) as the real ones do (SetIntents).
	intents bool
	retires map[string]int // device → RetireDevice calls
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
	gatewayFrames map[string][][]byte
	garps         map[string]int // bridge + IP → gratuitous ARP sends
}

func (f *NetProvFake) GARPCount(bridge, ip string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.garps[bridge+"\x00"+ip]
}

func (f *NetProvFake) FDBDestinations(vni int, mac string) []string {
	f.mu.Lock()
	k := f.kernel
	f.mu.Unlock()
	if k == nil {
		return nil
	}
	return k.Dsts(fmt.Sprintf("vxlan%d", vni), mac)
}

func (f *NetProvFake) fdbKernel() (*fdbfake.Kernel, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.kernel == nil {
		f.kernel = fdbfake.New()
	}
	local := make([]string, 0, len(f.vteps))
	for _, addr := range f.vteps {
		local = append(local, addr)
	}
	return f.kernel, local
}

func (f *NetProvFake) AddFDBEntry(vni int, mac, remoteVTEP string) error {
	k, local := f.fdbKernel()
	return network.AddFDBEntryWith(vni, mac, remoteVTEP, k.Exec, local)
}

func (f *NetProvFake) DeleteFDBEntry(vni int, mac, remoteVTEP string) error {
	k, _ := f.fdbKernel()
	return network.DeleteFDBEntryWith(vni, mac, remoteVTEP, k.Exec)
}

func (f *NetProvFake) SyncPeerVTEP(ctx context.Context, db *corrosion.Client, networkName, hostName string, vni int, peer, peerAddr string) error {
	k, local := f.fdbKernel()
	return network.SyncPeerVTEPWith(ctx, db, networkName, hostName, vni, peer, peerAddr, k.Exec, local)
}

func (f *NetProvFake) SendGARP(bridge, ip string) error {
	return network.SendGARPWith(bridge, ip, func(name string, args ...string) ([]byte, error) {
		if name != "arping" || len(args) != 6 || args[0] != "-A" || args[1] != "-c" || args[2] != "3" || args[3] != "-I" {
			return nil, fmt.Errorf("unexpected GARP command: %s %v", name, args)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.garps == nil {
			f.garps = map[string]int{}
		}
		f.garps[args[4]+"\x00"+args[5]]++
		return nil, nil
	})
}

func NewNetProvFake() *NetProvFake {
	return &NetProvFake{
		up:           map[string]string{},
		provisions:   map[string]int{},
		deprovisions: map[string]int{},
		flat:         map[string]bool{},
		devSubnets:   map[string]string{},
		created:      map[string]bool{},
		operator:     map[string]bool{},
		sweeps:       map[string]int{},
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
// A bridge network with no interface is refused as the real one refuses it.
func (f *NetProvFake) Provision(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	dev := network.BridgeName(name, def)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failWith[name]; err != nil {
		return "", err
	}
	if (def.Type == "" || def.Type == "bridge") && def.Interface == "" {
		return "", fmt.Errorf("bridge network requires interface name")
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
			for other, sub := range f.devSubnets {
				if p, err := netip.ParsePrefix(sub); other != dev && err == nil && p.Overlaps(mine) {
					return "", fmt.Errorf("start DHCP on %s: dnsmasq on %s exited immediately: exit status 2", dev, dev)
				}
			}
		}
	}
	if f.intents && db != nil {
		if err := fakeRecordIntent(ctx, db, name, def, dev, hostName); err != nil {
			return "", err
		}
	}
	f.up[name] = dev
	if def.Subnet != "" && fakeServes(def) {
		f.devSubnets[dev] = def.Subnet
	}
	if (def.Type == "" || def.Type == "bridge" || def.Type == "isolated") && !f.operator[dev] {
		f.created[dev] = true
	}
	f.provisions[name]++
	return dev, nil
}

// Deprovision tears down what Provision set up for def's device, and the
// network's firewall intent.
func (f *NetProvFake) Deprovision(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, hostName string) error {
	dev := network.BridgeName(name, def)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.intents && db != nil {
		if err := corrosion.DeleteHostFWIntent(ctx, db, hostName, "net:"+name); err != nil {
			return err
		}
	}
	delete(f.up, name)
	delete(f.devSubnets, dev)
	delete(f.created, dev)
	f.deprovisions[name]++
	return nil
}

// RetireDevice tears down what Provision set up for def's device and nothing
// keyed by the network: its firewall intent stays, as with the real one.
func (f *NetProvFake) RetireDevice(_ context.Context, _ *corrosion.Client, name string, def compose.NetworkDef, _ string) error {
	dev := network.BridgeName(name, def)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.devSubnets, dev)
	delete(f.created, dev)
	if f.retires == nil {
		f.retires = map[string]int{}
	}
	f.retires[dev]++
	return nil
}

// ReleaseDeviceServices stops what def's device serves, keeping the device.
func (f *NetProvFake) ReleaseDeviceServices(name string, def compose.NetworkDef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.devSubnets, network.BridgeName(name, def))
}

// ServingGateway reports whether def's device serves a subnet here.
func (f *NetProvFake) ServingGateway(name string, def compose.NetworkDef) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.devSubnets[network.BridgeName(name, def)]
	return ok
}

// WouldServeGateway is the real gate on the definition alone: the fleet has
// no host bridges for an operator to have made.
func (f *NetProvFake) WouldServeGateway(_ context.Context, _ *corrosion.Client, _ string, def compose.NetworkDef, _ string) bool {
	return fakeServes(def)
}

// fakeServes is network.DHCPWouldServe for a bridge litevirt makes, and for
// a vxlan network's gateway host (the fleet's nodes all are).
func fakeServes(def compose.NetworkDef) bool {
	return network.DHCPWouldServe(def, network.DHCPHostFacts{IsGatewayHost: true})
}

// fakeRecordIntent writes the intent the real Provision writes for def.
func fakeRecordIntent(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, dev, hostName string) error {
	scope := "net:" + name
	switch {
	case def.HostIsolation:
		return corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{ScopeKey: scope, Bridge: dev, Isolate: true})
	case def.Subnet != "" && def.NATEnabled() && def.VLAN == 0:
		return corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{ScopeKey: scope, Bridge: dev, MasqueradeSubnet: def.Subnet})
	}
	return corrosion.DeleteHostFWIntent(ctx, db, hostName, scope)
}

// SetIntents turns on writing and deleting the network firewall intents.
func (f *NetProvFake) SetIntents(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.intents = on
}

// Retires counts RetireDevice calls for device dev.
func (f *NetProvFake) Retires(dev string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.retires[dev]
}

// CreatedBridges lists the bridges litevirt made here and still has.
func (f *NetProvFake) CreatedBridges() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.created))
	for b := range f.created {
		out = append(out, b)
	}
	sort.Strings(out)
	return out, nil
}

// RemoveOrphanedBridge removes a bridge litevirt made here, with what it
// served, unless a guest port is on it.
func (f *NetProvFake) RemoveOrphanedBridge(name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.created[name] || len(f.guestPorts[name]) > 0 {
		return false, nil
	}
	delete(f.created, name)
	delete(f.devSubnets, name)
	f.sweeps[name]++
	return true, nil
}

// RecordCreatedBridge marks name as a bridge litevirt made here outside any
// network's provisioning: a flat bridge a NIC fell back to.
func (f *NetProvFake) RecordCreatedBridge(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created[name] = true
}

// SetOperatorBridge marks name as a bridge an operator made: Provision on it
// never counts it as litevirt's.
func (f *NetProvFake) SetOperatorBridge(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.operator[name] = true
}

// Serving lists the devices that serve a subnet here (gateway address and
// dnsmasq), sorted.
func (f *NetProvFake) Serving() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.devSubnets))
	for d := range f.devSubnets {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Sweeps counts RemoveOrphanedBridge removals of bridge.
func (f *NetProvFake) Sweeps(bridge string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sweeps[bridge]
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
	if dev, ok := f.up[network]; ok {
		delete(f.devSubnets, dev)
	}
	delete(f.up, network)
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

// Addrs is the gateway address the device dev serves here (its subnet's first
// host), as the real provisioner gives a bridge it made. A device keeps
// serving after its network moved off it, until something tears it down.
func (f *NetProvFake) Addrs(dev string) []netip.Prefix {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := netip.ParsePrefix(f.devSubnets[dev])
	if err != nil {
		return nil
	}
	p = p.Masked()
	return []netip.Prefix{netip.PrefixFrom(p.Addr().Next(), p.Bits())}
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

// AnnounceGateway models a packet only on a device that owns this address.
// The frame uses the production encoder, without any socket or host lookup.
func (f *NetProvFake) AnnounceGateway(bridge string, gateway netip.Addr) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := netip.ParsePrefix(f.devSubnets[bridge])
	if err != nil || p.Masked().Addr().Next() != gateway {
		return false, nil
	}
	frame, err := network.GatewayARPFrame(network.BridgeMAC(bridge), gateway)
	if err != nil {
		return false, err
	}
	if f.gatewayFrames == nil {
		f.gatewayFrames = map[string][][]byte{}
	}
	key := bridge + "\x00" + gateway.String()
	f.gatewayFrames[key] = append(f.gatewayFrames[key], frame)
	return true, nil
}
func (f *NetProvFake) GatewayFrames(bridge, ip string) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]byte
	for _, b := range f.gatewayFrames[bridge+"\x00"+ip] {
		out = append(out, append([]byte(nil), b...))
	}
	return out
}
