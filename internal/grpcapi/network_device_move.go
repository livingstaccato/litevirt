package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
)

// provisionedDevices is the definition each network was last provisioned
// with on this host by this process, by every provisioning path (a create, a
// deploy, a peer's ProvisionNetwork, a VM's NIC, the network reconciler), and
// the devices networks moved off that something here still uses. A restart
// empties it; sweepOrphanedBridges covers that case.
type provisionedDevices struct {
	mu   sync.Mutex
	defs map[string]compose.NetworkDef
	// pending maps a device a network moved off, still in use on this host,
	// to that network and the definition it was provisioned with: it is torn
	// down (retirePendingDevices) once nothing here uses it.
	pending map[string]pendingRetire
	// inflight counts the provisions running per device, so the sweep never
	// removes a device being provisioned.
	inflight map[string]int
	// netLocks serialises the provisions of one network; different networks
	// provision in parallel.
	netLocks map[string]*sync.Mutex
}

type pendingRetire struct {
	network string
	def     compose.NetworkDef
}

func (d *provisionedDevices) lockNetwork(name string) func() {
	d.mu.Lock()
	if d.netLocks == nil {
		d.netLocks = map[string]*sync.Mutex{}
	}
	l, ok := d.netLocks[name]
	if !ok {
		l = &sync.Mutex{}
		d.netLocks[name] = l
	}
	d.mu.Unlock()
	l.Lock()
	return l.Unlock
}

func (d *provisionedDevices) lastDef(name string) (compose.NetworkDef, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	def, ok := d.defs[name]
	return def, ok
}

// provisionDevice provisions name on this host. When this process last
// provisioned it on another device, that device is retired first
// (retireReplacedDevice).
func (s *Server) provisionDevice(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	unlock := s.netDevs.lockNetwork(name)
	defer unlock()
	if err := s.retireReplacedDevice(ctx, name, def); err != nil {
		return "", err
	}
	dev := network.BridgeName(name, def)
	s.netDevs.mu.Lock()
	if s.netDevs.inflight == nil {
		s.netDevs.inflight = map[string]int{}
	}
	s.netDevs.inflight[dev]++
	s.netDevs.mu.Unlock()
	got, err := s.networkProvisioner().Provision(ctx, db, name, def, localIP, hostName)
	s.netDevs.mu.Lock()
	if s.netDevs.inflight[dev]--; s.netDevs.inflight[dev] <= 0 {
		delete(s.netDevs.inflight, dev)
	}
	if err == nil {
		if s.netDevs.defs == nil {
			s.netDevs.defs = map[string]compose.NetworkDef{}
		}
		s.netDevs.defs[name] = def
		delete(s.netDevs.pending, dev) // in use by name again
	}
	s.netDevs.mu.Unlock()
	return got, err
}

// deprovisionDevice tears name down on this host and forgets its device.
func (s *Server) deprovisionDevice(ctx context.Context, name string, def compose.NetworkDef) error {
	unlock := s.netDevs.lockNetwork(name)
	defer unlock()
	if err := s.networkProvisioner().Deprovision(ctx, s.db, name, def, s.hostName); err != nil {
		return err
	}
	s.netDevs.mu.Lock()
	delete(s.netDevs.defs, name)
	s.netDevs.mu.Unlock()
	return nil
}

// retireReplacedDevice handles the device this process last provisioned
// network name on, when def puts the network on another one.
//
// A device another live network names is left as it is. One that something on
// this host still uses — a guest port, a VM's domain definition, running or
// not, or a container's config — is not touched: it keeps its gateway and
// dnsmasq and becomes pending, and retirePendingDevices tears it down once
// nothing uses it (a VM or container moves to the new device when it next
// starts, followNetworkDevices). Otherwise it is torn down now.
//
// While the old device stays and serves a subnet the new one would serve
// too, the two cannot both carry its gateway: that, and only that, is refused,
// naming what holds the old device.
func (s *Server) retireReplacedDevice(ctx context.Context, name string, def compose.NetworkDef) error {
	old, ok := s.netDevs.lastDef(name)
	if !ok {
		return nil
	}
	oldDev, newDev := network.BridgeName(name, old), network.BridgeName(name, def)
	if oldDev == newDev {
		return nil
	}
	user, err := s.liveNetworkNaming(ctx, oldDev, name)
	if err != nil {
		return fmt.Errorf("network %q moves from %s to %s: read which networks use %s: %w", name, oldDev, newDev, oldDev, err)
	}
	if user != "" {
		slog.Info("network moved to another device; the previous one stays, another network uses it",
			"network", name, "from", oldDev, "to", newDev, "live_network", user)
		s.forgetDef(name)
		return nil
	}
	ref, err := s.deviceReference(ctx, oldDev)
	if err != nil {
		ref = "unknown (" + err.Error() + ")"
	}
	if ref == "" {
		if err := s.networkProvisioner().Deprovision(ctx, s.db, name, old, s.hostName); err != nil {
			return fmt.Errorf("network %q moves from %s to %s: tear down %s: %w", name, oldDev, newDev, oldDev, err)
		}
		s.forgetDef(name)
		slog.Info("network moved to another device; tore down the previous one", "network", name, "from", oldDev, "to", newDev)
		return nil
	}
	s.netDevs.mu.Lock()
	if s.netDevs.pending == nil {
		s.netDevs.pending = map[string]pendingRetire{}
	}
	s.netDevs.pending[oldDev] = pendingRetire{network: name, def: old}
	s.netDevs.mu.Unlock()
	if gw, clash := subnetsCollide(old.Subnet, def.Subnet); clash {
		return fmt.Errorf("network %q moves from %s to %s, but %s on this host still uses %s, which keeps serving %s; "+
			"%s cannot carry its gateway %s beside it. Restart %s (`lv restart`, or stop and start it): "+
			"it starts on %s, and %s is torn down once nothing uses it",
			name, oldDev, newDev, ref, oldDev, old.Subnet, newDev, gw, ref, newDev, oldDev)
	}
	slog.Info("network moved to another device; the previous one stays until nothing on this host uses it",
		"network", name, "from", oldDev, "to", newDev, "in_use_by", ref)
	return nil
}

func (s *Server) forgetDef(name string) {
	s.netDevs.mu.Lock()
	delete(s.netDevs.defs, name)
	s.netDevs.mu.Unlock()
}

// subnetsCollide reports whether two network subnets overlap, and the
// gateway address the first one carries.
func subnetsCollide(a, b string) (string, bool) {
	pa, errA := netip.ParsePrefix(a)
	pb, errB := netip.ParsePrefix(b)
	if errA != nil || errB != nil || !pa.Overlaps(pb) {
		return "", false
	}
	gw, _, _, _, err := network.SubnetRange(a)
	if err != nil {
		gw = a
	}
	return gw, true
}

// retirePendingDevices tears down each device a network moved off once
// nothing on this host uses it any more, and drops one a live network uses
// again.
func (s *Server) retirePendingDevices(ctx context.Context) {
	s.netDevs.mu.Lock()
	devs := make([]string, 0, len(s.netDevs.pending))
	for d := range s.netDevs.pending {
		devs = append(devs, d)
	}
	s.netDevs.mu.Unlock()
	sort.Strings(devs)
	for _, dev := range devs {
		s.netDevs.mu.Lock()
		p, ok := s.netDevs.pending[dev]
		s.netDevs.mu.Unlock()
		if !ok {
			continue
		}
		unlock := s.netDevs.lockNetwork(p.network)
		func() {
			defer unlock()
			if user, err := s.liveNetworkNaming(ctx, dev, ""); err != nil {
				return
			} else if user != "" {
				s.dropPending(dev)
				return
			}
			if ref, err := s.deviceReference(ctx, dev); err != nil || ref != "" {
				return
			}
			if err := s.networkProvisioner().Deprovision(ctx, s.db, p.network, p.def, s.hostName); err != nil {
				slog.Warn("network moved off a device; tearing it down failed (will retry)",
					"network", p.network, "device", dev, "error", err)
				return
			}
			s.dropPending(dev)
			slog.Info("network moved off a device; tore it down once nothing on this host used it",
				"network", p.network, "device", dev)
		}()
	}
}

func (s *Server) dropPending(dev string) {
	s.netDevs.mu.Lock()
	delete(s.netDevs.pending, dev)
	s.netDevs.mu.Unlock()
}

// containerNICLinker is the part of a ContainerRuntime that reads and sets
// the bridge each container NIC links to in its config.
type containerNICLinker interface {
	ContainerNICLinks(ctx context.Context, name string) (map[int]string, error)
	SetContainerNICLink(ctx context.Context, name string, ordinal int, bridge string) error
}

// deviceReference names something on this host that uses device dev: a guest
// port plugged into it, a VM whose domain definition (persistent or live)
// has a NIC on it, or a container whose config links a NIC to it. "" means
// nothing does. An answer that cannot be read is an error, and the caller
// keeps the device.
func (s *Server) deviceReference(ctx context.Context, dev string) (string, error) {
	ports, err := s.networkProvisioner().GuestPorts(dev)
	if err != nil {
		return "", fmt.Errorf("read the guests on %s: %w", dev, err)
	}
	if len(ports) > 0 {
		return "guest port " + strings.Join(ports, ", "), nil
	}
	if s.virt != nil {
		doms, err := s.virt.ListDomains()
		if err != nil {
			return "", fmt.Errorf("list the domains: %w", err)
		}
		for _, d := range doms {
			x, err := s.virt.DumpXMLInactive(d)
			if err != nil {
				return "", fmt.Errorf("read the definition of %s: %w", d, err)
			}
			xmls := []string{x}
			if active, aerr := s.virt.DomainIsActive(d); aerr == nil && active {
				if live, lerr := s.virt.DumpXML(d); lerr == nil {
					xmls = append(xmls, live)
				}
			}
			for _, x := range xmls {
				for _, b := range libvirt.InterfaceBridges(x) {
					if b == dev {
						return "VM " + d, nil
					}
				}
			}
		}
	}
	if l, ok := s.containerRuntime.(containerNICLinker); ok && s.containerRuntime != nil {
		cts, err := s.containerRuntime.ListContainers(ctx)
		if err != nil {
			return "", fmt.Errorf("list the containers: %w", err)
		}
		for _, ct := range cts {
			links, err := l.ContainerNICLinks(ctx, ct)
			if err != nil {
				return "", fmt.Errorf("read the NIC links of container %s: %w", ct, err)
			}
			for _, b := range links {
				if b == dev {
					return "container " + ct, nil
				}
			}
		}
	}
	return "", nil
}

// liveNetworkNaming names a live network other than except whose device is
// dev, or returns "".
func (s *Server) liveNetworkNaming(ctx context.Context, dev, except string) (string, error) {
	rows, err := s.db.Query(ctx, `SELECT name, type, config FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		n := r.String("name")
		if n == except {
			continue
		}
		def, err := networkRowDef(networkRow{name: n, typ: r.String("type"), config: r.String("config")})
		if err != nil {
			return "", fmt.Errorf("network %s: config: %w", n, err)
		}
		if network.BridgeName(n, def) == dev {
			return n, nil
		}
	}
	return "", nil
}

// followNetworkDevices moves each NIC of the stopped VM vm onto its network's
// current device, before the VM starts: a network whose device changed since
// the domain was defined is provisioned on the new one, the domain's NIC is
// re-pointed there (vm.nic_moved), and the device it left is torn down once
// nothing on this host uses it. A NIC that cannot be moved stays where it is,
// and the VM starts on it as before.
func (s *Server) followNetworkDevices(ctx context.Context, vm string) {
	if s.virt == nil {
		return
	}
	if active, err := s.virt.DomainIsActive(vm); err != nil || active {
		return
	}
	x, err := s.virt.DumpXMLInactive(vm)
	if err != nil {
		return
	}
	have := libvirt.InterfaceBridges(x)
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm)
	if err != nil {
		slog.Warn("start: cannot read the NICs to move onto their networks' devices", "vm", vm, "error", err)
		return
	}
	moved := false
	for _, n := range nics {
		cur, ok := have[strings.ToLower(n.MAC)]
		if !ok {
			continue
		}
		want, ok := s.networkDeviceFor(ctx, n.NetworkName)
		if !ok || want == cur {
			continue
		}
		err := s.moveWorkloadNIC(ctx, n.NetworkName, cur, want,
			func(b string) error { return s.virt.SetNICBridge(vm, n.MAC, b) })
		if err != nil {
			slog.Warn("start: NIC stays on its previous device", "vm", vm, "mac", n.MAC, "from", cur, "to", want, "error", err)
			s.recordVMEvent(ctx, vm, "vm.nic_moved", "error",
				fmt.Sprintf("NIC %s stays on %s; network %s is on %s: %v", n.MAC, cur, n.NetworkName, want, err))
			continue
		}
		moved = true
		s.recordVMEvent(ctx, vm, "vm.nic_moved", "ok",
			fmt.Sprintf("NIC %s moved from %s to %s, the device network %s is on now", n.MAC, cur, want, n.NetworkName))
	}
	if moved {
		s.retirePendingDevices(ctx)
	}
}

// followNetworkDevicesCT is followNetworkDevices for a stopped container.
func (s *Server) followNetworkDevicesCT(ctx context.Context, ct string) {
	l, ok := s.containerRuntime.(containerNICLinker)
	if !ok || s.containerRuntime == nil {
		return
	}
	if st, err := s.containerRuntime.StateContainer(ctx, ct); err != nil || st != "stopped" {
		return
	}
	links, err := l.ContainerNICLinks(ctx, ct)
	if err != nil {
		return
	}
	ifaces, err := corrosion.GetContainerInterfaces(ctx, s.db, s.hostName, ct)
	if err != nil {
		return
	}
	moved := false
	for _, n := range ifaces {
		cur, ok := links[n.Ordinal]
		if !ok {
			continue
		}
		want, ok := s.networkDeviceFor(ctx, n.NetworkName)
		if !ok || want == cur {
			continue
		}
		ord := n.Ordinal
		if err := s.moveWorkloadNIC(ctx, n.NetworkName, cur, want,
			func(b string) error { return l.SetContainerNICLink(ctx, ct, ord, b) }); err != nil {
			slog.Warn("start: container NIC stays on its previous device", "container", ct, "nic", ord, "from", cur, "to", want, "error", err)
			continue
		}
		moved = true
		slog.Info("start: container NIC moved to its network's device", "container", ct, "nic", ord, "from", cur, "to", want)
	}
	if moved {
		s.retirePendingDevices(ctx)
	}
}

// networkDeviceFor is the device network name is on now, when it is a
// managed network whose NICs sit on a bridge.
func (s *Server) networkDeviceFor(ctx context.Context, name string) (string, bool) {
	def, err := lookupNetworkDef(ctx, s.db, name)
	if err != nil || def == nil {
		return "", false // a flat bridge: its name never changes
	}
	dev := network.BridgeName(name, *def)
	if strings.HasPrefix(dev, "direct:") || dev == "" {
		return "", false
	}
	return dev, true
}

// moveWorkloadNIC re-points one stopped workload NIC from device from to
// device to (set), then provisions network on to. The NIC is re-pointed
// first: while it names from, the device it leaves is in use and its gateway
// stays there. A failed provision puts the NIC back.
func (s *Server) moveWorkloadNIC(ctx context.Context, netName, from, to string, set func(bridge string) error) error {
	if err := set(to); err != nil {
		return fmt.Errorf("re-point the NIC: %w", err)
	}
	if _, err := s.provisionForVM(ctx, netName); err != nil {
		// After a restart this process does not know the device the network
		// left; a bridge litevirt made that nothing uses now is swept, and the
		// provision tried once more.
		if s.sweepOneBridge(ctx, from) {
			_, err = s.provisionForVM(ctx, netName)
		}
		if err != nil {
			if rerr := set(from); rerr != nil {
				return fmt.Errorf("provision %s on %s: %w; putting the NIC back on %s failed: %v", netName, to, err, from, rerr)
			}
			return fmt.Errorf("provision %s on %s: %w", netName, to, err)
		}
	}
	return nil
}

// orphanBridgeSweeper is the part of a NetworkProvisioner that finds and
// removes the bridges litevirt created on this host that nothing names any
// more. A provisioner without it is not swept.
type orphanBridgeSweeper interface {
	// CreatedBridges lists the bridges litevirt created here and still has.
	CreatedBridges() ([]string, error)
	// RemoveOrphanedBridge removes one of them, with the dnsmasq that served
	// it, unless anything is plugged into it; it reports whether it did.
	RemoveOrphanedBridge(name string) (bool, error)
}

// sweepOrphanedBridges removes the bridges litevirt created on this host that
// nothing names any more: not a live network, not a deleted one whose
// teardown here is still pending, not a network this process provisioned or a
// device it keeps pending, not a VM's domain, a container's config or a
// guest port, and no VM or container row on this host. They are what a
// network leaves behind when its device changed while this process did not
// see it (a restart, a peer's overwrite of the row), and one that still holds
// its gateway address and dnsmasq makes the network's new device fail to
// start DHCP. It runs before the live networks are provisioned, under the
// reconcile lock.
func (s *Server) sweepOrphanedBridges(ctx context.Context, st *netReconcileState, dead []networkRow) {
	sw, ok := s.networkProvisioner().(orphanBridgeSweeper)
	if !ok {
		return
	}
	bridges, err := sw.CreatedBridges()
	if err != nil {
		slog.Warn("network reconcile: list the bridges litevirt created", "error", err)
		return
	}
	pendingTeardown := map[string]bool{}
	for _, r := range dead {
		if st.torn[r.name] == r.deletedAt {
			continue
		}
		if def, err := networkRowDef(r); err == nil {
			pendingTeardown[network.BridgeName(r.name, def)] = true
		}
	}
	for _, b := range bridges {
		key := "sweep:" + b
		reason, err := s.bridgeKeptBecause(ctx, b, pendingTeardown)
		if err != nil {
			reason = "unknown: " + err.Error()
		}
		if reason != "" {
			if st.lastErr[key] != reason && !strings.HasPrefix(reason, "named:") {
				st.lastErr[key] = reason
				slog.Info("network reconcile: a bridge litevirt made that no network names is kept",
					"bridge", b, "in_use_by", reason)
			}
			continue
		}
		removed, err := s.removeOrphanUnlessNamed(ctx, sw, b, pendingTeardown)
		switch {
		case err != nil:
			if st.lastErr[key] != err.Error() {
				st.lastErr[key] = err.Error()
				slog.Warn("network reconcile: remove a bridge litevirt made that no network names", "bridge", b, "error", err)
			}
		case removed:
			delete(st.lastErr, key)
			slog.Info("network reconcile: removed a bridge litevirt made that no network names any more", "bridge", b)
		}
	}
}

// sweepOneBridge sweeps bridge b alone, outside a reconcile pass, and
// reports whether it removed it.
func (s *Server) sweepOneBridge(ctx context.Context, b string) bool {
	sw, ok := s.networkProvisioner().(orphanBridgeSweeper)
	if !ok {
		return false
	}
	if reason, err := s.bridgeKeptBecause(ctx, b, nil); err != nil || reason != "" {
		return false
	}
	removed, err := s.removeOrphanUnlessNamed(ctx, sw, b, nil)
	return err == nil && removed
}

// bridgeKeptBecause says why bridge b, which litevirt made here, must stay,
// or "" when nothing on this host names or uses it.
func (s *Server) bridgeKeptBecause(ctx context.Context, b string, pendingTeardown map[string]bool) (string, error) {
	if pendingTeardown[b] {
		return "named: a deleted network's pending teardown", nil
	}
	if s.deviceNamedHere(b) {
		return "named: a network provisioned here", nil
	}
	if user, err := s.liveNetworkNaming(ctx, b, ""); err != nil {
		return "", err
	} else if user != "" {
		return "named: network " + user, nil
	}
	if who, err := network.BridgeNamedByWorkload(ctx, s.db, s.hostName, "", b); err != nil || who != "" {
		return who, err
	}
	return s.deviceReference(ctx, b)
}

// deviceNamedHere reports whether this process provisioned a network on b,
// keeps b pending, or is provisioning something on it now.
func (s *Server) deviceNamedHere(b string) bool {
	s.netDevs.mu.Lock()
	defer s.netDevs.mu.Unlock()
	if _, ok := s.netDevs.pending[b]; ok || s.netDevs.inflight[b] > 0 {
		return true
	}
	for n, def := range s.netDevs.defs {
		if network.BridgeName(n, def) == b {
			return true
		}
	}
	return false
}

// removeOrphanUnlessNamed removes b, deciding again with s.netDevs.mu held
// across the decision and the delete: a provision registers its device under
// that lock, after its network's row is written, so none can start on b
// while it goes, and a network written since the first look keeps it.
func (s *Server) removeOrphanUnlessNamed(ctx context.Context, sw orphanBridgeSweeper, b string, pendingTeardown map[string]bool) (bool, error) {
	s.netDevs.mu.Lock()
	defer s.netDevs.mu.Unlock()
	if s.netDevs.inflight[b] > 0 || pendingTeardown[b] {
		return false, nil
	}
	if _, ok := s.netDevs.pending[b]; ok {
		return false, nil
	}
	for n, def := range s.netDevs.defs {
		if network.BridgeName(n, def) == b {
			return false, nil
		}
	}
	if user, err := s.liveNetworkNaming(ctx, b, ""); err != nil || user != "" {
		return false, err
	}
	return sw.RemoveOrphanedBridge(b)
}
