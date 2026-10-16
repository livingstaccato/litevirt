package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
)

// DefaultNetworkDeviceStatePath is where the daemon keeps provisionedDevices:
// under /run, so it survives a daemon restart and goes, with the dnsmasq
// processes and addresses it describes, at a reboot.
const DefaultNetworkDeviceStatePath = "/run/litevirt/network-devices.json"

// provisionedDevices is the definition each network was last provisioned
// with on this host, by every provisioning path (a create, a deploy, a peer's
// ProvisionNetwork, a VM's NIC, the network reconciler), and the devices
// networks moved off that something here still uses. With a state path set
// (SetNetworkDeviceStatePath) both are kept on disk, so a daemon restart
// still knows them.
type provisionedDevices struct {
	mu        sync.Mutex
	statePath string
	loaded    bool
	defs      map[string]compose.NetworkDef
	// pending maps a device a network moved off, still in use on this host,
	// to that network and the definition it was provisioned with: it is
	// retired (retirePendingDevices) once nothing here uses it.
	pending map[string]pendingRetire
	// inflight counts the provisions running per device, so the sweep never
	// removes a device being provisioned.
	inflight map[string]int
	// netLocks serialise the provisions of one network, devLocks those on one
	// device; taken in that order.
	netLocks map[string]*sync.Mutex
	devLocks map[string]*sync.Mutex
}

type pendingRetire struct {
	Network string             `json:"network"`
	Def     compose.NetworkDef `json:"def"`
	// Released: its gateway and dnsmasq went to the network's new device
	// already; only its L2 is kept, for workloads still defined on it.
	Released bool `json:"released,omitempty"`
}

type deviceState struct {
	Defs    map[string]compose.NetworkDef `json:"defs"`
	Pending map[string]pendingRetire      `json:"pending"`
}

// SetNetworkDeviceStatePath keeps this host's network device record at path
// ("" keeps it in memory only).
func (s *Server) SetNetworkDeviceStatePath(path string) {
	s.netDevs.mu.Lock()
	defer s.netDevs.mu.Unlock()
	s.netDevs.statePath, s.netDevs.loaded = path, false
}

// loadLocked reads the record from disk once. Caller holds d.mu.
func (d *provisionedDevices) loadLocked() {
	if d.loaded {
		return
	}
	d.loaded = true
	if d.defs == nil {
		d.defs = map[string]compose.NetworkDef{}
	}
	if d.pending == nil {
		d.pending = map[string]pendingRetire{}
	}
	if d.statePath == "" {
		return
	}
	b, err := os.ReadFile(d.statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("network device record unreadable; starting without it", "path", d.statePath, "error", err)
		}
		return
	}
	var st deviceState
	if err := json.Unmarshal(b, &st); err != nil {
		slog.Warn("network device record unparseable; starting without it", "path", d.statePath, "error", err)
		return
	}
	for k, v := range st.Defs {
		d.defs[k] = v
	}
	for k, v := range st.Pending {
		d.pending[k] = v
	}
}

// saveLocked writes the record. Caller holds d.mu.
func (d *provisionedDevices) saveLocked() {
	if d.statePath == "" {
		return
	}
	b, err := json.Marshal(deviceState{Defs: d.defs, Pending: d.pending})
	if err == nil {
		err = os.MkdirAll(filepath.Dir(d.statePath), 0o755)
	}
	if err == nil {
		tmp := d.statePath + ".tmp"
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, d.statePath)
		}
	}
	if err != nil {
		slog.Warn("network device record not saved; a daemon restart forgets moved-off devices", "path", d.statePath, "error", err)
	}
}

func (d *provisionedDevices) lock(m *map[string]*sync.Mutex, key string) func() {
	d.mu.Lock()
	if *m == nil {
		*m = map[string]*sync.Mutex{}
	}
	l, ok := (*m)[key]
	if !ok {
		l = &sync.Mutex{}
		(*m)[key] = l
	}
	d.mu.Unlock()
	l.Lock()
	return l.Unlock
}

func (d *provisionedDevices) lockNetwork(name string) func() { return d.lock(&d.netLocks, name) }
func (d *provisionedDevices) lockDevice(dev string) func()   { return d.lock(&d.devLocks, dev) }

func (d *provisionedDevices) lastDef(name string) (compose.NetworkDef, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadLocked()
	def, ok := d.defs[name]
	return def, ok
}

func (d *provisionedDevices) setDef(name string, def compose.NetworkDef, ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadLocked()
	if ok {
		d.defs[name] = def
	} else {
		delete(d.defs, name)
	}
	d.saveLocked()
}

func (d *provisionedDevices) setPending(dev string, p *pendingRetire) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadLocked()
	if p != nil {
		d.pending[dev] = *p
	} else {
		delete(d.pending, dev)
	}
	d.saveLocked()
}

// provisionDevice provisions name on this host. When it was last provisioned
// here on another device, that device is dealt with first
// (retireReplacedDevice).
func (s *Server) provisionDevice(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	unlock := s.netDevs.lockNetwork(name)
	defer unlock()
	released, err := s.retireReplacedDevice(ctx, name, def)
	if err != nil {
		return "", err
	}
	dev := network.BridgeName(name, def)
	unlockDev := s.netDevs.lockDevice(dev)
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
	s.netDevs.mu.Unlock()
	unlockDev()
	if err != nil {
		if released != nil {
			// The new device did not come up: the gateway goes back to the
			// device the network's workloads are on.
			if _, rerr := s.networkProvisioner().Provision(ctx, db, name, *released, localIP, hostName); rerr != nil {
				slog.Warn("network move failed; putting the gateway back on the previous device failed too",
					"network", name, "device", network.BridgeName(name, *released), "error", rerr)
			}
			s.netDevs.setPending(network.BridgeName(name, *released), nil)
		}
		return "", err
	}
	s.netDevs.setDef(name, def, true)
	s.netDevs.setPending(dev, nil) // in use by name again
	if released != nil {
		// The gateway is on the new device now: every stopped workload still
		// defined on the old one follows at once, and the old device goes
		// when nothing uses it.
		oldDev := network.BridgeName(name, *released)
		s.repointStoppedOn(ctx, name, oldDev, dev)
		s.retirePendingHeld(ctx, oldDev)
	}
	return got, nil
}

// deprovisionDevice tears name down on this host and forgets its device.
func (s *Server) deprovisionDevice(ctx context.Context, name string, def compose.NetworkDef) error {
	unlock := s.netDevs.lockNetwork(name)
	defer unlock()
	unlockDev := s.netDevs.lockDevice(network.BridgeName(name, def))
	defer unlockDev()
	if err := s.networkProvisioner().Deprovision(ctx, s.db, name, def, s.hostName); err != nil {
		return err
	}
	s.netDevs.setDef(name, compose.NetworkDef{}, false)
	return nil
}

// retireReplacedDevice deals with the device network name was last
// provisioned on here, when def puts the network on another one. Retiring a
// device tears down only what belongs to the device (RetireDevice): the
// network's firewall intent now describes the new one.
//
//   - Another live network names the old device: it is left as it is.
//   - Nothing on this host uses it: it is retired now.
//   - Something does — a guest port, a VM's domain definition, a container's
//     config — and both devices would serve overlapping subnets here: while a
//     running workload is on the old device the move is refused, naming the
//     running workloads; with only stopped ones defined on it, the gateway and
//     dnsmasq move to the new device now (returned as released), and once the
//     new device is up every stopped definition on the old one is re-pointed
//     to it (repointStoppedOn) and the old one retired.
//   - Otherwise the old device is kept whole, pending.
//
// A pending device is retired once nothing uses it (retirePendingDevices).
func (s *Server) retireReplacedDevice(ctx context.Context, name string, def compose.NetworkDef) (*compose.NetworkDef, error) {
	old, ok := s.netDevs.lastDef(name)
	if !ok {
		return nil, nil
	}
	oldDev, newDev := network.BridgeName(name, old), network.BridgeName(name, def)
	if oldDev == newDev {
		return nil, nil
	}
	unlockDev := s.netDevs.lockDevice(oldDev)
	defer unlockDev()
	user, err := s.liveNetworkNaming(ctx, oldDev, name)
	if err != nil {
		return nil, fmt.Errorf("network %q moves from %s to %s: read which networks use %s: %w", name, oldDev, newDev, oldDev, err)
	}
	if user != "" {
		slog.Info("network moved to another device; the previous one stays, another network uses it",
			"network", name, "from", oldDev, "to", newDev, "live_network", user)
		return nil, nil
	}
	users, err := s.deviceUsers(ctx, oldDev)
	if err != nil {
		// Whatever could be read is named beside what could not.
		users.running = append(users.running, "(unknown: "+err.Error()+")")
	}
	prov := s.networkProvisioner()
	if users.none() {
		if err := prov.RetireDevice(ctx, s.db, name, old, s.hostName); err != nil {
			slog.Warn("network moved to another device; retiring the previous one failed, it is retried",
				"network", name, "from", oldDev, "to", newDev, "error", err)
			s.netDevs.setPending(oldDev, &pendingRetire{Network: name, Def: old})
			return nil, nil
		}
		slog.Info("network moved to another device; retired the previous one", "network", name, "from", oldDev, "to", newDev)
		return nil, nil
	}
	collide := network.SubnetsOverlap(old, def) && prov.ServingGateway(name, old) &&
		prov.WouldServeGateway(ctx, s.db, name, def, s.hostName)
	switch {
	case collide && len(users.running) > 0:
		s.netDevs.setPending(oldDev, &pendingRetire{Network: name, Def: old})
		return nil, fmt.Errorf("network %q moves from %s to %s, but %s still running on this host on %s, "+
			"which carries the network's gateway; this host cannot carry it on %s beside it. "+
			"Stop or migrate them: once none runs on %s here the move completes, and each starts on %s",
			name, oldDev, newDev, strings.Join(users.running, ", "), oldDev, newDev, oldDev, newDev)
	case collide:
		prov.ReleaseDeviceServices(name, old)
		s.netDevs.setPending(oldDev, &pendingRetire{Network: name, Def: old, Released: true})
		slog.Info("network moved to another device; its gateway moves now, the previous device stays for workloads defined on it",
			"network", name, "from", oldDev, "to", newDev, "defined_on_it", strings.Join(users.stopped, ", "))
		return &old, nil
	default:
		s.netDevs.setPending(oldDev, &pendingRetire{Network: name, Def: old})
		slog.Info("network moved to another device; the previous one stays until nothing on this host uses it",
			"network", name, "from", oldDev, "to", newDev, "in_use_by", users.String())
		return nil, nil
	}
}

// retirePendingDevices retires each device a network moved off once nothing
// on this host uses it any more, and drops one a live network uses again.
func (s *Server) retirePendingDevices(ctx context.Context) {
	s.netDevs.mu.Lock()
	s.netDevs.loadLocked()
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
		func() {
			unlock := s.netDevs.lockNetwork(p.Network)
			defer unlock()
			s.retirePendingHeld(ctx, dev)
		}()
	}
}

// retirePendingHeld retires pending device dev if nothing on this host uses
// it any more. The caller holds the lock of dev's network.
func (s *Server) retirePendingHeld(ctx context.Context, dev string) {
	s.netDevs.mu.Lock()
	s.netDevs.loadLocked()
	p, ok := s.netDevs.pending[dev]
	s.netDevs.mu.Unlock()
	if !ok {
		return
	}
	unlockDev := s.netDevs.lockDevice(dev)
	defer unlockDev()
	if user, err := s.liveNetworkNaming(ctx, dev, ""); err != nil {
		return
	} else if user != "" {
		s.netDevs.setPending(dev, nil)
		return
	}
	if users, err := s.deviceUsers(ctx, dev); err != nil || !users.none() {
		return
	}
	if err := s.networkProvisioner().RetireDevice(ctx, s.db, p.Network, p.Def, s.hostName); err != nil {
		slog.Warn("network moved off a device; retiring it failed (will retry)",
			"network", p.Network, "device", dev, "error", err)
		return
	}
	s.netDevs.setPending(dev, nil)
	slog.Info("network moved off a device; retired it once nothing on this host used it",
		"network", p.Network, "device", dev)
}

// containerNICLinker is the part of a ContainerRuntime that reads and sets
// the bridge each container NIC links to in its config.
type containerNICLinker interface {
	ContainerNICLinks(ctx context.Context, name string) (map[int]string, error)
	SetContainerNICLink(ctx context.Context, name string, ordinal int, bridge string) error
}

// deviceUse is what on this host uses a device: running workloads (a guest
// port, a running VM's domain, a running container's config) and stopped
// ones whose definitions name it.
type deviceUse struct{ running, stopped []string }

func (u deviceUse) none() bool { return len(u.running) == 0 && len(u.stopped) == 0 }

func (u deviceUse) String() string {
	return strings.Join(append(append([]string(nil), u.running...), u.stopped...), ", ")
}

// deviceUsers reads, from the hypervisor and the container runtime now —
// never from what this process remembers — what on this host uses dev. An
// answer that cannot be read is an error, and the caller keeps the device;
// what could be read is returned with it, so a refusal can name it.
func (s *Server) deviceUsers(ctx context.Context, dev string) (deviceUse, error) {
	all, err := s.deviceUsersAll(ctx)
	u := all[dev]
	ports, perr := s.networkProvisioner().GuestPorts(dev)
	if perr != nil {
		return u, errors.Join(err, fmt.Errorf("read the guests on %s: %w", dev, perr))
	}
	for _, p := range ports {
		u.running = append(u.running, "guest port "+p)
	}
	return u, err
}

// containerRuntimeAbsent reports whether err, from listing the containers,
// is the lookup of a runtime binary that is not installed: a host without the
// lxc-* tooling (lxc.Available) runs no containers. Any other failure is not.
func containerRuntimeAbsent(err error) bool {
	var ee *exec.Error
	return errors.As(err, &ee) && errors.Is(ee.Err, exec.ErrNotFound)
}

// deviceUsersAll maps each bridge any defined VM or container on this host
// names to what names it: one read of every domain and container. A host
// without a container runtime has no containers. When the containers cannot
// be read, the error comes with the VMs read already.
func (s *Server) deviceUsersAll(ctx context.Context) (map[string]deviceUse, error) {
	out := map[string]deviceUse{}
	add := func(dev, who string, running bool) {
		u := out[dev]
		list := &u.stopped
		if running {
			list = &u.running
		}
		for _, w := range *list {
			if w == who {
				return
			}
		}
		*list = append(*list, who)
		out[dev] = u
	}
	if s.virt != nil {
		doms, err := s.virt.ListDomains()
		if err != nil {
			return nil, fmt.Errorf("list the domains: %w", err)
		}
		for _, d := range doms {
			active, err := s.virt.DomainIsActive(d)
			if err != nil {
				return nil, fmt.Errorf("is %s running: %w", d, err)
			}
			x, err := s.virt.DumpXMLInactive(d)
			if err != nil {
				return nil, fmt.Errorf("read the definition of %s: %w", d, err)
			}
			xmls := []string{x}
			if active {
				live, err := s.virt.DumpXML(d)
				if err != nil {
					return nil, fmt.Errorf("read the live definition of %s: %w", d, err)
				}
				xmls = append(xmls, live)
			}
			for _, x := range xmls {
				for _, b := range libvirt.InterfaceBridges(x) {
					add(b, "VM "+d, active)
				}
			}
		}
	}
	if l, ok := s.containerRuntime.(containerNICLinker); ok && s.containerRuntime != nil {
		cts, err := s.containerRuntime.ListContainers(ctx)
		if err != nil && !containerRuntimeAbsent(err) {
			return out, fmt.Errorf("list the containers: %w", err)
		}
		for _, ct := range cts {
			st, err := s.containerRuntime.StateContainer(ctx, ct)
			if err != nil {
				return out, fmt.Errorf("container %s state: %w", ct, err)
			}
			links, err := l.ContainerNICLinks(ctx, ct)
			if err != nil {
				return out, fmt.Errorf("read the NIC links of container %s: %w", ct, err)
			}
			for _, b := range links {
				add(b, "container "+ct, st != "stopped")
			}
		}
	}
	return out, nil
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
// current device, before the VM starts: the network is provisioned on that
// device first, with the VM still defined on the old one, and only then is
// the NIC re-pointed, in the persistent definition (vm.nic_moved). A NIC
// whose network cannot be provisioned stays where it is, and the VM starts
// on it as before; the device it is on is never removed for the attempt.
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
		if _, err := s.provisionForVM(ctx, n.NetworkName); err != nil {
			slog.Warn("start: NIC stays on its previous device", "vm", vm, "mac", n.MAC, "from", cur, "to", want, "error", err)
			s.recordVMEvent(ctx, vm, "vm.nic_moved", "error",
				fmt.Sprintf("NIC %s stays on %s; network %s is on %s, which could not be set up here: %v", n.MAC, cur, n.NetworkName, want, err))
			continue
		}
		if err := s.virt.SetNICBridgeConfig(vm, n.MAC, want); err != nil {
			slog.Warn("start: NIC stays on its previous device", "vm", vm, "mac", n.MAC, "from", cur, "to", want, "error", err)
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

// followNetworkDevicesCT is followNetworkDevices for a stopped container
// (logged, no VM event).
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
		if _, err := s.provisionForVM(ctx, n.NetworkName); err != nil {
			slog.Warn("start: container NIC stays on its previous device", "container", ct, "nic", n.Ordinal, "from", cur, "to", want, "error", err)
			continue
		}
		if err := l.SetContainerNICLink(ctx, ct, n.Ordinal, want); err != nil {
			slog.Warn("start: container NIC stays on its previous device", "container", ct, "nic", n.Ordinal, "from", cur, "to", want, "error", err)
			continue
		}
		moved = true
		slog.Info("start: container NIC moved to its network's device", "container", ct, "nic", n.Ordinal, "from", cur, "to", want)
	}
	if moved {
		s.retirePendingDevices(ctx)
	}
}

// migrationNICBridges maps each NIC of vm (by MAC) whose running domain is on
// another device than the one the target serves its network on (targetDevs,
// from the target's EnsureDisks answer) to that device: the live migration
// lands it there (MigrateParams.NICBridges). A target that is still on the
// device the network moved off — it refused the move — gets the NIC on that
// device; one that moved gets it on the new one. nil targetDevs (an older
// target, or no answer) retargets nothing.
func (s *Server) migrationNICBridges(ctx context.Context, vm string, targetDevs map[string]string) map[string]string {
	if s.virt == nil || len(targetDevs) == 0 {
		return nil
	}
	x, err := s.virt.DumpXML(vm)
	if err != nil {
		return nil
	}
	have := libvirt.InterfaceBridges(x)
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm)
	if err != nil {
		return nil
	}
	var out map[string]string
	for _, n := range nics {
		cur, ok := have[strings.ToLower(n.MAC)]
		if !ok {
			continue
		}
		want := targetDevs[n.NetworkName]
		if want == "" || want == cur {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[n.MAC] = want
	}
	return out
}

// servedNetworkDevices answers a migration source (EnsureDisks): for each
// managed network vm has a NIC on, the device this host serves it on — the
// one it was last provisioned on here, which for a move this host refused is
// still the previous one, else the device the network names now.
func (s *Server) servedNetworkDevices(ctx context.Context, vm string) map[string]string {
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, n := range nics {
		want, ok := s.networkDeviceFor(ctx, n.NetworkName)
		if !ok {
			continue
		}
		if def, ok := s.servedDef(n.NetworkName); ok {
			want = network.BridgeName(n.NetworkName, def)
		}
		out[n.NetworkName] = want
	}
	return out
}

// servedDef is the definition network name was last provisioned with on this
// host, when it puts the network on a bridge: the device this host serves it
// on, which for a move this host refused is still the previous one.
func (s *Server) servedDef(name string) (compose.NetworkDef, bool) {
	def, ok := s.netDevs.lastDef(name)
	if !ok {
		return compose.NetworkDef{}, false
	}
	if d := network.BridgeName(name, def); d == "" || strings.HasPrefix(d, "direct:") {
		return compose.NetworkDef{}, false
	}
	return def, true
}

// vmHasManagedNIC reports whether vm has a NIC on a managed bridge network.
func (s *Server) vmHasManagedNIC(ctx context.Context, vm string) bool {
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm)
	if err != nil {
		return false
	}
	for _, n := range nics {
		if _, ok := s.networkDeviceFor(ctx, n.NetworkName); ok {
			return true
		}
	}
	return false
}

// repointStoppedOn moves every stopped workload on this host whose
// definition names device from onto device to: a stopped VM's persistent
// definition (vm.nic_moved), a stopped container's config. A running one is
// never touched. It runs once a network's gateway has moved from from to to,
// so no start path — one that does not follow its network (a health restart,
// libvirt autostart) — brings a workload back on a device without its
// gateway.
func (s *Server) repointStoppedOn(ctx context.Context, network, from, to string) {
	if s.virt != nil {
		if doms, err := s.virt.ListDomains(); err == nil {
			for _, d := range doms {
				if active, err := s.virt.DomainIsActive(d); err != nil || active {
					continue
				}
				x, err := s.virt.DumpXMLInactive(d)
				if err != nil {
					continue
				}
				for mac, b := range libvirt.InterfaceBridges(x) {
					if b != from {
						continue
					}
					if err := s.virt.SetNICBridgeConfig(d, mac, to); err != nil {
						slog.Warn("network moved; a stopped VM's NIC stays on the previous device until it starts",
							"vm", d, "mac", mac, "from", from, "to", to, "error", err)
						continue
					}
					s.recordVMEvent(ctx, d, "vm.nic_moved", "ok",
						fmt.Sprintf("NIC %s moved from %s to %s, the device network %s is on now", mac, from, to, network))
				}
			}
		}
	}
	l, ok := s.containerRuntime.(containerNICLinker)
	if !ok || s.containerRuntime == nil {
		return
	}
	cts, err := s.containerRuntime.ListContainers(ctx)
	if err != nil {
		return
	}
	for _, ct := range cts {
		if st, err := s.containerRuntime.StateContainer(ctx, ct); err != nil || st != "stopped" {
			continue
		}
		links, err := l.ContainerNICLinks(ctx, ct)
		if err != nil {
			continue
		}
		for ord, b := range links {
			if b != from {
				continue
			}
			if err := l.SetContainerNICLink(ctx, ct, ord, to); err != nil {
				slog.Warn("network moved; a stopped container's NIC stays on the previous device until it starts",
					"container", ct, "nic", ord, "from", from, "to", to, "error", err)
				continue
			}
			slog.Info("network moved; relinked a stopped container's NIC", "container", ct, "nic", ord, "from", from, "to", to)
		}
	}
}

// FollowNetworkDevices is followNetworkDevices for a start path outside this
// package (the health checker's restart).
func (s *Server) FollowNetworkDevices(ctx context.Context, vm string) {
	s.followNetworkDevices(ctx, vm)
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
// teardown here is still pending, not a network provisioned here or a device
// kept pending, not a VM's domain, a container's config or a guest port, and
// no VM or container row on this host. They are what a network leaves behind
// when its device changed while no record of it was kept (an older build, a
// peer's overwrite of the row). It runs before the live networks are
// provisioned, under the reconcile lock; the domains and containers are read
// once per pass.
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
	if len(bridges) == 0 {
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
	users, uerr := s.deviceUsersAll(ctx)
	for _, b := range bridges {
		key := "sweep:" + b
		reason := ""
		switch {
		case uerr != nil:
			reason = "unknown: " + uerr.Error()
		case !users[b].none():
			reason = users[b].String()
		default:
			r, err := s.bridgeKeptBecause(ctx, b, pendingTeardown)
			if err != nil {
				r = "unknown: " + err.Error()
			}
			reason = r
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

// bridgeKeptBecause says why bridge b, which litevirt made here and no
// workload's definition names, must stay, or "".
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
	ports, err := s.networkProvisioner().GuestPorts(b)
	if err != nil {
		return "", err
	}
	if len(ports) > 0 {
		return "guest port " + strings.Join(ports, ", "), nil
	}
	return "", nil
}

// deviceNamedHere reports whether a network was provisioned on b here, b is
// kept pending, or something is being provisioned on it now.
func (s *Server) deviceNamedHere(b string) bool {
	s.netDevs.mu.Lock()
	defer s.netDevs.mu.Unlock()
	return s.deviceNamedHereLocked(b)
}

func (s *Server) deviceNamedHereLocked(b string) bool {
	s.netDevs.loadLocked()
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

// removeOrphanUnlessNamed removes b under its device lock and s.netDevs.mu,
// deciding again there: a provision registers its device under that lock,
// after its network's row is written, so none can start on b while it goes;
// a network written since the first look keeps it; and the domains and
// containers are read once more, so a domain defined on b since (an incoming
// migration's) keeps it too.
func (s *Server) removeOrphanUnlessNamed(ctx context.Context, sw orphanBridgeSweeper, b string, pendingTeardown map[string]bool) (bool, error) {
	unlockDev := s.netDevs.lockDevice(b)
	defer unlockDev()
	s.netDevs.mu.Lock()
	defer s.netDevs.mu.Unlock()
	if pendingTeardown[b] || s.deviceNamedHereLocked(b) {
		return false, nil
	}
	if user, err := s.liveNetworkNaming(ctx, b, ""); err != nil || user != "" {
		return false, err
	}
	all, err := s.deviceUsersAll(ctx)
	if err != nil {
		return false, err
	}
	if !all[b].none() {
		return false, nil
	}
	return sw.RemoveOrphanedBridge(b)
}
