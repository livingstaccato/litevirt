package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// provisionedDevices is the definition each network was last provisioned
// with on this host by this process, by every provisioning path (a create, a
// deploy, a peer's ProvisionNetwork, a VM's NIC, the network reconciler). It
// is what names the device a network leaves when its definition moves it to
// another one. A restart empties it; sweepOrphanedBridges covers that case.
type provisionedDevices struct {
	mu   sync.Mutex
	defs map[string]compose.NetworkDef
}

// provisionDevice provisions name on this host, first tearing down the device
// this process last provisioned it on when def names another one
// (retireReplacedDevice).
func (s *Server) provisionDevice(ctx context.Context, db *corrosion.Client, name string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	s.netDevs.mu.Lock()
	defer s.netDevs.mu.Unlock()
	if err := s.retireReplacedDevice(ctx, name, def); err != nil {
		return "", err
	}
	dev, err := s.networkProvisioner().Provision(ctx, db, name, def, localIP, hostName)
	if err == nil {
		if s.netDevs.defs == nil {
			s.netDevs.defs = map[string]compose.NetworkDef{}
		}
		s.netDevs.defs[name] = def
	}
	return dev, err
}

// deprovisionDevice tears name down on this host and forgets its device.
func (s *Server) deprovisionDevice(ctx context.Context, name string, def compose.NetworkDef) error {
	s.netDevs.mu.Lock()
	defer s.netDevs.mu.Unlock()
	if err := s.networkProvisioner().Deprovision(ctx, s.db, name, def, s.hostName); err != nil {
		return err
	}
	delete(s.netDevs.defs, name)
	return nil
}

// retireReplacedDevice tears down the device this process last provisioned
// network name on, when def puts it on another one. Two definitions of one
// network on two devices hold the same gateway address, and the second
// dnsmasq cannot start.
//
// A device another live network names is left as it is. A device a guest on
// this host is still plugged into is refused: tearing it down would take the
// guest's gateway and DHCP away, and the guest only moves to the new device
// when it restarts. The caller's provision fails, and the reconciler retries
// it every pass until the guest has left. Caller holds s.netDevs.mu.
func (s *Server) retireReplacedDevice(ctx context.Context, name string, def compose.NetworkDef) error {
	old, ok := s.netDevs.defs[name]
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
		delete(s.netDevs.defs, name)
		return nil
	}
	ports, err := s.networkProvisioner().GuestPorts(oldDev)
	if err != nil {
		return fmt.Errorf("network %q moves from %s to %s: read the guests on %s: %w", name, oldDev, newDev, oldDev, err)
	}
	if len(ports) > 0 {
		return fmt.Errorf("network %q moves from %s to %s, but guest port %s on this host is still on %s; "+
			"restart the guest (or stop it) so it attaches to %s, and the move completes",
			name, oldDev, newDev, strings.Join(ports, ", "), oldDev, newDev)
	}
	if err := s.networkProvisioner().Deprovision(ctx, s.db, name, old, s.hostName); err != nil {
		return fmt.Errorf("network %q moves from %s to %s: tear down %s: %w", name, oldDev, newDev, oldDev, err)
	}
	delete(s.netDevs.defs, name)
	slog.Info("network moved to another device; tore down the previous one", "network", name, "from", oldDev, "to", newDev)
	return nil
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
// no network names any more: not a live network, not a deleted one whose
// teardown here is still pending, not a network this process provisioned, and
// no VM or container on this host. They are what a network leaves behind when
// its device changed while this process did not see it (a restart, a peer's
// overwrite of the row), and one that still holds its gateway address and
// dnsmasq makes the network's new device fail to start DHCP. It runs before
// the live networks are provisioned, under the reconcile lock.
func (s *Server) sweepOrphanedBridges(ctx context.Context, st *netReconcileState, live, dead []networkRow) {
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
	named := map[string]bool{}
	for _, r := range live {
		def, err := networkRowDef(r)
		if err != nil {
			return // a device this network names cannot be known
		}
		named[network.BridgeName(r.name, def)] = true
	}
	for _, r := range dead {
		if st.torn[r.name] == r.deletedAt {
			continue
		}
		def, err := networkRowDef(r)
		if err != nil {
			continue // nothing the reconciler could tear down by it either
		}
		named[network.BridgeName(r.name, def)] = true
	}
	s.netDevs.mu.Lock()
	for n, def := range s.netDevs.defs {
		named[network.BridgeName(n, def)] = true
	}
	s.netDevs.mu.Unlock()

	for _, b := range bridges {
		if named[b] {
			continue
		}
		key := "sweep:" + b
		if who, err := network.BridgeNamedByWorkload(ctx, s.db, s.hostName, "", b); err != nil || who != "" {
			reason := who
			if err != nil {
				reason = "unknown: " + err.Error()
			}
			if st.lastErr[key] != reason {
				st.lastErr[key] = reason
				slog.Info("network reconcile: a bridge litevirt made that no network names is kept; a workload on this host attaches to it",
					"bridge", b, "workload", reason)
			}
			continue
		}
		removed, err := sw.RemoveOrphanedBridge(b)
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
