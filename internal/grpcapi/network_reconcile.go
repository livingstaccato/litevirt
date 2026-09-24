package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/network"
)

// defaultNetworkReconcileInterval is how often each host converges its own
// network devices on the replicated networks table.
const defaultNetworkReconcileInterval = 30 * time.Second

// netReconcileState is what THIS process has done to this host's network
// devices. It is in memory on purpose: a restart starts empty, so the first
// pass provisions every live network again (dnsmasq is a child process and
// died with the daemon) and tears down every tombstoned one.
type netReconcileState struct {
	mu sync.Mutex
	// applied maps a live network to the definition this process provisioned,
	// so an unchanged network is not provisioned again every pass.
	applied map[string]appliedNetwork
	// torn maps a tombstoned network to the deleted_at this process tore down,
	// so a tombstone is acted on once, and again if the name is re-created and
	// deleted a second time.
	torn map[string]string
	// lastErr is the last provisioning error logged per network, so a network
	// that keeps failing logs once per distinct error, not once per pass.
	lastErr map[string]string
}

type appliedNetwork struct {
	sig string
	def compose.NetworkDef
}

type networkRow struct {
	name, typ, config, deletedAt string
}

func networkRowDef(r networkRow) (compose.NetworkDef, error) {
	var def compose.NetworkDef
	if r.config != "" {
		if err := json.Unmarshal([]byte(r.config), &def); err != nil {
			return def, err
		}
	}
	def.Type = r.typ
	if def.Interface == "" {
		def.Interface = r.name
	}
	return def, nil
}

// StartNetworkReconciler runs RunNetworkReconcile in the background. interval
// <= 0 means the default.
func (s *Server) StartNetworkReconciler(ctx context.Context, interval time.Duration) {
	go s.RunNetworkReconcile(ctx, interval)
}

// RunNetworkReconcile converges this host's network devices on the networks
// table every interval until ctx is cancelled. The first pass waits one
// interval: the daemon runs ReconcileNetworksOnce itself at startup.
func (s *Server) RunNetworkReconcile(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = defaultNetworkReconcileInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.ReconcileNetworksOnce(ctx); err != nil {
				slog.Warn("network reconcile pass failed", "error", err)
			}
		}
	}
}

// ReconcileNetworksOnce makes this host's network devices match the networks
// table, which every host replicates:
//
//   - every live network is provisioned here, unless this process already
//     provisioned the same definition. This is what puts a network created on
//     one node onto every other node, onto a node that joins later, and back
//     onto a node after a restart.
//   - every tombstoned network is torn down here, once. This is what removes a
//     network deleted on one node from every other node, including one that
//     was down when the delete happened.
//
// A tombstone whose device a live network also uses is skipped: tearing it
// down would pull the bridge, gateway or dnsmasq out from under the live one.
//
// Every step is idempotent, so a pass that races a create, a delete or a VM's
// own provisioning converges on the next one.
func (s *Server) ReconcileNetworksOnce(ctx context.Context) error {
	rows, err := s.db.Query(ctx,
		`SELECT name, type, config, COALESCE(deleted_at, '') AS deleted_at FROM networks`)
	if err != nil {
		return fmt.Errorf("list networks: %w", err)
	}
	var live, dead []networkRow
	for _, r := range rows {
		nr := networkRow{
			name: r.String("name"), typ: r.String("type"),
			config: r.String("config"), deletedAt: r.String("deleted_at"),
		}
		// A row with no config was never provisioned by any path (the VM path
		// refuses to parse it), so there is nothing to set up or tear down.
		if nr.config == "" {
			continue
		}
		if nr.deletedAt == "" {
			live = append(live, nr)
		} else {
			dead = append(dead, nr)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].name < live[j].name })
	sort.Slice(dead, func(i, j int) bool { return dead[i].name < dead[j].name })

	st := &s.netReconcile
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.applied == nil {
		st.applied = map[string]appliedNetwork{}
		st.torn = map[string]string{}
		st.lastErr = map[string]string{}
	}

	prov := s.networkProvisioner()
	localIP := getLocalIP()
	changed := false

	// Tear down first, so a device a tombstone shares with nothing live is
	// gone before anything is provisioned in its place.
	liveNames := map[string]bool{}
	liveDevices := map[string]string{} // device → live network using it
	for _, r := range live {
		liveNames[r.name] = true
		if def, err := networkRowDef(r); err == nil {
			liveDevices[network.BridgeName(r.name, def)] = r.name
		}
	}
	for _, r := range dead {
		if liveNames[r.name] || st.torn[r.name] == r.deletedAt {
			continue
		}
		def, err := networkRowDef(r)
		if err != nil {
			st.torn[r.name] = r.deletedAt // unparseable: nothing we could tear down by it
			continue
		}
		if user, shared := liveDevices[network.BridgeName(r.name, def)]; shared {
			slog.Info("network reconcile: not tearing down a deleted network whose device a live network uses",
				"network", r.name, "device", network.BridgeName(r.name, def), "live_network", user)
			st.torn[r.name] = r.deletedAt
			delete(st.applied, r.name)
			continue
		}
		if err := prov.Deprovision(ctx, s.db, r.name, def, s.hostName); err != nil {
			slog.Warn("network reconcile: tear down deleted network failed (will retry)",
				"network", r.name, "error", err)
			continue
		}
		st.torn[r.name] = r.deletedAt
		delete(st.applied, r.name)
		changed = true
	}
	// A network this process provisioned whose row is gone altogether.
	present := map[string]bool{}
	for _, r := range rows {
		present[r.String("name")] = true
	}
	for name, a := range st.applied {
		if present[name] {
			continue
		}
		if err := prov.Deprovision(ctx, s.db, name, a.def, s.hostName); err != nil {
			slog.Warn("network reconcile: tear down vanished network failed (will retry)",
				"network", name, "error", err)
			continue
		}
		delete(st.applied, name)
		changed = true
	}

	for _, r := range live {
		sig := r.typ + "\x00" + r.config
		if a, ok := st.applied[r.name]; ok && a.sig == sig {
			// Unchanged and set up by this process. Provision again only if the
			// host lost it since: a dnsmasq that died, a bridge someone deleted.
			if prov.Provisioned(r.name, a.def) {
				continue
			}
			slog.Warn("network reconcile: this host lost the network's bridge or dnsmasq; provisioning it again",
				"network", r.name)
		}
		def, err := networkRowDef(r)
		if err != nil {
			s.noteNetworkReconcileErr(st, r.name, fmt.Errorf("parse config: %w", err))
			continue
		}
		if _, err := prov.Provision(ctx, s.db, r.name, def, localIP, s.hostName); err != nil {
			s.noteNetworkReconcileErr(st, r.name, err)
			continue
		}
		delete(st.lastErr, r.name)
		st.applied[r.name] = appliedNetwork{sig: sig, def: def}
		changed = true
		slog.Info("network reconciled", "network", r.name, "type", r.typ)
		if def.Type == "vxlan" && def.VNI != 0 {
			s.notifyVTEPPeers(ctx, r.name, def.VNI, localIP)
		}
	}

	if changed {
		s.reconcileFirewall(ctx)
	}
	return nil
}

func (s *Server) noteNetworkReconcileErr(st *netReconcileState, name string, err error) {
	if st.lastErr[name] == err.Error() {
		return
	}
	st.lastErr[name] = err.Error()
	slog.Warn("network reconcile: provision failed (will retry)", "network", name, "error", err)
}
