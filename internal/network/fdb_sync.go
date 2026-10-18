package network

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// SyncFloodEntries brings vxlan<VNI>'s forwarding table to the replicated
// state of networkName.
//
// Flood (BUM) entries: one for every peer's VTEP row, none for this host. Then
// a flood entry is pruned when its address is neither a VTEP of the network
// nor a live host's registered address — a peer's VTEP from before it moved,
// or a host that has gone. A live host's address is kept though no VTEP row
// names it yet: a peer that has just provisioned pushes its VTEP before its
// row replicates here.
//
// Unicast entries: one for every live NIC on the network — a VM's, from
// vm_interfaces and vm_nics, and a container's — that sits on another host
// with a VTEP row, pointing the NIC's MAC at that host's VTEP. An entry for
// such a MAC that points anywhere else is replaced, and a unicast entry whose
// address is not a current VTEP is removed. So a recreated vxlan device gets
// its entries back, and a peer whose VTEP moved is repointed.
//
// Every entry, flood or unicast, whose destination is one of this host's own
// addresses is removed and never installed (refuseLocalDst). A peer row naming
// one is skipped rather than refused: during an upgrade a peer on an earlier
// build can still register an address that is also this host's.
func SyncFloodEntries(ctx context.Context, db *corrosion.Client, networkName, hostName string, vni int) error {
	return syncFDB(ctx, db, hostFDB(), networkName, hostName, vni, "", "")
}

// SyncPeerVTEP is SyncFloodEntries for a peer that has just sent its VTEP
// (SyncVTEP): peerAddr stands in for whatever peer's network_vteps row says
// here, because that row may not have replicated yet — and if it still holds
// the peer's previous address, re-adding that is exactly the stale entry the
// prune removes.
func SyncPeerVTEP(ctx context.Context, db *corrosion.Client, networkName, hostName string, vni int, peer, peerAddr string) error {
	return syncFDB(ctx, db, hostFDB(), networkName, hostName, vni, peer, peerAddr)
}

// SyncFDB is SyncFloodEntries for a provisioned network's definition: a no-op
// for anything but a vxlan network.
func SyncFDB(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, hostName string) error {
	if def.Type != "vxlan" || def.VNI == 0 {
		return nil
	}
	return SyncFloodEntries(ctx, db, networkName, hostName, def.VNI)
}

// SyncFDBWith is SyncFDB on a host modelled by the caller: its `bridge fdb`
// commands go to exec, and its own addresses are local. The fleet harness
// runs each node's sync against that node's own model of the kernel table.
func SyncFDBWith(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, hostName string,
	exec ExecFunc, local []string) error {
	if def.Type != "vxlan" || def.VNI == 0 {
		return nil
	}
	o := fdbOps{exec: exec, local: localAddrs{}}
	for _, a := range local {
		o.local[a] = ""
	}
	return syncFDB(ctx, db, o, networkName, hostName, def.VNI, "", "")
}

func syncFDB(ctx context.Context, db *corrosion.Client, o fdbOps, networkName, hostName string, vni int, peer, peerAddr string) error {
	local := o.local
	vteps, err := GetVTEPs(ctx, db, networkName)
	if err != nil {
		return fmt.Errorf("get vteps: %w", err)
	}

	hostVTEP := map[string]string{} // peer host → its VTEP
	for _, v := range vteps {
		if v.HostName == hostName || v.VTEPAddr == "" {
			continue
		}
		hostVTEP[v.HostName] = v.VTEPAddr
	}
	if peerAddr != "" && peer != hostName {
		hostVTEP[peer] = peerAddr
	}

	want := map[string]bool{} // flood destinations
	for h, a := range hostVTEP {
		if local.has(a) {
			// A peer row naming this host: skipped, see above.
			if logOnce("peer|" + networkName + "|" + h + "|" + a) {
				slog.Warn("vxlan: a peer's VTEP is an address of this host's; not flooding to it until the peer registers another",
					"network", networkName, "peer", h, "vtep", a)
			}
			continue
		}
		want[a] = true
	}
	addrs := make([]string, 0, len(want))
	for a := range want {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	for _, a := range addrs {
		if err := o.appendFlood(vni, a); err != nil {
			return fmt.Errorf("flood entry %s: %w", a, err)
		}
	}

	wantUni := map[string]string{} // MAC → VTEP of the host the NIC is on
	nics, err := remoteNICs(ctx, db, networkName, hostName)
	if err != nil {
		slog.Warn("vxlan: read the network's NICs for unicast entries", "network", networkName, "error", err)
	}
	for mac, h := range nics {
		if a, ok := hostVTEP[h]; ok && !local.has(a) {
			wantUni[mac] = a
		}
	}

	keepFlood := map[string]bool{}
	for a := range want {
		keepFlood[a] = true
	}
	hostsKnown := true
	if hosts, err := corrosion.ListHosts(ctx, db); err == nil {
		for _, h := range hosts {
			if h.Name != hostName && h.Address != "" {
				keepFlood[h.Address] = true
			}
		}
	} else {
		hostsKnown = false
		slog.Warn("vxlan: list hosts for flood-entry pruning; keeping every flood entry not proven stale", "error", err)
	}

	entries, err := o.list(vni)
	if err != nil {
		slog.Warn("vxlan: read forwarding entries", "vni", vni, "error", err)
	}
	present := map[string]bool{}
	for _, e := range entries {
		mac := strings.ToLower(e.MAC)
		switch {
		case local.has(e.Dst):
			slog.Warn("vxlan: removing a forwarding entry that points at this host's own address",
				"vni", vni, "mac", mac, "dst", e.Dst)
			if mac == floodMAC {
				_ = o.del(vni, floodMAC, e.Dst)
			} else {
				_ = o.del(vni, mac, e.Dst)
			}
		case mac == floodMAC:
			if hostsKnown && !keepFlood[e.Dst] {
				slog.Info("vxlan: removing a stale flood entry", "vni", vni, "dst", e.Dst)
				_ = o.del(vni, floodMAC, e.Dst)
			}
		default:
			d, wanted := wantUni[mac]
			switch {
			case wanted && d == e.Dst:
				present[mac] = true
			case wanted || !want[e.Dst]:
				// Repointed (the NIC's host has another VTEP now), or
				// pointing at an address that is no VTEP of the network.
				slog.Info("vxlan: removing a stale unicast entry", "vni", vni, "mac", mac, "dst", e.Dst)
				_ = o.del(vni, mac, e.Dst)
			}
		}
	}
	macs := make([]string, 0, len(wantUni))
	for mac := range wantUni {
		if !present[mac] {
			macs = append(macs, mac)
		}
	}
	sort.Strings(macs)
	for _, mac := range macs {
		if err := o.addUnicast(vni, mac, wantUni[mac]); err != nil {
			slog.Warn("vxlan: add unicast entry", "vni", vni, "mac", mac, "dst", wantUni[mac], "error", err)
		}
	}
	return nil
}

// remoteNICs maps the MAC of every live NIC on networkName that is not on
// hostName to the host it is on: VM NICs (vm_interfaces, vm_nics) by their
// VM's host, and container NICs by their own.
func remoteNICs(ctx context.Context, db *corrosion.Client, networkName, hostName string) (map[string]string, error) {
	rows, err := db.Query(ctx,
		`SELECT v.host_name AS host, i.mac AS mac FROM vm_interfaces i JOIN vms v ON v.name = i.vm_name
		  WHERE i.network_name = ? AND i.deleted_at IS NULL AND v.deleted_at IS NULL
		 UNION
		 SELECT v.host_name AS host, n.mac AS mac FROM vm_nics n JOIN vms v ON v.name = n.vm_name
		  WHERE n.network_name = ? AND n.deleted_at IS NULL AND v.deleted_at IS NULL
		 UNION
		 SELECT host_name AS host, mac FROM container_interfaces
		  WHERE network_name = ? AND deleted_at IS NULL`,
		networkName, networkName, networkName)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		h, mac := r.String("host"), strings.ToLower(r.String("mac"))
		if h == "" || mac == "" || h == hostName {
			continue
		}
		out[mac] = h
	}
	return out, nil
}
