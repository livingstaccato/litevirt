package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// maxIfaceName is the Linux interface-name limit (IFNAMSIZ - 1). Names longer
// than this are rejected by `ip link add` ("Attribute failed policy
// validation") on kernels that enforce it, and silently truncated on older
// ones (risking collisions).
const maxIfaceName = 15

// IsolatedBridgeName returns the host bridge name for an isolated network
// (compose.IsolatedBridgeName, which the firewall shares).
func IsolatedBridgeName(networkName string) string {
	return compose.IsolatedBridgeName(networkName)
}

// FlatBridgeName returns the host bridge a NIC on a network with no record
// attaches to (flat-bridge mode). It is the network name itself when that fits
// IFNAMSIZ, so every bridge that exists today keeps its name across a rolling
// upgrade. A longer name could never be created (EnsureBridge refuses it), so
// it maps to the stable hashed form "lvf-<11 hex>" (exactly 15 chars) instead
// of failing the VM create or the leftover-bridge cleanup forever. Every site
// that creates or removes a flat bridge MUST use this so the names agree.
func FlatBridgeName(networkName string) string {
	return compose.FlatBridgeName(networkName)
}

// ValidateBridgeNetworkName refuses a plain bridge network whose bridge name
// (its interface, or its own name when none is given) cannot be a Linux
// interface: over 15 bytes the bridge can never be created, so the network would
// persist and then fail every VM placed on it. Other types name their device
// themselves (hashed, VNI or a given interface).
func ValidateBridgeNetworkName(netType, networkName, iface string) error {
	if netType != "" && netType != "bridge" {
		return nil
	}
	dev := iface
	if dev == "" {
		dev = networkName
	}
	if len(dev) > maxIfaceName {
		return fmt.Errorf("bridge name %q is %d bytes; a Linux interface name is at most %d. Give the network a shorter name or set --iface to a shorter bridge", dev, len(dev), maxIfaceName)
	}
	return nil
}

// BridgeName returns the host device a NIC on networkName attaches to: the
// same name Provision returns for def. Code that needs the device without
// provisioning (hot attach, restart, containers) must use this, so the NIC
// and the provisioned bridge always agree.
//
// A "direct" network answers "direct:<iface>", as Provision does. A network
// missing the field its type keys on (vni, pf, interface) falls back to its
// own name, which is the flat-bridge answer.
func BridgeName(networkName string, def compose.NetworkDef) string {
	switch def.Type {
	case "vxlan":
		if def.VNI != 0 {
			return vxlanBridgeName(def.VNI)
		}
	case "isolated":
		return IsolatedBridgeName(networkName)
	case "sriov":
		if def.PF != "" {
			return def.PF
		}
		return networkName
	case "direct":
		if def.Interface != "" {
			return "direct:" + def.Interface
		}
		return networkName
	}
	if def.Interface != "" {
		return def.Interface
	}
	return FlatBridgeName(networkName)
}

// bridgePreExistedFor is whether bridge counts as one litevirt found already
// there for def, the fact the DHCP gate reads (see Provision). One predicate,
// so WouldServeGateway answers as Provision acts.
func bridgePreExistedFor(def compose.NetworkDef, bridge string) bool {
	return BridgeExists(bridge) &&
		(def.NetBoxPrefixID != 0 || !litevirtServedDHCP(dnsmasqPidFile(bridge)))
}

// VTEPRecord holds a host's VTEP information for a network.
type VTEPRecord struct {
	NetworkName string
	HostName    string
	VTEPAddr    string
	VNI         int
}

// Provision ensures network infra for def exists. Returns bridge name for libvirt.
// type="" or "bridge": returns def.Interface (zero new code, flat mode)
// type="vxlan": EnsureVXLAN, UpsertVTEP, SyncFloodEntries; if Subnet != "" also EnsureIRB
// type="isolated": create bridge with no uplink
// type="sriov": return def.PF
func Provision(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	switch def.Type {
	case "", "bridge":
		// Ensure the bridge exists; create it if missing.
		bridge := def.Interface
		if bridge == "" {
			return "", fmt.Errorf("bridge network requires interface name")
		}
		// Check if bridge pre-exists before we touch anything. Pre-existing
		// bridges (infrastructure bridges like br0) should not get DHCP/NAT
		// added unless the user explicitly enables them.
		//
		// A litevirt dnsmasq pidfile for the bridge overrides that: litevirt
		// served DHCP here, so the bridge is litevirt's (or --dhcp named it),
		// whatever its existence says now. Without it, a dnsmasq that died on
		// a bridge litevirt made would never be restarted — the bridge exists
		// on every pass after the first — and the reconciler, reading the dead
		// pidfile, would re-provision forever. A NetBox-bound network is left
		// to the plain fact: its refusal below must read the same host state
		// on every attempt.
		pidFile := dnsmasqPidFile(bridge)
		bridgePreExisted := bridgePreExistedFor(def, bridge)

		// REFUSE BEFORE CREATING ANYTHING, and this ordering is the whole of
		// whether the refusal survives a retry.
		//
		// The check used to live inside startDHCPFor, below EnsureBridge. So the
		// first attempt CREATED the bridge and then refused — and the second read
		// a pre-existing bridge, which is the one input that turns DHCPWouldServe
		// off for this shape, and provisioned successfully with no DHCP server on
		// a subnet-ful network. Guests with no addresses and no explanation,
		// which is the outcome startDHCPFor's own comment says it refuses in
		// order to avoid. Hoisted here, the refusal reads the same host state
		// every time and a retry refuses identically.
		//
		// startDHCPFor still asks the same question, for the other two dnsmasq
		// sites (isolated, vxlan) which do not create a bridge this way; it is
		// one exported predicate, not two copies.
		if err := BoundNetworkDHCPRefusal(def,
			DHCPHostFacts{BridgePreExisted: bridgePreExisted}, networkName, bridge,
			hostName); err != nil {
			return "", err
		}

		if err := EnsureBridge(bridge); err != nil {
			return "", err
		}
		// A bridge litevirt made (its record says so), with no VLAN and no
		// uplink, gets the network's MAC, the same on every host
		// (BridgeMAC). An operator's bridge, and a bridge that shares
		// one L2 with the other hosts' (a VLAN, an uplink), keep their own.
		if def.VLAN == 0 && bridgeRecorded(bridge) {
			if BridgeHasUplink(bridge) {
				warnSharedMACOnUplink(networkName, bridge)
			} else {
				ensureNetworkBridgeMAC(networkName, bridge, def.Subnet)
			}
		}

		// If a VLAN ID is specified, create a VLAN sub-interface on the
		// default-route interface (or explicit underlay) and attach it to
		// the bridge. This gives VMs direct L2 access to the tagged VLAN.
		if def.VLAN > 0 {
			if err := EnsureBridgeVLAN(bridge, def.VLAN, def.Underlay); err != nil {
				return "", fmt.Errorf("bridge VLAN setup: %w", err)
			}
		}

		// When a VLAN is set, the bridge is on a physical network — VMs
		// talk directly to the VLAN's router. Skip DHCP/NAT/proxy ARP
		// (same logic as pre-existing bridges).
		onPhysicalVLAN := def.VLAN > 0

		scope := fwScopeNet(networkName)
		if def.HostIsolation || onPhysicalVLAN {
			clearStaleDnsmasqPidFile(pidFile) // no DHCP here
		}
		if def.HostIsolation {
			// Host-isolated: no DHCP, no NAT. IPs delivered via cloud-init.
			if err := corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{
				ScopeKey: scope, Bridge: bridge, Isolate: true,
			}); err != nil {
				return "", fmt.Errorf("record host-isolation intent for %s: %w", bridge, err)
			}
			// The guests' gateway, on a bridge litevirt made: the host routes
			// for them (an LB's SNAT), as a vxlan network's IRB gateway does,
			// and the isolation drop keeps every guest off the address itself.
			// A bridge litevirt did not make, or one on a physical VLAN, has
			// its router upstream, which this address would collide with.
			if def.Subnet != "" && !onPhysicalVLAN && bridgeCreatedHere(bridge) {
				if gw, _, _, _, err := SubnetRange(def.Subnet); err == nil && gw != "" {
					if out, err := execCommand("ip", "addr", "add", gw, "dev", bridge); err != nil && !isAlreadyExists(out) {
						return "", fmt.Errorf("ip addr add %s dev %s: %w: %s", gw, bridge, err, out)
					}
				}
			}
		} else if !onPhysicalVLAN {
			// Start DHCP only on a litevirt-managed bridge — a pre-existing
			// infrastructure bridge (e.g. br0) must not get a DHCP server unless
			// the user explicitly enabled it. The gate is still keyed on
			// (!bridgePreExisted || def.DHCP); it lives in DHCPWouldServe now
			// because the NetBox bind-time refusal decides from the same
			// predicate, and two copies of it would drift.
			if err := startDHCPFor(def, DHCPHostFacts{BridgePreExisted: bridgePreExisted},
				networkName, bridge, hostName, pidFile); err != nil {
				return "", err
			}
			// Record NAT (masquerade) intent whenever this managed subnet-network
			// wants NAT — independent of the DHCP-start gate above. On a
			// re-provision the bridge always exists, so gating NAT on
			// !bridgePreExisted would drop the intent and strand the network on
			// the pre-consolidation iptables rule; the empty-subnet check keeps
			// infra bridges (no subnet, e.g. br0) untouched. Matches the vxlan
			// case, which already records NAT on Subnet != "" && NATEnabled().
			natSubnet := ""
			if def.Subnet != "" && def.NATEnabled() {
				if err := EnableIPForwarding(); err != nil {
					return "", err
				}
				natSubnet = def.Subnet
			}
			if err := recordNATOrClear(ctx, db, hostName, scope, bridge, natSubnet); err != nil {
				return "", err
			}
			// Enable proxy ARP only when the host IS the VM gateway — i.e., NAT
			// is active (same condition as the masquerade intent above).
			if natSubnet != "" {
				if err := EnsureProxyARP(bridge); err != nil {
					slog.Warn("proxy ARP setup failed (VMs may be unreachable from outside)", "bridge", bridge, "error", err)
				}
			}
		} else {
			// Physical VLAN — litevirt manages no NAT/isolation here; clear stale intent.
			if err := corrosion.DeleteHostFWIntent(ctx, db, hostName, scope); err != nil {
				return "", err
			}
		}
		return bridge, nil

	case "vxlan":
		vni := def.VNI
		if vni == 0 {
			return "", fmt.Errorf("vxlan network requires vni")
		}
		if localIP == "" {
			return "", &VTEPRefusal{Network: networkName, Reason: "no tunnel local address was resolved for this host"}
		}
		underlay := def.Underlay
		if underlay == "" {
			underlay = defaultRouteInterface()
		}
		if underlay == "" {
			return "", fmt.Errorf("vxlan network requires underlay interface (could not auto-detect; set 'underlay' explicitly)")
		}

		bridge, err := EnsureVXLAN(vni, underlay, localIP)
		if err != nil {
			return "", fmt.Errorf("ensure vxlan vni %d: %w", vni, err)
		}

		// Register this host's VTEP under the logical network name — unless
		// the network was deleted while this pass ran: the upsert clears
		// deleted_at, and would bring a tombstoned row back to life.
		if deleted, err := networkTombstoned(ctx, db, networkName); err != nil {
			return "", fmt.Errorf("read network %q: %w", networkName, err)
		} else if deleted {
			return "", fmt.Errorf("vxlan network %q was deleted; not registering this host's VTEP", networkName)
		}
		if err := UpsertVTEP(ctx, db, networkName, hostName, localIP, vni); err != nil {
			return "", fmt.Errorf("upsert vtep: %w", err)
		}

		// Brief delay for CRDT convergence before reading peer VTEPs.
		time.Sleep(500 * time.Millisecond)

		// Sync flood entries from all known VTEPs
		if err := SyncFloodEntries(ctx, db, networkName, hostName, vni); err != nil {
			return "", fmt.Errorf("sync flood entries: %w", err)
		}

		natSubnet := ""
		if def.Subnet == "" || def.HostIsolation {
			clearStaleDnsmasqPidFile(dnsmasqPidFileVNI(vni)) // no DHCP here
		}
		if def.Subnet != "" {
			// IRB (anycast gateway) is always set up — VMs need a default route.
			if _, err := EnsureIRB(vni, def.Subnet); err != nil {
				return "", fmt.Errorf("ensure irb: %w", err)
			}

			if def.HostIsolation {
				// Host-isolated: no DHCP, no NAT. IPs delivered via cloud-init.
				// IRB gateway stays for routing (FORWARD), but INPUT is dropped.
			} else {
				if def.NATEnabled() {
					if err := EnableIPForwarding(); err != nil {
						return "", err
					}
					natSubnet = def.Subnet
				}
				if err := startDHCPFor(def,
					DHCPHostFacts{IsGatewayHost: isGatewayHost(ctx, db, networkName, hostName)},
					networkName, bridge, hostName, dnsmasqPidFileVNI(vni)); err != nil {
					return "", err
				}
			}
		}

		// Record NAT/isolation intent for the canonical firewall reconciler.
		scope := fwScopeNet(networkName)
		if def.HostIsolation {
			if err := corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{
				ScopeKey: scope, Bridge: bridge, Isolate: true,
			}); err != nil {
				return "", fmt.Errorf("record host-isolation intent for %s: %w", bridge, err)
			}
		} else if err := recordNATOrClear(ctx, db, hostName, scope, bridge, natSubnet); err != nil {
			return "", err
		}

		return bridge, nil

	case "isolated":
		// Create a bridge with no uplink; IsolatedBridgeName keeps the name
		// within IFNAMSIZ even for long network names.
		bridge := IsolatedBridgeName(networkName)
		out, err := execCommand("ip", "link", "add", bridge, "type", "bridge")
		if err != nil && !isFileExists(out) {
			return "", fmt.Errorf("ip link add isolated bridge: %w: %s", err, out)
		}
		// The interface group is what the firewall holds the bridge to the
		// host by (compose.IsolatedBridgeGroup), set before the bridge is up.
		// Every network is provisioned again on a daemon's first pass, which
		// marks a bridge an earlier build made.
		if out, err := execCommand("ip", "link", "set", bridge, "group", strconv.Itoa(compose.IsolatedBridgeGroup)); err != nil {
			return "", fmt.Errorf("ip link set %s group %d: %w: %s", bridge, compose.IsolatedBridgeGroup, err, out)
		}
		out, err = execCommand("ip", "link", "set", bridge, "up")
		if err != nil && !isFileExists(out) {
			return "", fmt.Errorf("ip link set %s up: %w: %s", bridge, err, out)
		}
		if !BridgeHasUplink(bridge) {
			ensureNetworkBridgeMAC(networkName, bridge, def.Subnet)
		}

		scope := fwScopeNet(networkName)
		if def.HostIsolation {
			clearStaleDnsmasqPidFile(dnsmasqPidFile(bridge)) // no DHCP here
			// Host-isolated: no DHCP. IPs delivered via cloud-init.
			if err := corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{
				ScopeKey: scope, Bridge: bridge, Isolate: true,
			}); err != nil {
				return "", fmt.Errorf("record host-isolation intent for %s: %w", bridge, err)
			}
		} else {
			// Not isolated and no uplink → no NAT either; clear any stale intent.
			if err := corrosion.DeleteHostFWIntent(ctx, db, hostName, scope); err != nil {
				return "", err
			}
			// If subnet is defined, enable DHCP implicitly — an isolated network
			// has no uplink and no router, so litevirt is the only possible
			// source of addresses. DHCPWouldServe says so for every host, which
			// is why a bind over an isolated network's subnet is refused
			// cluster-wide rather than on the binding node's own evidence.
			if err := startDHCPFor(def, DHCPHostFacts{},
				networkName, bridge, hostName, dnsmasqPidFile(bridge)); err != nil {
				return "", err
			}
			if def.Subnet != "" {
				// NAT is skipped for isolated networks — they have no uplink.
				if def.NAT != nil && *def.NAT {
					slog.Warn("NAT requested on isolated network (no uplink) — skipping", "network", networkName)
				}
			}
		}

		return bridge, nil

	case "sriov":
		return def.PF, nil

	case "direct":
		// macvtap: VM attaches directly to the interface via macvtap.
		// No bridge needed. Return the interface name prefixed with "direct:"
		// so the caller knows to use macvtap XML instead of bridge XML.
		iface := def.Interface
		if iface == "" {
			return "", fmt.Errorf("direct network requires interface name")
		}
		if _, err := net.InterfaceByName(iface); err != nil {
			return "", fmt.Errorf("direct network interface %q not found: %w", iface, err)
		}
		// Ensure a macvlan companion exists so the host can communicate with
		// macvtap guests on the same parent interface (kernel limitation).
		ensureMacvlan(iface)
		return "direct:" + iface, nil

	default:
		return "", fmt.Errorf("unknown network type %q", def.Type)
	}
}

// Deprovision tears down network infrastructure for def on this host.
// It is the inverse of Provision: stops DHCP, removes bridges/VXLAN/IRB.
// networkName is the logical network name (used for isolated bridge naming).
//
// It deletes this network's firewall intent, so the canonical reconciler drops
// its litevirt-fw NAT/isolation chains on the next pass.
func Deprovision(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, hostName string) error {
	if db != nil {
		_ = corrosion.DeleteHostFWIntent(ctx, db, hostName, fwScopeNet(networkName))
	}
	return RetireDevice(ctx, db, networkName, def, hostName)
}

// RetireDevice tears down what def's device carries for networkName on this
// host — its dnsmasq, gateway address, the proxy-ARP rules of that device, its VLAN sub-interface, and the bridge when
// litevirt created it and nothing uses it — and nothing keyed by the network
// itself: the network's firewall intent stays. It is the teardown of a device
// a network has moved off, whose intent now describes the new device.
func RetireDevice(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, hostName string) error {
	switch def.Type {
	case "", "bridge":
		bridge := def.Interface
		if bridge == "" {
			return nil
		}
		RemoveProxyARP(bridge)
		// Stop DHCP and remove the gateway IP if subnet was configured.
		if def.Subnet != "" {
			pidFile := dnsmasqPidFile(bridge)
			stopDHCPAndForgetLeases(pidFile, bridge)
			// Remove the gateway IP that StartDHCP added to the bridge.
			//
			// SubnetRange already returns the gateway WITH its prefix (see
			// dnsmasq.go: "10.0.1.128/25" -> gateway "10.0.1.129/25"), so it is
			// used as-is. Appending the subnet's prefix again produced
			// "10.0.1.1/24/24", which iproute2 rejects — and because the error is
			// deliberately discarded here, the address silently stayed on the
			// bridge for good, including through SafeProvision's rollback.
			if gw, _, _, _, err := SubnetRange(def.Subnet); err == nil && gw != "" {
				execCommand("ip", "addr", "del", gw, "dev", bridge) //nolint:errcheck
			}
		}
		// Remove VLAN sub-interface if we created one.
		if def.VLAN > 0 {
			RemoveBridgeVLAN(bridge, def.VLAN, def.Underlay)
		}
		// The bridge itself goes only when litevirt created it here, no other
		// live network names it, and no workload on this host attaches to it;
		// an operator's bridge is never deleted.
		removeCreatedBridge(ctx, db, networkName, bridge, hostName)
		return nil

	case "vxlan":
		vni := def.VNI
		if vni == 0 {
			return nil
		}
		bridge := vxlanBridgeName(vni)
		// Remove the IRB gateway if subnet was set.
		if def.Subnet != "" {
			RemoveIRB(vni, def.Subnet) //nolint:errcheck
			pidFile := dnsmasqPidFileVNI(vni)
			stopDHCPAndForgetLeases(pidFile, bridge)
		}
		return DeprovisionVXLAN(vni)

	case "isolated":
		bridge := IsolatedBridgeName(networkName)
		// Stop DHCP if subnet was configured.
		if def.Subnet != "" {
			pidFile := dnsmasqPidFile(bridge)
			stopDHCPAndForgetLeases(pidFile, bridge)
		}
		// Delete the isolated bridge (litevirt created it, safe to remove).
		out, err := execCommand("ip", "link", "del", bridge)
		if err != nil && !isNoSuchDevice(out) {
			return fmt.Errorf("ip link del %s: %w: %s", bridge, err, out)
		}
		return nil

	case "sriov":
		// SR-IOV PF is not managed by litevirt; nothing to tear down.
		return nil

	case "direct":
		// macvtap: nothing to tear down — the tap device is removed with the VM.
		return nil

	default:
		return fmt.Errorf("unknown network type %q", def.Type)
	}
}

// removeCreatedBridge removes bridge, the device of bridge network
// networkName that is being torn down, when this host's record says
// EnsureBridge created it (RemoveCreatedBridgeIfUnused), no OTHER live
// network uses it as its device, and no VM or container on hostName attaches
// to it (BridgeNamedByWorkload). networkName itself does not count as a
// network: its own delete deprovisions before it tombstones the row.
//
// Every teardown of a bridge network reaches the bridge here — `lv network
// rm`, a stack delete, and the network reconciler's teardown of a tombstone —
// so the workload check guards all of them.
//
// It is best effort and never fails the teardown: a bridge it cannot prove
// unshared, or cannot remove, stays, as every bridge network's bridge did
// before. Without a database there is no way to prove the bridge unshared, so
// it stays.
func removeCreatedBridge(ctx context.Context, db *corrosion.Client, networkName, bridge, hostName string) {
	if db == nil {
		return
	}
	live, err := corrosion.ListNetworks(ctx, db)
	if err != nil {
		slog.Warn("network teardown: cannot read the live networks, so the bridge stays",
			"network", networkName, "bridge", bridge, "error", err)
		return
	}
	for _, r := range live {
		if r.Name == networkName {
			continue
		}
		var def compose.NetworkDef
		if r.Config != "" {
			if err := json.Unmarshal([]byte(r.Config), &def); err != nil {
				slog.Warn("network teardown: a live network's config is unreadable, so the bridge stays",
					"network", networkName, "bridge", bridge, "live_network", r.Name, "error", err)
				return
			}
		}
		def.Type = r.Type
		if BridgeName(r.Name, def) == bridge || (def.Interface == "" && r.Name == bridge) {
			slog.Info("network teardown: another live network uses the bridge, so it stays",
				"network", networkName, "bridge", bridge, "live_network", r.Name)
			return
		}
	}
	if who, err := BridgeNamedByWorkload(ctx, db, hostName, networkName, bridge); err != nil {
		slog.Warn("network teardown: cannot read this host's workload NICs, so the bridge stays",
			"network", networkName, "bridge", bridge, "error", err)
		return
	} else if who != "" {
		slog.Info("network teardown: a workload on this host still attaches to the bridge, so it stays",
			"network", networkName, "bridge", bridge, "workload", who)
		return
	}
	removed, err := RemoveCreatedBridgeIfUnused(bridge)
	switch {
	case err != nil:
		slog.Warn("network teardown: removing the bridge litevirt created failed; it stays",
			"network", networkName, "bridge", bridge, "error", err)
	case removed:
		slog.Info("network teardown: removed the bridge litevirt created", "network", networkName, "bridge", bridge)
	}
}

// BridgeNamedByWorkload names a live VM or container on hostName with a NIC
// that attaches to bridge, or returns "" when there is none. A NIC attaches to
// it when it names networkName (a `--force` delete leaves its NICs in place),
// names the bridge itself (a flat-bridge NIC, `--network <bridge>`), names
// another network — live or deleted — whose device is the bridge, or is a
// container's raw `bridge=` NIC, which has no interface row and is found in
// its create spec.
//
// The bridge's ports cannot answer this: a stopped VM has no tap on it, and a
// VM start does not re-create its bridge, so removing it leaves that VM
// unable to start. An error means the answer is unknown, and the caller keeps
// the bridge: a leaked bridge is harmless, a missing one is not.
func BridgeNamedByWorkload(ctx context.Context, db *corrosion.Client, hostName, networkName, bridge string) (string, error) {
	// The device each network name resolves to, from every network row,
	// live or deleted: a VM's domain keeps the bridge it was defined with
	// after its network is deleted. A name with no row is a flat bridge.
	netRows, err := db.Query(ctx, `SELECT name, type, config FROM networks`)
	if err != nil {
		return "", fmt.Errorf("read networks: %w", err)
	}
	netDev := map[string]string{}
	badDef := map[string]error{}
	for _, r := range netRows {
		name := r.String("name")
		var def compose.NetworkDef
		if c := r.String("config"); c != "" {
			if err := json.Unmarshal([]byte(c), &def); err != nil {
				badDef[name] = err
				continue
			}
		}
		def.Type = r.String("type")
		netDev[name] = BridgeName(name, def)
	}
	attaches := func(n string) (bool, error) {
		if n == "" {
			return false, nil
		}
		if n == networkName || n == bridge || FlatBridgeName(n) == bridge {
			return true, nil
		}
		if err, bad := badDef[n]; bad {
			return false, fmt.Errorf("network %s: config: %w", n, err)
		}
		return netDev[n] == bridge, nil
	}

	for _, q := range []string{
		`SELECT 'VM ' || vi.vm_name AS w, vi.network_name AS n FROM vm_interfaces vi
		   JOIN vms v ON v.name = vi.vm_name
		  WHERE v.host_name = ? AND v.deleted_at IS NULL AND vi.deleted_at IS NULL`,
		`SELECT 'VM ' || vn.vm_name AS w, vn.network_name AS n FROM vm_nics vn
		   JOIN vms v ON v.name = vn.vm_name
		  WHERE v.host_name = ? AND v.deleted_at IS NULL AND vn.deleted_at IS NULL`,
		`SELECT 'container ' || ci.ct_name AS w, ci.network_name AS n FROM container_interfaces ci
		   JOIN containers c ON c.host_name = ci.host_name AND c.name = ci.ct_name
		  WHERE ci.host_name = ? AND c.deleted_at IS NULL AND ci.deleted_at IS NULL`,
	} {
		rows, err := db.Query(ctx, q, hostName)
		if err != nil {
			return "", err
		}
		for _, r := range rows {
			hit, err := attaches(r.String("n"))
			if err != nil {
				return "", fmt.Errorf("%s: %w", r.String("w"), err)
			}
			if hit {
				return r.String("w"), nil
			}
		}
	}

	// A container's raw-bridge NIC has no interface row; its create spec
	// holds the bridge.
	rows, err := db.Query(ctx,
		`SELECT name, COALESCE(create_spec, '') AS create_spec FROM containers
		  WHERE host_name = ? AND deleted_at IS NULL`, hostName)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		raw := r.String("create_spec")
		if raw == "" {
			continue
		}
		var spec corrosion.ContainerCreateSpec
		if err := json.Unmarshal([]byte(raw), &spec); err != nil {
			return "", fmt.Errorf("container %s: create spec: %w", r.String("name"), err)
		}
		for _, n := range spec.Networks {
			if n.Bridge == bridge {
				return "container " + r.String("name"), nil
			}
			hit, err := attaches(n.NetworkName)
			if err != nil {
				return "", fmt.Errorf("container %s: %w", r.String("name"), err)
			}
			if hit {
				return "container " + r.String("name"), nil
			}
		}
	}
	return "", nil
}

// fwScopeNet is the host_fw_intent scope key for a network's provisioning
// decision (its LB counterpart is "lb:<name>", written by the LB path).
func fwScopeNet(networkName string) string { return "net:" + networkName }

// recordNATOrClear upserts a masquerade intent for (bridge, natSubnet) when
// natSubnet is set, or deletes any stale intent for the scope when it isn't — so a
// network that loses NAT (or never had it) leaves no orphaned masquerade behind.
func recordNATOrClear(ctx context.Context, db *corrosion.Client, hostName, scope, bridge, natSubnet string) error {
	if natSubnet == "" {
		return corrosion.DeleteHostFWIntent(ctx, db, hostName, scope)
	}
	return corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{
		ScopeKey: scope, Bridge: bridge, MasqueradeSubnet: natSubnet,
	})
}

// isNoSuchDevice returns true if the command output indicates the device does not exist.
func isNoSuchDevice(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "Cannot find device") || strings.Contains(s, "No such device")
}

// networkTombstoned reports whether networkName has a deleted record and no
// live one. A network with no record at all is not.
func networkTombstoned(ctx context.Context, db *corrosion.Client, networkName string) (bool, error) {
	rows, err := db.Query(ctx,
		`SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END), 0) AS live
		 FROM networks WHERE name = ?`, networkName)
	if err != nil || len(rows) == 0 {
		return false, err
	}
	return rows[0].Int("n") > 0 && rows[0].Int("live") == 0, nil
}

// UpsertVTEP writes this host's VTEP into network_vteps.
func UpsertVTEP(ctx context.Context, db *corrosion.Client, networkName, hostName, vtepIP string, vni int) error {
	now := db.NowTS()
	return db.Execute(ctx,
		`INSERT INTO network_vteps (network_name, host_name, vtep_ip, vni, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(network_name, host_name) DO UPDATE SET
		   vtep_ip = excluded.vtep_ip,
		   vni = excluded.vni,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		networkName, hostName, vtepIP, vni, now,
	)
}

// GetVTEPs returns all active VTEPs for a network.
func GetVTEPs(ctx context.Context, db *corrosion.Client, networkName string) ([]VTEPRecord, error) {
	rows, err := db.Query(ctx,
		`SELECT network_name, host_name, vtep_ip, vni
		 FROM network_vteps WHERE network_name = ? AND deleted_at IS NULL`,
		networkName)
	if err != nil {
		return nil, err
	}

	vteps := make([]VTEPRecord, len(rows))
	for i, r := range rows {
		vteps[i] = VTEPRecord{
			NetworkName: r.String("network_name"),
			HostName:    r.String("host_name"),
			VTEPAddr:    r.String("vtep_ip"),
			VNI:         r.Int("vni"),
		}
	}
	return vteps, nil
}

// isGatewayHost returns true if hostName is the elected DHCP gateway for this
// VXLAN network. The gateway is the first VTEP host by lexical hostname order,
// ensuring deterministic, convergent election without coordination.
func isGatewayHost(ctx context.Context, db *corrosion.Client, networkName, hostName string) bool {
	vteps, err := GetVTEPs(ctx, db, networkName)
	if err != nil || len(vteps) == 0 {
		return true // no peers yet — we're the gateway
	}
	sort.Slice(vteps, func(i, j int) bool { return vteps[i].HostName < vteps[j].HostName })
	return vteps[0].HostName == hostName
}

// ProvisionFunc provisions one network on this host and returns the device a
// NIC attaches to. SafeProvision is the production one.
type ProvisionFunc func(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, localIP, hostName string) (string, error)

// ProvisionForVMWith looks up a network definition from corrosion and calls
// provision to ensure all infrastructure (bridge, DHCP, NAT, VXLAN, IRB)
// exists on this host. Returns the bridge name, or "" if no provisioning is
// needed (flat bridge mode). It hands provision no VTEP address (""): the
// provisioner resolves the tunnel endpoint itself
// (grpcapi.Server.ProvisionNetworkHere), and network.Provision refuses a
// vxlan network without one.
func ProvisionForVMWith(ctx context.Context, db *corrosion.Client, networkName, hostName string, provision ProvisionFunc) (string, error) {
	rows, err := db.Query(ctx,
		`SELECT type, config FROM networks WHERE name = ? AND deleted_at IS NULL`,
		networkName)
	if err != nil || len(rows) == 0 {
		return "", nil // not in DB — flat bridge mode
	}

	netType := rows[0].String("type")
	configJSON := rows[0].String("config")

	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(configJSON), &def); err != nil {
		return "", fmt.Errorf("parse network config: %w", err)
	}
	def.Type = netType
	if def.Interface == "" {
		def.Interface = networkName
	}

	bridge, err := provision(ctx, db, networkName, def, "", hostName)
	if err != nil {
		return "", err
	}
	return bridge, nil
}
