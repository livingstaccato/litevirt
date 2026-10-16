package grpcapi

// A NIC's identity on its segment — MAC, IPv4 and IPv6 address — is what its
// guard holds it to, so it must be its own: an explicit value that another
// live NIC already holds is refused at assignment (a tenant naming a
// victim's MAC or address in a create request would otherwise have the guard
// enforce the impersonation for it). And a guarded NIC on a network litevirt
// serves DHCP for gets an exact address, reserved in dnsmasq, instead of
// "anything in the subnet".

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// checkNICIdentities refuses explicit MACs and addresses another live NIC
// holds, and addresses a network keeps for itself. project is the project of
// the workload the NICs are for; owners are the names whose own rows do not
// count (the VM being created, and the one it re-creates).
func (s *Server) checkNICIdentities(ctx context.Context, project string, atts []*pb.NetworkAttachment, owners ...string) error {
	explicit := false
	for _, a := range atts {
		if a != nil && (a.GetMac() != "" || a.GetIp() != "" || a.GetIpv6() != "") {
			explicit = true
		}
	}
	if !explicit {
		return nil
	}
	ids, err := corrosion.LiveNICIdentities(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Internal, "read NIC identities: %v", err)
	}
	mine := map[string]bool{}
	for _, o := range owners {
		mine[o] = true
	}
	guards, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Internal, "read NIC guards: %v", err)
	}
	var infos map[string]corrosion.NetworkGuardInfo
	seenMAC := map[string]bool{}
	for _, a := range atts {
		if a == nil {
			continue
		}
		if m := strings.ToLower(a.GetMac()); m != "" {
			if seenMAC[m] {
				return status.Errorf(codes.InvalidArgument, "MAC %s is given to two NICs of this request", m)
			}
			seenMAC[m] = true
			for _, id := range ids {
				if id.MAC == m && !mine[id.Owner] {
					return status.Errorf(codes.AlreadyExists, "MAC %s is already used by %s", m, id.Owner)
				}
			}
		}
		if ip := a.GetIp(); ip != "" {
			if infos == nil {
				if infos, err = corrosion.NetworkGuardInfos(ctx, s.db); err != nil {
					return status.Errorf(codes.Internal, "read networks: %v", err)
				}
			}
			if err := s.checkAddrFree(ctx, project, a.GetName(), ip, ids, mine, infos[a.GetName()]); err != nil {
				return err
			}
		}
		if v6 := strings.TrimSpace(a.GetIpv6()); v6 != "" {
			addr := canonAddr(v6)
			if addr == "" {
				return status.Errorf(codes.InvalidArgument, "ipv6 %q is not an IPv6 address", v6)
			}
			for _, r := range guards {
				for _, k := range r.Known {
					if k == addr && !mine[r.VMName] {
						return status.Errorf(codes.AlreadyExists, "IPv6 address %s is already assigned to %s", addr, r.VMName)
					}
				}
			}
		}
	}
	return nil
}

// checkAddrFree refuses an explicit address on a network litevirt manages
// when it is one of the subnet's own addresses (network, broadcast), the
// network's router or a reserved address (re-review I-9: the gateway litevirt
// puts on the bridge where it does, the configured gateway and reserved
// addresses — never simply network+1), a gateway other projects' NICs route
// through, or another NIC's. On a NetBox-bound network NetBox decides, as it
// always has.
//
// A gateway only VMs of the caller's own project route through stays
// claimable: a project may run its own router. A caller with network.update on
// the network may claim any NIC-declared gateway.
func (s *Server) checkAddrFree(ctx context.Context, project, netName, ip string, ids []corrosion.AddrOwner, mine map[string]bool, info corrosion.NetworkGuardInfo) error {
	addr := canonAddr(ip)
	if addr == "" {
		return nil // the create path reports a malformed address itself
	}
	if alloc, _, err := s.allocatorFor(ctx, "vm", netName); err == nil && alloc != nil {
		return nil
	}
	a, _ := netip.ParseAddr(addr)
	if sp, err := netip.ParsePrefix(strings.TrimSpace(info.Subnet)); err == nil && sp.Addr().Is4() == a.Is4() {
		sp = sp.Masked()
		if sp.Contains(a) && sp.Bits() < sp.Addr().BitLen()-1 && (a == sp.Addr() || (a.Is4() && a == lastAddr(sp))) {
			return status.Errorf(codes.InvalidArgument,
				"%s is the network or broadcast address of %s; it cannot be a NIC's", addr, netName)
		}
	}
	for _, r := range append([]string{info.LitevirtGateway}, info.Reserved...) {
		if r != "" && r == addr {
			return status.Errorf(codes.InvalidArgument,
				"%s is the gateway or a reserved address of network %q; it cannot be a NIC's", addr, netName)
		}
	}
	for _, d := range info.NICGateways {
		if d.Addr != addr || mine[d.VM] || tenancy.NormalizeProject(d.Project) == tenancy.NormalizeProject(project) {
			continue
		}
		if err := s.requireGuardAuthority(ctx, netName, "claiming "+addr+", the gateway "+d.VM+" routes through,"); err != nil {
			return status.Errorf(codes.InvalidArgument,
				"%s is the gateway VM %s routes through on network %q; claiming it needs network.update there", addr, d.VM, netName)
		}
	}
	for _, id := range ids {
		if id.Network == netName && id.Addr == addr && !mine[id.Owner] {
			return status.Errorf(codes.AlreadyExists, "address %s on network %q is already used by %s", addr, netName, id.Owner)
		}
	}
	return nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	for i := 0; i < 32; i++ {
		if i >= p.Bits() {
			b[i/8] |= 0x80 >> (i % 8)
		}
	}
	return netip.AddrFrom4(b)
}

func canonAddr(s string) string {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return ""
}

// dhcpReservable reports whether a new NIC should get an exact DHCP
// reservation: it will be guarded (its record can be written and it is on),
// it named no address, and its network's DHCP is served by this host's
// dnsmasq ALONE — an isolated network, or a host-local bridge (no VLAN, no
// uplink) — since the reservation is made here (re-review I-8). On vxlan the
// elected gateway host serves, and on a bridge with an uplink another server
// may answer first; a guest given a dynamic address there would be dropped by
// its exact guard for the whole lease. Such a NIC is guarded to its subnet
// instead (docs/firewall.md, "Which addresses a guarded NIC may use").
func (s *Server) dhcpReservable(att *pb.NetworkAttachment, def *compose.NetworkDef) bool {
	if att.GetIp() != "" || def == nil || !def.DHCP || def.Subnet == "" || !s.db.MayWriteClusterPolicy() {
		return false
	}
	if mode, err := normalizeNICGuardMode(att.GetSpoofGuard()); err != nil || mode != corrosion.NICGuardOn {
		return false
	}
	if def.NetBoxPrefixID != 0 || def.HostIsolation {
		return false
	}
	switch def.Type {
	case "", "bridge":
		if def.VLAN != 0 {
			return false
		}
	case "isolated":
	default:
		return false // vxlan: another host may serve; sriov, direct: no bridge
	}
	p, err := netip.ParsePrefix(def.Subnet)
	if err != nil || !p.Addr().Is4() {
		return false
	}
	bridge := network.BridgeName(att.GetName(), *def)
	served, uplink := network.DHCPServedHere, network.BridgeHasUplink
	if s.dhcpServedHere != nil {
		served = s.dhcpServedHere
	}
	if s.bridgeHasUplink != nil {
		uplink = s.bridgeHasUplink
	}
	return served(bridge) && (def.Type == "isolated" || !uplink(bridge))
}

// reserveDHCPAddress picks a free address for mac on netName and reserves it
// in the local dnsmasq at once (the guest asks within seconds of starting).
// Free means: no live NIC row or lease holds it, the local dnsmasq has not
// leased it, and no create in flight on this host just took it. A MAC the
// local dnsmasq has already leased an address to (a re-created VM that kept
// its MAC) keeps that address when nothing else holds it (re-review I-11).
// dhcpReservable has established that this host's dnsmasq is the network's
// only server, so one host decides each address.
func (s *Server) reserveDHCPAddress(ctx context.Context, netName, subnet, bridge, mac string) (string, error) {
	assigned, err := corrosion.NetworkAssignedAddrs(ctx, s.db)
	if err != nil {
		return "", err
	}
	s.dhcpResMu.Lock()
	defer s.dhcpResMu.Unlock()
	s.prunePendingLocked()
	taken := map[string]bool{}
	for _, a := range assigned[netName] {
		taken[a] = true
	}
	for ip := range s.dhcpPending[netName] {
		taken[ip] = true
	}
	ip := ""
	if own := canonAddr(network.LeasedAddrFor(bridge, mac)); own != "" && !taken[own] {
		if sp, perr := netip.ParsePrefix(subnet); perr == nil {
			if a, aerr := netip.ParseAddr(own); aerr == nil && sp.Masked().Contains(a) && a != sp.Masked().Addr().Next() {
				ip = own
			}
		}
	}
	if ip == "" {
		used := append([]string(nil), network.LeasedAddrs(bridge)...)
		for a := range taken {
			used = append(used, a)
		}
		if ip, err = network.NextFreeIP(subnet, used); err != nil {
			return "", err
		}
	}
	add := network.AddDHCPHost
	if s.addDHCPHost != nil {
		add = s.addDHCPHost
	}
	if err := add(bridge, mac, ip); err != nil {
		return "", err
	}
	if s.dhcpPending[netName] == nil {
		s.dhcpPending[netName] = map[string]dhcpPendingRes{}
	}
	s.dhcpPending[netName][ip] = dhcpPendingRes{mac: strings.ToLower(mac), at: time.Now()}
	return ip, nil
}

// hostIsolatedAddress picks the address a new NIC on host-isolated network
// netName is given. Free means: no live NIC row or lease on the network holds
// it, it is not the network's gateway, one of its reserved addresses or a
// load balancer's VIP (a live lb_configs row's, or one of vips, those of the
// workload being created), and no create in flight on this host just took
// it. The NIC row records it, and the seed's network-config delivers it to
// the guest as a static address. The caller releases the pick
// (releaseHostIsolatedPicks) once its rows are written or its create failed.
//
// The pick is decided from this node's replica, so two creates on two hosts
// in the same moment could pick alike. The scan starts at an offset hashed
// from this host and the network, which makes that unlikely short of a
// nearly full subnet; a duplicate that happens anyway is reported by the
// firewall reconciler (firewall.DuplicateAddressReporter).
func (s *Server) hostIsolatedAddress(ctx context.Context, netName string, def *compose.NetworkDef, vips []string) (string, error) {
	lbs, err := corrosion.ListLBConfigs(ctx, s.db)
	if err != nil {
		return "", err
	}
	s.dhcpResMu.Lock()
	defer s.dhcpResMu.Unlock()
	// Read under the lock: a container's lease on this host is written under
	// it too (claimContainerAddress), so neither misses the other.
	assigned, err := corrosion.NetworkAssignedAddrs(ctx, s.db)
	if err != nil {
		return "", err
	}
	s.pruneIsoPendingLocked()
	used := append([]string(nil), assigned[netName]...)
	for ip := range s.isoPending[netName] {
		used = append(used, ip)
	}
	if def.Gateway != "" {
		used = append(used, def.Gateway)
	}
	used = append(used, def.ReservedAddresses...)
	for _, lb := range lbs {
		used = append(used, lb.VIP)
	}
	used = append(used, vips...)
	ip, err := network.NextFreeIPv4From(def.Subnet, used, s.isoScanOffset(netName))
	if err != nil {
		return "", err
	}
	if s.isoPending[netName] == nil {
		s.isoPending[netName] = map[string]time.Time{}
	}
	s.isoPending[netName][ip] = time.Now()
	return ip, nil
}

// stackVIPs are the load balancer VIPs the stack's VMs already recorded
// name in their specs: an LB row is written only after its stack's VMs, so
// a VM created after one that names a VIP must still pass over it. A VIP
// named by a VM of the stack created later is not known yet
// (docs/compose.md: list it in reserved-addresses). Read only; a read
// failure gives none.
func (s *Server) stackVIPs(ctx context.Context, stack string) []string {
	if stack == "" {
		return nil
	}
	vms, err := corrosion.ListVMs(ctx, s.db, stack, "")
	if err != nil {
		slog.Warn("host-isolated pick: could not read the stack's VMs for their VIPs", "stack", stack, "error", err)
		return nil
	}
	var out []string
	for _, vm := range vms {
		var spec pb.VMSpec
		if json.Unmarshal([]byte(vm.Spec), &spec) != nil {
			continue
		}
		if lb := spec.GetLoadbalancer(); lb != nil && lb.GetVip() != "" {
			out = append(out, lb.GetVip())
		}
	}
	return out
}

// isoScanOffset is where this host's scan of netName's subnet starts.
func (s *Server) isoScanOffset(netName string) uint64 {
	if s.isoOffset != nil {
		return s.isoOffset(netName)
	}
	h := fnv.New64a()
	h.Write([]byte(s.hostName + "\x00" + netName))
	return h.Sum64()
}

// isoPick is one address hostIsolatedAddress handed out.
type isoPick struct{ network, ip string }

// releaseHostIsolatedPicks drops picks from the in-flight set: their rows are
// written (and now hold the address) or their create failed.
func (s *Server) releaseHostIsolatedPicks(picks []isoPick) {
	if len(picks) == 0 {
		return
	}
	s.dhcpResMu.Lock()
	defer s.dhcpResMu.Unlock()
	for _, p := range picks {
		delete(s.isoPending[p.network], p.ip)
		if len(s.isoPending[p.network]) == 0 {
			delete(s.isoPending, p.network)
		}
	}
}

// pruneIsoPendingLocked drops in-flight picks older than any create takes to
// write its rows. Caller holds dhcpResMu.
func (s *Server) pruneIsoPendingLocked() {
	if s.isoPending == nil {
		s.isoPending = map[string]map[string]time.Time{}
	}
	for n, m := range s.isoPending {
		for ip, at := range m {
			if time.Since(at) > 10*time.Minute {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(s.isoPending, n)
		}
	}
}

// isoPendingAddrs is a copy of netName's in-flight picks. Caller holds
// dhcpResMu.
func (s *Server) isoPendingAddrsLocked(netName string) []string {
	s.pruneIsoPendingLocked()
	out := make([]string, 0, len(s.isoPending[netName]))
	for ip := range s.isoPending[netName] {
		out = append(out, ip)
	}
	return out
}

// dhcpPendingRes is a reservation made for a NIC whose rows are not written
// yet.
type dhcpPendingRes struct {
	mac string
	at  time.Time
}

// prunePendingLocked drops reservations older than any create takes to
// write its rows. Caller holds dhcpResMu.
func (s *Server) prunePendingLocked() {
	if s.dhcpPending == nil {
		s.dhcpPending = map[string]map[string]dhcpPendingRes{}
	}
	for n, m := range s.dhcpPending {
		for ip, r := range m {
			if time.Since(r.at) > 10*time.Minute {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(s.dhcpPending, n)
		}
	}
}

// SyncDHCPReservations rewrites every local dnsmasq's hosts file from the
// NIC rows — the authority once they exist — plus reservations and NICs still
// in flight: each guarded NIC's reservation, and on an isolated network the
// NICs offered no router (noRouterMACs). The daemon runs it periodically, and
// a VM's create, NIC attach and detach, and delete run it at once.
func (s *Server) SyncDHCPReservations(ctx context.Context) {
	_ = s.syncDHCPReservations(ctx)
}

// syncDHCPReservations is SyncDHCPReservations, reporting a pass that could
// not read what it needs (nothing is written then).
func (s *Server) syncDHCPReservations(ctx context.Context) error {
	s.dhcpSyncMu.Lock()
	defer s.dhcpSyncMu.Unlock()
	nets, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		return err
	}
	defs := map[string]*compose.NetworkDef{}
	for _, nr := range nets {
		def, _ := lookupNetworkDef(ctx, s.db, nr.Name)
		defs[nr.Name] = def
	}
	noRouter, err := s.noRouterMACs(ctx, defs)
	if err != nil {
		return err
	}
	ids, err := corrosion.LiveNICIdentities(ctx, s.db)
	if err != nil {
		return err
	}
	guards, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		return err
	}
	// Only guarded VM NICs are reserved; the address the NIC row records is
	// the reservation.
	byNet := map[string]map[string]string{}
	macOf := map[string]string{} // owner|network → mac (vm_nics rows)
	for _, id := range ids {
		if id.MAC != "" {
			macOf[id.Owner+"|"+id.Network] = id.MAC
		}
	}
	for _, id := range ids {
		if id.Addr == "" || strings.HasPrefix(id.Owner, "ct:") {
			continue
		}
		mac := macOf[id.Owner+"|"+id.Network]
		if rec, ok := guards[corrosion.NICGuardKey(id.Owner, mac)]; !ok || !rec.Guarded() {
			continue
		}
		if byNet[id.Network] == nil {
			byNet[id.Network] = map[string]string{}
		}
		byNet[id.Network][mac] = id.Addr
	}
	s.dhcpResMu.Lock()
	s.prunePendingLocked()
	for n, m := range s.dhcpPending {
		for ip, r := range m {
			if byNet[n] == nil {
				byNet[n] = map[string]string{}
			}
			if _, ok := byNet[n][r.mac]; !ok {
				byNet[n][r.mac] = ip
			}
		}
	}
	s.dhcpResMu.Unlock()
	sync := network.SyncDHCPHosts
	if s.syncDHCPHosts != nil {
		sync = s.syncDHCPHosts
	}
	for _, nr := range nets {
		def := defs[nr.Name]
		if def == nil || def.Subnet == "" {
			continue
		}
		tags := network.NoRouterNetwork(*def)
		if !def.DHCP && !tags {
			continue
		}
		hosts := map[string]network.DHCPHost{}
		if def.DHCP {
			for mac, ip := range byNet[nr.Name] {
				hosts[mac] = network.DHCPHost{IP: ip}
			}
		}
		if tags {
			for mac := range noRouter[nr.Name] {
				h := hosts[mac]
				h.NoRouter = true
				hosts[mac] = h
			}
		}
		if _, err := sync(network.BridgeName(nr.Name, *def), hosts); err != nil {
			slog.Debug("DHCP hosts file not rewritten", "network", nr.Name, "error", err)
		}
	}
	return nil
}

// noRouterPendingNIC is a NIC registered by pendingNICs whose row is not
// written yet.
type noRouterPendingNIC struct {
	network string
	at      time.Time
}

// noRouterMACs is, per isolated network (network.NoRouterNetwork), the MACs
// (lower-case) of the NICs its dnsmasq offers no router: every NIC on it of a
// VM that also has a NIC on a network that carries a route (routedNetwork),
// counting every live VM in the cluster (a VM that moves here finds its tag
// already in place) and the NICs pendingNICs registered. Such a VM takes its
// default route from that NIC, never through a bridge that leads nowhere —
// which netplan's use-routes: false in its seed already says, and RHEL's
// cloud-init renderers drop. A VM whose NICs are all isolated is offered the
// bridge as before. Containers are not counted. With no such network nothing
// is read.
func (s *Server) noRouterMACs(ctx context.Context, defs map[string]*compose.NetworkDef) (map[string]map[string]bool, error) {
	var isolated []string
	for name, def := range defs {
		if def != nil && network.NoRouterNetwork(*def) {
			isolated = append(isolated, name)
		}
	}
	if len(isolated) == 0 {
		return nil, nil
	}
	sort.Strings(isolated)
	rows, err := corrosion.VMNICsTouching(ctx, s.db, isolated)
	if err != nil {
		return nil, err
	}
	byVM := map[string]map[string]string{} // vm → mac → network
	add := func(vm, mac, net string) {
		if byVM[vm] == nil {
			byVM[vm] = map[string]string{}
		}
		byVM[vm][strings.ToLower(mac)] = net
	}
	for _, n := range rows {
		add(n.VMName, n.MAC, n.NetworkName)
	}
	s.dhcpResMu.Lock()
	for vm, m := range s.noRouterPending {
		for mac, p := range m {
			if time.Since(p.at) > 10*time.Minute {
				delete(m, mac)
				continue
			}
			add(vm, mac, p.network)
		}
		if len(m) == 0 {
			delete(s.noRouterPending, vm)
		}
	}
	s.dhcpResMu.Unlock()
	out := map[string]map[string]bool{}
	for _, nics := range byVM {
		routed := false
		for _, net := range nics {
			if routedNetwork(defs[net]) {
				routed = true
				break
			}
		}
		if !routed {
			continue
		}
		for mac, net := range nics {
			if def := defs[net]; def == nil || !network.NoRouterNetwork(*def) {
				continue
			}
			if out[net] == nil {
				out[net] = map[string]bool{}
			}
			out[net][mac] = true
		}
	}
	return out, nil
}

// routedNetwork reports whether a NIC on def can carry the VM's default
// route: a bridge, VXLAN, SR-IOV or macvtap network, or a host-isolated one
// (its seed gives the NIC the bridge as gateway) — anything but an isolated
// network. A network with no record counts as not routed, which keeps the
// router an isolated network's dnsmasq offers as it was.
func routedNetwork(def *compose.NetworkDef) bool {
	return def != nil && (def.Type != "isolated" || def.HostIsolation)
}

// pendingDHCPNICs registers vm's NICs whose rows are not written yet with
// the DHCP hosts files and rewrites them at once, so a NIC that is to be
// offered no router is tagged before its guest can ask; the returned func
// forgets them and rewrites the files again (the rows written by then, or the
// create failed).
func (s *Server) pendingDHCPNICs(vm string, recs []corrosion.InterfaceRecord) func() {
	if s.db == nil || len(recs) == 0 || !s.anyNoRouterNetwork(recs) {
		return func() {}
	}
	s.dhcpResMu.Lock()
	if s.noRouterPending == nil {
		s.noRouterPending = map[string]map[string]noRouterPendingNIC{}
	}
	if s.noRouterPending[vm] == nil {
		s.noRouterPending[vm] = map[string]noRouterPendingNIC{}
	}
	now := time.Now()
	for _, r := range recs {
		s.noRouterPending[vm][strings.ToLower(r.MAC)] = noRouterPendingNIC{network: r.NetworkName, at: now}
	}
	s.dhcpResMu.Unlock()
	s.resyncDHCPHosts()
	return func() {
		s.dhcpResMu.Lock()
		for _, r := range recs {
			delete(s.noRouterPending[vm], strings.ToLower(r.MAC))
		}
		if len(s.noRouterPending[vm]) == 0 {
			delete(s.noRouterPending, vm)
		}
		s.dhcpResMu.Unlock()
		s.resyncDHCPHosts()
	}
}

// anyNoRouterNetwork reports whether one of recs is on a network whose
// dnsmasq can withhold its router (network.NoRouterNetwork): only then can
// the NICs change a tag before their rows exist. A NIC on any other network
// changes a tag only of a guest already running, which takes it at its next
// lease; the rewrite after the rows are written covers that.
func (s *Server) anyNoRouterNetwork(recs []corrosion.InterfaceRecord) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, r := range recs {
		if def, _ := lookupNetworkDef(ctx, s.db, r.NetworkName); def != nil && network.NoRouterNetwork(*def) {
			return true
		}
	}
	return false
}

// resyncDHCPHosts runs SyncDHCPReservations now: a VM's NICs changed. A pass
// that cannot read what it needs is retried, and one that still fails is
// logged — a tag it would have written is then missing until the periodic
// pass, and a guest that asks for a lease before it takes the router.
func (s *Server) resyncDHCPHosts() {
	if s.db == nil {
		return
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = s.syncDHCPReservations(ctx)
		cancel()
		if err == nil {
			return
		}
		slog.Warn("DHCP hosts files: rewrite after a NIC change failed; retrying", "attempt", attempt+1, "error", err)
	}
	slog.Error("DHCP hosts files: rewrite after a NIC change failed; the periodic pass retries every 30s, and a NIC on an isolated network may be offered the router until then", "error", err)
}

// StartDHCPReservations runs SyncDHCPReservations every interval.
func (s *Server) StartDHCPReservations(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			s.SyncDHCPReservations(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}
