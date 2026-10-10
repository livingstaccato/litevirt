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
	"net/netip"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// checkNICIdentities refuses explicit MACs and addresses another live NIC
// holds, and addresses a subnet keeps for itself. owners are the names whose
// own rows do not count (the VM being created, and the one it re-creates).
func (s *Server) checkNICIdentities(ctx context.Context, atts []*pb.NetworkAttachment, owners ...string) error {
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
		return status.Errorf(codes.Unavailable, "read NIC guards: %v", err)
	}
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
			if err := s.checkAddrFree(ctx, a.GetName(), ip, ids, mine); err != nil {
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

// checkAddrFree refuses an explicit IPv4 address on a network litevirt
// manages when it is one of the subnet's own addresses or another NIC's. On a
// NetBox-bound network NetBox decides, as it always has.
func (s *Server) checkAddrFree(ctx context.Context, netName, ip string, ids []corrosion.AddrOwner, mine map[string]bool) error {
	addr := canonAddr(ip)
	if addr == "" {
		return nil // the create path reports a malformed address itself
	}
	if alloc, _, err := s.allocatorFor(ctx, "vm", netName); err == nil && alloc != nil {
		return nil
	}
	if def, _ := lookupNetworkDef(ctx, s.db, netName); def != nil && def.Subnet != "" {
		if sp, err := netip.ParsePrefix(def.Subnet); err == nil {
			sp = sp.Masked()
			a, _ := netip.ParseAddr(addr)
			if sp.Contains(a) && (a == sp.Addr() || a == sp.Addr().Next() || (a.Is4() && a == lastAddr(sp))) {
				return status.Errorf(codes.InvalidArgument,
					"%s is the network address, gateway or broadcast of %s; it cannot be a NIC's", addr, netName)
			}
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
// it named no address, and its network is one litevirt serves DHCPv4 on.
func (s *Server) dhcpReservable(att *pb.NetworkAttachment, def *compose.NetworkDef) bool {
	if att.GetIp() != "" || def == nil || !def.DHCP || def.Subnet == "" || !s.db.MayWriteClusterPolicy() {
		return false
	}
	if mode, err := normalizeNICGuardMode(att.GetSpoofGuard()); err != nil || mode != corrosion.NICGuardOn {
		return false
	}
	if def.Type == "direct" || def.Type == "sriov" || def.NetBoxPrefixID != 0 {
		return false
	}
	p, err := netip.ParsePrefix(def.Subnet)
	return err == nil && p.Addr().Is4()
}

// reserveDHCPAddress picks a free address for mac on netName and reserves it
// in the local dnsmasq at once (the guest asks within seconds of starting).
// Free means: no live NIC row or lease holds it, the local dnsmasq has not
// leased it, and no create in flight on this host just took it. Two hosts
// reserving at the same instant can still pick the same address — the
// tables have no UNIQUE — which the guard then shows as a dropped guest, not
// as an impersonation.
func (s *Server) reserveDHCPAddress(ctx context.Context, netName, subnet, bridge, mac string) (string, error) {
	assigned, err := corrosion.NetworkAssignedAddrs(ctx, s.db)
	if err != nil {
		return "", err
	}
	s.dhcpResMu.Lock()
	defer s.dhcpResMu.Unlock()
	s.prunePendingLocked()
	used := append(append([]string(nil), assigned[netName]...), network.LeasedAddrs(bridge)...)
	for ip := range s.dhcpPending[netName] {
		used = append(used, ip)
	}
	ip, err := network.NextFreeIP(subnet, used)
	if err != nil {
		return "", err
	}
	if s.dhcpPending[netName] == nil {
		s.dhcpPending[netName] = map[string]dhcpPendingRes{}
	}
	s.dhcpPending[netName][ip] = dhcpPendingRes{mac: strings.ToLower(mac), at: time.Now()}
	if err := network.AddDHCPHost(bridge, mac, ip); err != nil {
		return "", err
	}
	return ip, nil
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

// SyncDHCPReservations rewrites every local dnsmasq's reservations from the
// NIC rows — the authority once they exist — plus reservations still in
// flight. The daemon runs it periodically.
func (s *Server) SyncDHCPReservations(ctx context.Context) {
	nets, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		return
	}
	ids, err := corrosion.LiveNICIdentities(ctx, s.db)
	if err != nil {
		return
	}
	guards, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		return
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
	for _, nr := range nets {
		def, _ := lookupNetworkDef(ctx, s.db, nr.Name)
		if def == nil || !def.DHCP || def.Subnet == "" {
			continue
		}
		bridge := network.BridgeName(nr.Name, *def)
		hosts := byNet[nr.Name]
		if hosts == nil {
			hosts = map[string]string{}
		}
		if _, err := network.SyncDHCPHosts(bridge, hosts); err != nil {
			continue
		}
	}
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
