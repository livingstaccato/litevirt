package grpcapi

import (
	"context"
	"encoding/json"
	"math"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
)

// peerLeaseTimeout bounds one pass of asking a vxlan network's other hosts
// for a lease.
const peerLeaseTimeout = 2 * time.Second

// SetDHCPLeaseLookup replaces the read of this host's dnsmasq lease for a MAC
// on a bridge (dhcpLeaseLookup). Test-only seam, nil in production.
func (s *Server) SetDHCPLeaseLookup(fn func(mac, bridge string) (string, int64)) {
	s.dhcpLeaseLookup = fn
}

// localLease is this host's dnsmasq lease for mac on bridge: its address and
// expiry (Unix seconds, 0 = infinite), or "".
func (s *Server) localLease(mac, bridge string) (string, int64) {
	if s.dhcpLeaseLookup != nil {
		return s.dhcpLeaseLookup(mac, bridge)
	}
	return lv.LeaseOnBridge(mac, bridge)
}

// peerLease is one host's answer to a lease_only GetVMIPRemote.
type peerLease struct {
	host   string
	ip     string
	expiry int64 // dnsmasq's: 0 = infinite
}

// peerLeaseIP asks the other hosts of networkName — a vxlan network that
// litevirt serves DHCP for — for their dnsmasq lease of mac, and returns the
// best answer (bestPeerLease), or "". Any other network has its dnsmasq on
// every host or none, so there is nobody else to ask.
func (s *Server) peerLeaseIP(ctx context.Context, mac, networkName string) string {
	if networkName == "" || mac == "" {
		return ""
	}
	nr, err := corrosion.GetNetwork(ctx, s.db, networkName)
	if err != nil || nr == nil || nr.Type != "vxlan" {
		return ""
	}
	var def compose.NetworkDef
	if json.Unmarshal([]byte(nr.Config), &def) != nil || def.Subnet == "" || def.HostIsolation {
		return ""
	}
	vteps, err := network.GetVTEPs(ctx, s.db, networkName)
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, peerLeaseTimeout)
	defer cancel()
	var mu sync.Mutex
	var answers []peerLease
	var wg sync.WaitGroup
	seen := map[string]bool{s.hostName: true}
	for _, v := range vteps {
		if seen[v.HostName] {
			continue
		}
		seen[v.HostName] = true
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			client, conn, err := s.peerClient(ctx, host)
			if err != nil {
				return
			}
			defer conn.Close()
			resp, err := client.GetVMIPRemote(ctx, &pb.GetVMIPRequest{Mac: mac, NetworkName: networkName, LeaseOnly: true})
			if err != nil || !resp.GetLease() || resp.GetIp() == "" {
				return
			}
			mu.Lock()
			answers = append(answers, peerLease{host: host, ip: resp.GetIp(), expiry: resp.GetLeaseExpiry()})
			mu.Unlock()
		}(v.HostName)
	}
	wg.Wait()
	return bestPeerLease(def.Subnet, answers)
}

// bestPeerLease picks the lease dnsmasq granted most recently (the latest
// expiry; 0 is infinite and newest), as a host's own lease files are read
// (lv.GetIPFromDHCPLeases): a host that was the network's gateway earlier
// can still hold an older, unexpired lease. An address outside subnet is not
// an answer. Ties go to the first host by name.
func bestPeerLease(subnet string, answers []peerLease) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	if err != nil {
		return ""
	}
	p = p.Masked()
	sort.Slice(answers, func(i, j int) bool { return answers[i].host < answers[j].host })
	best, bestExp := "", int64(-1)
	for _, a := range answers {
		addr, err := netip.ParseAddr(a.ip)
		if err != nil || !p.Contains(addr) {
			continue
		}
		exp := a.expiry
		if exp == 0 {
			exp = math.MaxInt64
		}
		if exp > bestExp {
			best, bestExp = addr.String(), exp
		}
	}
	return best
}
