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
	"google.golang.org/grpc"
)

// Budgets for one batch of peer lease lookups (peerLeases): the IP scanner's
// pass, well inside its 30-second interval, and a single-VM read.
const (
	scanPeerLeaseBudget    = 5 * time.Second
	inspectPeerLeaseBudget = 2 * time.Second
	// peerLeaseConcurrency bounds the lookups in flight at once in a batch.
	peerLeaseConcurrency = 16
)

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

// peerLease is one host's lease for a MAC (expiry: dnsmasq's, 0 = infinite).
type peerLease struct {
	host   string
	ip     string
	expiry int64
}

// peerLeases asks, for each NIC on a vxlan network litevirt serves DHCP for,
// the network's other hosts for the lease they hold for its MAC, and returns
// the best answer per NIC (bestPeerLease; "" where there is none). Any other
// network has its dnsmasq on every host or none, so nobody else is asked.
//
// The whole batch shares one deadline (budget), one connection per peer and a
// bound on lookups in flight, and a host is asked only while it is in this
// node's gossip membership: one powered-off host costs a pass at most budget,
// not a wait per NIC.
func (s *Server) peerLeases(ctx context.Context, nics []nicQuery, budget time.Duration) []peerLease {
	out := make([]peerLease, len(nics))
	type netPeers struct {
		subnet string
		hosts  []string
	}
	nets := map[string]*netPeers{}
	var alive map[string]bool
	for _, n := range nics {
		if _, done := nets[n.network]; done || n.network == "" {
			continue
		}
		nets[n.network] = nil
		nr, err := corrosion.GetNetwork(ctx, s.db, n.network)
		if err != nil || nr == nil || nr.Type != "vxlan" {
			continue
		}
		var def compose.NetworkDef
		if json.Unmarshal([]byte(nr.Config), &def) != nil || def.Subnet == "" || def.HostIsolation {
			continue
		}
		vteps, err := network.GetVTEPs(ctx, s.db, n.network)
		if err != nil {
			continue
		}
		if alive == nil {
			alive = map[string]bool{}
			for _, m := range s.db.Members() {
				alive[m.Name] = true
			}
		}
		np := &netPeers{subnet: def.Subnet}
		seen := map[string]bool{}
		for _, v := range vteps {
			if v.HostName == s.hostName || seen[v.HostName] || !alive[v.HostName] {
				continue
			}
			seen[v.HostName] = true
			np.hosts = append(np.hosts, v.HostName)
		}
		sort.Strings(np.hosts)
		if len(np.hosts) > 0 {
			nets[n.network] = np
		}
	}
	if len(nets) == 0 {
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var cmu sync.Mutex
	clients := map[string]pb.LiteVirtClient{}
	var conns []*grpc.ClientConn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	client := func(host string) pb.LiteVirtClient {
		cmu.Lock()
		defer cmu.Unlock()
		if c, ok := clients[host]; ok {
			return c
		}
		c, conn, err := s.peerClient(ctx, host)
		if err != nil {
			c = nil
		} else {
			conns = append(conns, conn)
		}
		clients[host] = c
		return c
	}

	answers := make([][]peerLease, len(nics))
	var amu sync.Mutex
	sem := make(chan struct{}, peerLeaseConcurrency)
	var wg sync.WaitGroup
	for i, n := range nics {
		np := nets[n.network]
		if np == nil {
			continue
		}
		for _, host := range np.hosts {
			wg.Add(1)
			go func(i int, mac, networkName, host string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				c := client(host)
				if c == nil {
					return
				}
				resp, err := c.GetVMIPRemote(ctx, &pb.GetVMIPRequest{Mac: mac, NetworkName: networkName, LeaseOnly: true})
				if err != nil || !resp.GetLease() || resp.GetIp() == "" {
					return
				}
				amu.Lock()
				answers[i] = append(answers[i], peerLease{host: host, ip: resp.GetIp(), expiry: resp.GetLeaseExpiry()})
				amu.Unlock()
			}(i, n.mac, n.network, host)
		}
	}
	wg.Wait()
	for i, n := range nics {
		if np := nets[n.network]; np != nil {
			out[i] = bestPeerLease(np.subnet, answers[i])
		}
	}
	return out
}

// bestPeerLease picks the lease dnsmasq granted most recently (the latest
// expiry; 0 is infinite and newest), as a host's own lease files are read
// (lv.GetIPFromDHCPLeases): a host that was the network's gateway earlier
// can still hold an older, unexpired lease. An address outside subnet is not
// an answer. Ties go to the first host by name.
func bestPeerLease(subnet string, answers []peerLease) peerLease {
	p, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	if err != nil {
		return peerLease{}
	}
	p = p.Masked()
	sort.Slice(answers, func(i, j int) bool { return answers[i].host < answers[j].host })
	var best peerLease
	bestExp := int64(-1)
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
			best, bestExp = peerLease{host: a.host, ip: addr.String(), expiry: a.expiry}, exp
		}
	}
	return best
}
