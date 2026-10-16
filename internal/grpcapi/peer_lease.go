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
	// peerLeasePerPeer bounds the lookups in flight to one peer in a batch.
	peerLeasePerPeer = 4
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
// bound on lookups in flight per peer (peerLeasePerPeer workers), and a host
// is asked only while it is in this node's gossip membership: one powered-off host costs a pass at most budget,
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
	type job struct {
		i                  int
		mac, network, host string
	}
	var jobs []job
	for i, n := range nics {
		if np := nets[n.network]; np != nil {
			for _, host := range np.hosts {
				jobs = append(jobs, job{i: i, mac: n.mac, network: n.network, host: host})
			}
		}
	}
	// A fixed pool of workers per peer over that peer's lookups: goroutines
	// and lookups in flight are bounded by the number of peers, not NICs, and
	// a peer that hangs holds up only its own lane until the deadline.
	lanes := map[string]chan job{}
	var amu sync.Mutex
	var wg sync.WaitGroup
	for _, j := range jobs {
		if lanes[j.host] != nil {
			continue
		}
		lane := make(chan job)
		lanes[j.host] = lane
		for w := 0; w < peerLeasePerPeer; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range lane {
					if ctx.Err() != nil {
						continue
					}
					c := client(j.host)
					if c == nil {
						continue
					}
					resp, err := c.GetVMIPRemote(ctx, &pb.GetVMIPRequest{Mac: j.mac, NetworkName: j.network, LeaseOnly: true})
					if err != nil || !resp.GetLease() || resp.GetIp() == "" {
						continue
					}
					amu.Lock()
					answers[j.i] = append(answers[j.i], peerLease{host: j.host, ip: resp.GetIp(), expiry: resp.GetLeaseExpiry()})
					amu.Unlock()
				}
			}()
		}
	}
	// Feed every lane from its own goroutine, so a full lane of a hung peer
	// never stops the others being fed.
	byHost := map[string][]job{}
	for _, j := range jobs {
		byHost[j.host] = append(byHost[j.host], j)
	}
	var fwg sync.WaitGroup
	for host, js := range byHost {
		fwg.Add(1)
		go func(lane chan job, js []job) {
			defer fwg.Done()
			defer close(lane)
			for _, j := range js {
				select {
				case lane <- j:
				case <-ctx.Done():
					return
				}
			}
		}(lanes[host], js)
	}
	fwg.Wait()
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
