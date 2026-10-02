package fleet

// Real gossip in the shared harness (Options.RealGossip).
//
// The default harness SEEDS each node's Members() view (seedGossipMembership),
// which is right for every scenario about what a node does with the peers it
// sees — and structurally unable to reach anything about how it comes to see
// them. A healed partition whose halves never merge again is exactly that: the
// replicator, anti-entropy and every other consumer of Members() behave
// correctly over a view that memberlist has stopped repairing.
//
// With RealGossip each node's store is a real corrosion client with its own
// memberlist on its own gossip port (freeGossipPort), binding 0.0.0.0 and
// advertising 127.0.0.1, joined to every other node. Its transport is
// memberlist's own NetTransport wrapped in a cut: SplitGossip drops every packet
// and refuses every stream from one side to the other, in both directions, as a
// firewall DROP between two groups of hosts would. Encryption and admission sit
// above the transport, so a key (Options.GossipKey) applies to everything that
// crosses it, re-joins included.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hlc"
)

// gossipDeadTime is memberlist's GossipToTheDeadTime under RealGossip: how long
// a node keeps gossiping to a member it has declared dead before reaping it.
// The LAN default is 30 s; it is shortened so a scenario can wait out the reap
// in seconds. Nothing else about failure detection is changed.
const gossipDeadTime = 2 * time.Second

// gossipRejoinInterval is the membership loop's base interval under
// RealGossip. Production is 30 s; the loop's logic is the same at any scale.
const gossipRejoinInterval = 200 * time.Millisecond

// gossipCut is the cluster-wide gossip firewall: which directed node pairs
// cannot reach each other, and which gossip address belongs to which node.
type gossipCut struct {
	mu      sync.Mutex
	byAddr  map[string]string // "127.0.0.1:port" → node name
	blocked map[string]map[string]bool
}

func (g *gossipCut) cut(from string, addr string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	to, ok := g.byAddr[addr]
	return ok && g.blocked[from][to]
}

func (g *gossipCut) set(from, to string, blocked bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.blocked[from] == nil {
		g.blocked[from] = map[string]bool{}
	}
	g.blocked[from][to] = blocked
}

// cutTransport is a node's memberlist transport behind the gossip firewall.
// Filtering the SENDING side of every pair is enough: a cut is always set in
// both directions, so nothing a cut peer sends ever arrives either.
type cutTransport struct {
	memberlist.NodeAwareTransport
	self string
	cut  *gossipCut
}

var errGossipCut = errors.New("fleet gossip partition: i/o timeout")

func (t *cutTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	if t.cut.cut(t.self, addr) {
		return time.Now(), nil // a dropped UDP packet: the sender never knows
	}
	return t.NodeAwareTransport.WriteTo(b, addr)
}

func (t *cutTransport) WriteToAddress(b []byte, a memberlist.Address) (time.Time, error) {
	if t.cut.cut(t.self, a.Addr) {
		return time.Now(), nil
	}
	return t.NodeAwareTransport.WriteToAddress(b, a)
}

func (t *cutTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	if t.cut.cut(t.self, addr) {
		return nil, errGossipCut
	}
	return t.NodeAwareTransport.DialTimeout(addr, timeout)
}

func (t *cutTransport) DialAddressTimeout(a memberlist.Address, timeout time.Duration) (net.Conn, error) {
	if t.cut.cut(t.self, a.Addr) {
		return nil, errGossipCut
	}
	return t.NodeAwareTransport.DialAddressTimeout(a, timeout)
}

func gossipAddr(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

// openGossipDB opens n's store as a real gossiping corrosion client.
func (c *Cluster) openGossipDB(n *Node) {
	var seeds []string
	for _, o := range c.Nodes {
		if o != n {
			seeds = append(seeds, gossipAddr(o.GossipPort))
		}
	}
	cfg := corrosion.Config{
		HostName:       n.Name,
		DataDir:        filepath.Join(c.tmpRoot, n.Name, "corrosion"),
		BindAddr:       "0.0.0.0",
		AdvertiseAddr:  "127.0.0.1",
		BindPort:       n.GossipPort,
		JoinPeers:      seeds,
		RejoinInterval: gossipRejoinInterval,
		MemberlistForTests: func(ml *memberlist.Config) {
			ml.GossipToTheDeadTime = gossipDeadTime
			nt, err := memberlist.NewNetTransport(&memberlist.NetTransportConfig{
				BindAddrs: []string{"0.0.0.0"},
				BindPort:  n.GossipPort,
				Logger:    log.New(ml.LogOutput, "", 0),
			})
			if err != nil {
				c.t.Fatalf("gossip transport for %s: %v", n.Name, err)
			}
			ml.Transport = &cutTransport{NodeAwareTransport: nt, self: n.Name, cut: c.gossip}
		},
	}
	if len(c.opts.GossipKey) > 0 {
		cfg.GossipEncryption = corrosion.GossipEncryptionEnforced
		cfg.GossipKeys = corrosion.GossipKeys{c.opts.GossipKey}
	}
	if err := mkdirAll(cfg.DataDir); err != nil {
		c.t.Fatalf("mkdir corrosion dir for %s: %v", n.Name, err)
	}
	db, err := corrosion.NewClient(cfg, hlc.NewClock(n.Name))
	if err != nil {
		c.t.Fatalf("open gossiping DB for %s: %v", n.Name, err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		c.t.Fatalf("InitSchema for %s: %v", n.Name, err)
	}
	db.MarkReplicaCaughtUpForTests("fleet-bootstrap")
	n.DB = db
}

// GossipSees reports whether a's ADMITTED gossip view contains b.
func GossipSees(a, b *Node) bool {
	for _, p := range a.DB.Members() {
		if p.Name == b.Name {
			return true
		}
	}
	return false
}

// gossipViews renders every node's gossip view, for a failure message.
func (c *Cluster) gossipViews() string {
	var views []string
	for _, n := range c.Nodes {
		var ms []string
		for _, p := range n.DB.Members() {
			ms = append(ms, p.Name)
		}
		views = append(views, fmt.Sprintf("%s sees %v", n.Name, ms))
	}
	return strings.Join(views, "\n  ")
}

// WaitGossip waits, bounded, until ok holds, failing with every node's view.
func (c *Cluster) WaitGossip(t *testing.T, timeout time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s:\n  %s", timeout, what, c.gossipViews())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// GossipConverged reports whether every node's gossip view holds every other.
func (c *Cluster) GossipConverged() bool {
	for _, a := range c.Nodes {
		for _, b := range c.Nodes {
			if a != b && !GossipSees(a, b) {
				return false
			}
		}
	}
	return true
}

// SplitGossip partitions the cluster into two groups, as a firewall dropping
// everything between them would: gossip in both directions, and every RPC in
// both directions — replication (the Block link fault) and everything else,
// health probes, claim RPCs and client calls included (BlockAll).
func (c *Cluster) SplitGossip(left, right []*Node) {
	for _, a := range left {
		for _, b := range right {
			c.gossip.set(a.Name, b.Name, true)
			c.gossip.set(b.Name, a.Name, true)
			c.SetLinkFaultBoth(a, b, LinkFault{Block: true, BlockAll: true})
		}
	}
}

// SplitAll cuts every node off from every other, as a fleet-wide blip does.
func (c *Cluster) SplitAll() {
	for i, a := range c.Nodes {
		for _, b := range c.Nodes[i+1:] {
			c.SplitGossip([]*Node{a}, []*Node{b})
		}
	}
}

// HealGossip removes every gossip cut and every replication link fault.
func (c *Cluster) HealGossip() {
	c.gossip.mu.Lock()
	c.gossip.blocked = map[string]map[string]bool{}
	c.gossip.mu.Unlock()
	c.ClearLinkFaults()
}
