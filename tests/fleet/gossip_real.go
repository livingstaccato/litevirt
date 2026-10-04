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
// memberlist, joined to every other node. Every node gossips on ONE port
// (freeGossipPort), each on its own loopback address (127.0.0.10, .11, ...),
// which is also the address its hosts row records, its gRPC listener binds and
// its certificate names — the shape of a real cluster, where every host has its
// own IP and gossip_port is uniform. That is what lets a bare recorded address
// be dialled at all: memberlist dials it on its own gossip port. (Linux routes
// all of 127.0.0.0/8 to lo. Where those addresses cannot be bound — macOS
// without lo0 aliases — the scenario skips; see skipWithoutRealGossipAddresses.)
//
// Its transport is memberlist's own NetTransport wrapped in a cut: SplitGossip
// drops every packet and refuses every stream from one side to the other, in
// both directions, as a firewall DROP between two groups of hosts would. The
// cut counts the packets it drops, which is how a scenario can see memberlist
// stop gossiping to members it has reaped. Encryption and admission sit above
// the transport, so a key (Options.GossipKey) applies to everything that
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
	byAddr  map[string]string // "127.0.0.x:port" → node name
	blocked map[string]map[string]bool
	// dropped counts the UDP packets the cut has dropped. Join's push/pull is
	// a stream, so this is memberlist's own gossip and probing only.
	dropped int
}

func (g *gossipCut) cut(from string, addr string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	to, ok := g.byAddr[addr]
	return ok && g.blocked[from][to]
}

func (g *gossipCut) drop(from string, addr string) bool {
	if !g.cut(from, addr) {
		return false
	}
	g.mu.Lock()
	g.dropped++
	g.mu.Unlock()
	return true
}

func (g *gossipCut) droppedPackets() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.dropped
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
	if t.cut.drop(t.self, addr) {
		return time.Now(), nil // a dropped UDP packet: the sender never knows
	}
	return t.NodeAwareTransport.WriteTo(b, addr)
}

func (t *cutTransport) WriteToAddress(b []byte, a memberlist.Address) (time.Time, error) {
	if t.cut.drop(t.self, a.Addr) {
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

// realGossipAddress is node i's own loopback address under RealGossip.
func realGossipAddress(i int) string { return fmt.Sprintf("127.0.0.%d", 10+i) }

// skipWithoutRealGossipAddresses skips the test unless every RealGossip node
// address can be bound. Linux routes all of 127.0.0.0/8 to lo; macOS routes only
// 127.0.0.1 unless an alias is added, and a container can have an unusual
// loopback too. So this probes the addresses rather than checking GOOS: on a
// host without them the scenario cannot run at all, and that is a skip, not a
// failure.
func skipWithoutRealGossipAddresses(t *testing.T, nodes int) {
	t.Helper()
	var missing []string
	for i := 0; i < nodes; i++ {
		addr := realGossipAddress(i)
		l, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
		if err != nil {
			missing = append(missing, addr)
			continue
		}
		l.Close()
	}
	if len(missing) == 0 {
		return
	}
	var fix []string
	for _, a := range missing {
		fix = append(fix, "sudo ifconfig lo0 alias "+a+" up")
	}
	t.Skipf("fleet RealGossip needs a loopback address per node, and %v cannot be bound here "+
		"(macOS routes only 127.0.0.1 to lo0 by default). To run it:\n  %s",
		missing, strings.Join(fix, "\n  "))
}

func gossipAddr(n *Node) string { return net.JoinHostPort(n.Address, strconv.Itoa(n.GossipPort)) }

// openGossipDB opens n's store as a real gossiping corrosion client.
func (c *Cluster) openGossipDB(n *Node) {
	var seeds []string
	for _, o := range c.Nodes {
		if o != n {
			seeds = append(seeds, gossipAddr(o))
		}
	}
	cfg := corrosion.Config{
		HostName:       n.Name,
		DataDir:        filepath.Join(c.tmpRoot, n.Name, "corrosion"),
		BindAddr:       n.Address,
		AdvertiseAddr:  n.Address,
		BindPort:       n.GossipPort,
		JoinPeers:      seeds,
		RejoinInterval: gossipRejoinInterval,
		MemberlistForTests: func(ml *memberlist.Config) {
			ml.GossipToTheDeadTime = gossipDeadTime
			nt, err := memberlist.NewNetTransport(&memberlist.NetTransportConfig{
				BindAddrs: []string{n.Address},
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

// WaitGossipReaped waits, bounded, until memberlist on both sides of a split
// has REAPED the other side's members, and fails if it never does.
//
// A member declared dead is still gossiped to for GossipToTheDeadTime, and a
// heal inside that window can let memberlist re-merge by itself: the next
// broadcast reaches the "dead" member, which refutes its death. Only once the
// dead are reaped will nothing ever reach them again — the drill's state.
//
// memberlist exposes no member count that includes the dead-but-unreaped
// (Members and NumMembers both skip the dead), and it sends nothing at all
// while it has nothing to broadcast, so silence on the wire proves nothing
// either. So each check makes every node broadcast afresh, and the members
// are reaped when not one of those broadcasts is aimed across the cut.
func (c *Cluster) WaitGossipReaped(t *testing.T, timeout time.Duration) {
	t.Helper()
	// Long enough for a fresh broadcast's retransmissions to go out several
	// gossip intervals over (200 ms on the LAN profile).
	const settle = 1500 * time.Millisecond
	deadline := time.Now().Add(timeout)
	for {
		before := c.gossip.droppedPackets()
		for _, n := range c.Nodes {
			if err := n.DB.GossipRebroadcastForTests(); err != nil {
				t.Fatalf("%s: rebroadcast: %v", n.Name, err)
			}
		}
		time.Sleep(settle)
		aimed := c.gossip.droppedPackets() - before
		if aimed == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("memberlist still gossiped across the split after %v (%d packets in the last check): "+
				"the dead were never reaped, so a heal now would prove nothing", timeout, aimed)
		}
	}
}

// ForgetGossipAddresses drops every node's remembered peer gossip addresses —
// the in-memory state a daemon restart loses — so a re-merge can only dial
// what the hosts table records.
func (c *Cluster) ForgetGossipAddresses() {
	for _, n := range c.Nodes {
		n.DB.ForgetGossipAddrsForTests()
	}
}

// pruneEstablishedHistory empties every established node's mutation_log, as
// the replicator's own pruning does to a long-running cluster's history
// (Options.Joiners). What it removes is what a joiner can no longer be
// pushed: the established hosts' own rows, written long ago, which then reach
// a joiner by anti-entropy or not at all.
func (c *Cluster) pruneEstablishedHistory() {
	for _, n := range c.Nodes {
		if c.isJoiner(n) {
			continue
		}
		if _, err := n.DB.DB().Exec(`DELETE FROM mutation_log`); err != nil {
			c.t.Fatalf("prune %s's mutation history: %v", n.Name, err)
		}
	}
}
