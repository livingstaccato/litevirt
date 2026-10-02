package corrosion

import (
	"log/slog"
	"sync"

	"github.com/hashicorp/memberlist"
)

// membershipEvents implements memberlist.EventDelegate. It wakes the
// replicator's peer-discovery loop the instant a peer joins, leaves, or
// updates, instead of waiting for the periodic backstop poll. Callbacks fire on
// memberlist's own goroutines, so they must be cheap and non-blocking — they
// only signal a coalescing channel.
//
// It also keeps its own set of live PEERS, because losing the last one is what
// makes this node's replica stale (see replicaFreshness). The set cannot be
// read back from memberlist here: these callbacks run with memberlist's node
// lock held, and Members() takes the same lock.
type membershipEvents struct {
	client *Client

	mu    sync.Mutex
	peers map[string]struct{}
	// addrs is every live member's gossip address, copied while memberlist
	// holds its node lock. Members() reads addresses from here and never from
	// the *Node memberlist hands back: memberlist rewrites a node's Addr and
	// Port in place when it re-learns it (aliveNode), so reading Address() on
	// a returned *Node after memberlist's lock is released is a data race —
	// one the re-merge loop, which reads Members() while a healed partition
	// re-addresses every peer, hits under -race.
	addrs map[string]string
}

// addr returns name's gossip address as last delivered by an event.
func (e *membershipEvents) addr(name string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	a, ok := e.addrs[name]
	return a, ok
}

func (e *membershipEvents) setAddr(n *memberlist.Node) {
	e.mu.Lock()
	if e.addrs == nil {
		e.addrs = make(map[string]string)
	}
	e.addrs[n.Name] = n.Address()
	e.mu.Unlock()
}

func (e *membershipEvents) NotifyJoin(n *memberlist.Node) {
	if n != nil {
		e.setAddr(n)
	}
	if n != nil && n.Name != e.client.hostName {
		e.mu.Lock()
		if e.peers == nil {
			e.peers = make(map[string]struct{})
		}
		e.peers[n.Name] = struct{}{}
		e.mu.Unlock()
		e.client.noteGossipAddr(n.Name, n.Address())
	}
	e.client.kickMembership()
}

func (e *membershipEvents) NotifyLeave(n *memberlist.Node) {
	if n != nil && n.Name != e.client.hostName {
		e.mu.Lock()
		_, had := e.peers[n.Name]
		delete(e.peers, n.Name)
		delete(e.addrs, n.Name)
		lastGone := had && len(e.peers) == 0
		e.mu.Unlock()
		if lastGone {
			e.client.MarkReplicaStale("lost sight of every gossip peer (last to leave: " + n.Name + ")")
		}
	}
	e.client.kickMembership()
}

func (e *membershipEvents) NotifyUpdate(n *memberlist.Node) {
	if n != nil {
		e.setAddr(n)
	}
	e.client.kickMembership()
}

// delegate implements memberlist.Delegate for the Client.
// Memberlist is used for membership detection only — no application data
// is sent through gossip. Replication is handled by the WAL-based replicator.
type delegate struct {
	client *Client
}

func (d *delegate) NodeMeta(limit int) []byte {
	return []byte(d.client.hostName)
}

// NotifyMsg is a no-op — application data is replicated via gRPC, not gossip.
func (d *delegate) NotifyMsg(msg []byte) {
	if len(msg) > 0 {
		slog.Debug("gossip: ignoring data message (replication handled by WAL)")
	}
}

// GetBroadcasts returns nil — we don't broadcast application data via gossip.
func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	return nil
}

// LocalState returns nil — full state sync is handled by the replicator on join.
func (d *delegate) LocalState(join bool) []byte {
	return nil
}

// MergeRemoteState is a no-op — state merging is handled by the replicator.
func (d *delegate) MergeRemoteState(buf []byte, join bool) {}
