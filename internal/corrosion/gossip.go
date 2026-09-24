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
}

func (e *membershipEvents) NotifyJoin(n *memberlist.Node) {
	if n != nil && n.Name != e.client.hostName {
		e.mu.Lock()
		if e.peers == nil {
			e.peers = make(map[string]struct{})
		}
		e.peers[n.Name] = struct{}{}
		e.mu.Unlock()
	}
	e.client.kickMembership()
}

func (e *membershipEvents) NotifyLeave(n *memberlist.Node) {
	if n != nil && n.Name != e.client.hostName {
		e.mu.Lock()
		_, had := e.peers[n.Name]
		delete(e.peers, n.Name)
		lastGone := had && len(e.peers) == 0
		e.mu.Unlock()
		if lastGone {
			e.client.MarkReplicaStale("lost sight of every gossip peer (last to leave: " + n.Name + ")")
		}
	}
	e.client.kickMembership()
}

func (e *membershipEvents) NotifyUpdate(*memberlist.Node) { e.client.kickMembership() }

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
