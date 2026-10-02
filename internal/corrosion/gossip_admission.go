package corrosion

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/memberlist"
)

// Gossip admission (colonelpanik/litevirt#259, step 1).
//
// memberlist runs with no keyring, so anyone who can reach the gossip port can
// announce a member. Before this, every such member was believed: it inflated
// the relay election's N and R and could take a relay slot by sorting first,
// anti-entropy dialled it, and — worst — capability activation counts every
// memberlist member for a ReplicationGated token, so ONE injected phantom held
// lease_term_ledger_v1 un-latched cluster-wide for as long as it kept
// announcing itself.
//
// The rule, in one place: a member is admitted iff
//
//   - it is this node, or
//   - its name is a hosts row that is not tombstoned AND its gossip address is
//     that row's address (so a phantom cannot borrow a real host's name), or
//   - this node has not yet learned its cluster at all — it holds no hosts row
//     but its own, live or tombstoned — and it was started with seeds to join.
//
// The last clause is bootstrap, and it is not optional. `lv host add` writes
// the new host's row on the ADMITTING node before the new daemon starts, so
// every existing node knows the newcomer; but the newcomer itself starts with
// nothing but its own row, and learns the rest by replication from peers it
// can only find through gossip. Refusing unknown names there would be the gossip
// twin of the mTLS bootstrap deadlock isTrustedHostCN documents. The window
// closes at the first replicated row; a founder (no seeds) and the survivor of
// a removal (it holds a tombstone) never open it.
//
// Admission is re-evaluated on every alive message and every push/pull, and a
// refusal is not remembered. A host that joins before its row has replicated
// to some existing node is refused THERE, and admitted by the first gossip
// exchange that carries it after the row arrives: memberlist's periodic
// push/pull (30s on the LAN profile, scaled up past 32 members), or the next
// pass of maintainMembership, which dials a listed host that gossip does not
// show (and every target when it sees nobody at all). Those re-joins are
// ordinary Joins and pass this same predicate.
//
// This is admission, not authentication. Without a keyring a host on the
// segment can still claim a real host's name from that host's own address, or
// perturb the failure detector; the keyring is step 2 of #259.

// admissionRow is one hosts row as admission sees it.
type admissionRow struct {
	ip      net.IP
	deleted bool
}

// gossipAdmission is a snapshot of the admission table.
type gossipAdmission struct {
	self   string
	rows   map[string]admissionRow
	seeded bool
}

// knowsCluster reports whether this node holds any host row but its own —
// live or tombstoned.
func (a *gossipAdmission) knowsCluster() bool {
	for name := range a.rows {
		if name != a.self {
			return true
		}
	}
	return false
}

// admit is THE predicate. Every membership consumer goes through it — the
// memberlist delegates below and Members() — so the set a node gossips with and
// the set it counts cannot drift apart.
func (a *gossipAdmission) admit(name string, ip net.IP) error {
	if name == a.self {
		return nil
	}
	row, ok := a.rows[name]
	switch {
	case !ok:
		if a.seeded && !a.knowsCluster() {
			return nil // bootstrap: see the package comment above
		}
		return fmt.Errorf("gossip member %q is not a host of this cluster (no hosts row here yet); "+
			"refused for now — it is admitted on the first exchange after its row replicates", name)
	case row.deleted:
		return fmt.Errorf("gossip member %q was removed from this cluster (its hosts row is tombstoned)", name)
	case row.ip == nil || ip == nil || !row.ip.Equal(ip):
		return fmt.Errorf("gossip member %q announced address %v, but its hosts row records %v; "+
			"refusing it — if the host is multi-homed, set advertise_address to the recorded address", name, ip, row.ip)
	}
	return nil
}

// loadAdmission reads the admission table without ever blocking on the
// client's lock.
//
// It is called from memberlist's AliveDelegate, which runs with memberlist's
// node lock held: blocking there on a writer holding c.mu (a large merge, a
// reseed) would stall probes and acks and get this node suspected by its
// peers — or deadlock, if that writer ever waits on memberlist. So a contended
// lock, or a failed read, answers from the last snapshot that succeeded.
// NewClient takes the first snapshot before memberlist exists, so there always
// is one on a gossiping client; a client that has never read successfully
// (the schema does not exist yet on a brand-new node) holds no rows, which is
// exactly what that node knows.
func (c *Client) loadAdmission() *gossipAdmission {
	if c.mu.TryRLock() {
		fresh, err := c.readAdmissionLocked()
		c.mu.RUnlock()
		if err == nil {
			c.admission.Store(fresh)
			return fresh
		}
	}
	if last := c.admission.Load(); last != nil {
		return last
	}
	return &gossipAdmission{self: c.hostName, rows: map[string]admissionRow{}, seeded: c.gossipSeeded}
}

// readAdmissionLocked reads every hosts row, tombstones included. The caller
// holds c.mu for reading.
func (c *Client) readAdmissionLocked() (*gossipAdmission, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rows, err := c.db.QueryContext(ctx, `SELECT name, address, deleted_at FROM hosts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	a := &gossipAdmission{self: c.hostName, rows: map[string]admissionRow{}, seeded: c.gossipSeeded}
	for rows.Next() {
		var name, addr string
		var deleted *string
		if err := rows.Scan(&name, &addr, &deleted); err != nil {
			return nil, err
		}
		a.rows[name] = admissionRow{ip: net.ParseIP(addr), deleted: deleted != nil && *deleted != ""}
	}
	return a, rows.Err()
}

// admissionDelegate is memberlist's AliveDelegate and MergeDelegate.
type admissionDelegate struct{ client *Client }

// NotifyAlive gates every alive message — join, push/pull merge, refutation —
// before memberlist adds or updates the node. An error drops that message only.
func (d *admissionDelegate) NotifyAlive(n *memberlist.Node) error {
	return d.client.loadAdmission().admit(n.Name, n.Addr)
}

// NotifyMerge sees the whole remote state of a JOIN exchange, and an error
// refuses the join outright. It refuses one that offers no admissible member —
// a phantom joining this cluster, or this node being pointed at someone else's.
// A join that offers any admissible member proceeds, and NotifyAlive then drops
// the rest one by one; refusing it whole would let one stale or hostile entry in
// a peer's view keep a legitimate host out.
func (d *admissionDelegate) NotifyMerge(peers []*memberlist.Node) error {
	if len(peers) == 0 {
		return nil
	}
	a := d.client.loadAdmission()
	refused := make([]string, 0, len(peers))
	for _, p := range peers {
		if err := a.admit(p.Name, p.Addr); err == nil {
			return nil
		}
		refused = append(refused, fmt.Sprintf("%s@%v", p.Name, p.Addr))
	}
	return fmt.Errorf("refusing gossip join: none of the members it offers is a host of this cluster [%s]",
		strings.Join(refused, ", "))
}

// admittedOnly filters a raw gossip view down to admitted members.
func (c *Client) admittedOnly(raw []PeerInfo) []PeerInfo {
	if len(raw) == 0 {
		return raw
	}
	a := c.loadAdmission()
	out := raw[:0:0]
	for _, p := range raw {
		if a.admit(p.Name, gossipIP(p.Addr)) == nil {
			out = append(out, p)
		}
	}
	return out
}

// gossipIP is the IP of a memberlist "ip:port" address (or a bare IP).
func gossipIP(addr string) net.IP {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		addr = h
	}
	return net.ParseIP(addr)
}
