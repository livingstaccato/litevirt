package corrosion

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"slices"
	"time"
)

// rejoinInterval is how often the membership loop runs a pass: an ISOLATED node
// retries the cluster, and a node missing some listed hosts dials those.
// Jittered so N nodes coming back from the same partition do not dial in
// lockstep.
const rejoinInterval = 30 * time.Second

// remergeMaxSkip caps the per-host backoff of the re-merge pass: a host that
// stays missing is dialled at most once every remergeMaxSkip+1 passes (about
// 2–3 minutes at the default interval). It is a cap, not an exponential without
// end, because the same backoff is what a healed partition waits out: a
// partition that lasted an hour must still re-merge within one capped wait.
const remergeMaxSkip = 3

// rejoiner keeps this node's gossip view joined to the cluster the hosts table
// describes.
//
// list.Join runs once, at startup, and a failure is logged and stepped over.
// Peer discovery for replication and anti-entropy both derive from Members(),
// so a node whose seeds were unavailable at boot -- or whose membership aged out
// across a long partition -- would keep that view for as long as the process
// lives. Anti-entropy cannot repair against a peer it never discovers, and the
// only known cure was a rolling daemon restart, because a restart was the only
// thing that ever called Join again. There are two triggers:
//
// ISOLATED — this node can see no one. It dials every seed and every admitted
// host (tick).
//
// MISSING — this node sees peers, but a host the cluster still lists as a
// member is absent from gossip. It dials those hosts only (remerge). This is
// the healed partition: in a 2|3 split neither side is empty, and memberlist
// does not re-merge two live clusters by itself — each side declares the other
// dead, reaps it after GossipToTheDeadTime, and nobody dials it again. The
// kvm003 drill of 2026-10-02 left the halves apart for more than eight minutes
// after the heal, the minority never receiving the majority's fence row, moved
// VM or claim proof, until a daemon restart called Join.
//
// The seams are fields so the policy is testable without a real memberlist: the
// interesting behaviour is WHEN it dials and WHAT it dials, neither of which
// needs a gossip stack to pin.
type rejoiner struct {
	peerCount func() int
	targets   func() []string
	join      func([]string) (int, error)
	// missing lists the hosts the cluster lists as members that this node's
	// gossip view does not show. Nil disables the re-merge pass.
	missing func() []remergeTarget
	// backoff is the re-merge pass's per-host state, keyed by host name. Only
	// hosts currently missing have an entry.
	backoff map[string]*remergeBackoff
}

// remergeTarget is one listed host absent from gossip, and where to dial it.
type remergeTarget struct {
	Name string
	Addr string
}

// remergeBackoff is one missing host's place in the re-merge backoff.
type remergeBackoff struct {
	failures int // consecutive dials after which it was still missing
	wait     int // passes still to skip before dialling it again
}

// remergeResult is what one re-merge pass did.
type remergeResult struct {
	dialled   []string // hosts dialled this pass
	recovered []string // dialled hosts gossip shows after the pass
	missing   []string // dialled hosts still missing after the pass
	err       error
}

// tick performs at most one re-join attempt.
//
// It dials only when the visible peer set is EMPTY; a node that can see peers is
// remerge's business, which dials the missing hosts and nothing else.
// Re-joining every seed on a timer regardless would add exactly the O(N)
// periodic chatter that makes the fleet's sizing claim hard to defend.
func (r *rejoiner) tick() (attempted bool, joined int, err error) {
	if r.peerCount() > 0 {
		return false, 0, nil
	}
	targets := r.targets()
	if len(targets) == 0 {
		// A single-node cluster with no seeds is a legitimate configuration,
		// not a fault to report every interval.
		return false, 0, nil
	}
	joined, err = r.join(targets)
	return true, joined, err
}

// rejoinTargets is the address set an isolated node should dial.
//
// Seeds AND the admitted hosts table, because the two fail in different ways: a
// seed list can be stale or point at hosts that have since been replaced, while
// the hosts table is the cluster's own durable record of who belongs and is the
// only thing that survives a membership wipe.
//
// Callers pass the output of ListHosts, which filters tombstones, so a REMOVED
// host is already absent here -- an expelled member must never be dialled back
// into the cluster by its own recovery path.
func rejoinTargets(seeds []string, hosts []HostRecord, selfName, selfAddr string) []string {
	out := make([]string, 0, len(seeds)+len(hosts))
	for _, s := range seeds {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, h := range hosts {
		// Blank addresses make memberlist dial nothing and log noise; self is
		// pointless to dial by either name or address.
		if h.Address == "" || h.Name == selfName || h.Address == selfAddr {
			continue
		}
		if !slices.Contains(out, h.Address) {
			out = append(out, h.Address)
		}
	}
	return out
}

// remerge performs at most one re-merge pass: dial the listed hosts gossip does
// not show, each on its own backoff.
//
// The cost is O(missing), not O(N): a healthy cluster dials nobody, and a
// partition costs one dial per missing host per pass. A host that is dead but
// was never removed is backed off to one dial every remergeMaxSkip+1 passes,
// so it costs a bounded dial per interval for as long as it stays listed. A
// host that drops out is dialled on the next pass, whatever another host's
// backoff; one that comes back, by our dial or the other side's, is forgotten.
//
// The dial is memberlist's ordinary Join, so a re-merge passes the same gossip
// admission (NotifyMerge and NotifyAlive, on both ends) under the same keyring
// as a first join: nothing here can admit a host a normal join would refuse.
func (r *rejoiner) remerge() remergeResult {
	if r.missing == nil {
		return remergeResult{}
	}
	if r.backoff == nil {
		r.backoff = map[string]*remergeBackoff{}
	}
	missing := r.missing()
	listed := make(map[string]bool, len(missing))
	var res remergeResult
	var addrs []string
	for _, m := range missing {
		listed[m.Name] = true
		b := r.backoff[m.Name]
		if b == nil {
			b = &remergeBackoff{}
			r.backoff[m.Name] = b
		}
		if b.wait > 0 {
			b.wait--
			continue
		}
		res.dialled = append(res.dialled, m.Name)
		addrs = append(addrs, m.Addr)
	}
	for name := range r.backoff {
		if !listed[name] {
			delete(r.backoff, name) // visible again, or no longer listed
		}
	}
	if len(addrs) == 0 {
		return res
	}
	_, res.err = r.join(addrs)

	// Judged by what gossip shows AFTER the dial, not by Join's count: Join
	// says how many addresses answered, not which hosts are now members.
	still := map[string]bool{}
	for _, m := range r.missing() {
		still[m.Name] = true
	}
	for _, name := range res.dialled {
		if !still[name] {
			delete(r.backoff, name)
			res.recovered = append(res.recovered, name)
			continue
		}
		b := r.backoff[name]
		b.failures++
		// 1, 3, then the cap: dialled at passes 0, 2, 6, 10, 14, ...
		b.wait = min(1<<min(b.failures, 8)-1, remergeMaxSkip)
		res.missing = append(res.missing, name)
	}
	return res
}

// remergeTargets is the set of hosts the cluster lists as members that gossip
// does not show, each with the address to dial.
//
// hosts is ListHosts' output, so a REMOVED host is already absent: membership
// is the replicated hosts table with tombstones filtered — the set gossip
// admission admits from. Removal is also what revokes a host's certificate, so
// a revoked host is a tombstoned one. Host STATE is deliberately not a filter.
// The majority of a partition fences, or marks offline, exactly the hosts on
// the other side; a state filter would exclude the very hosts that need
// re-merging, and the minority would never receive the fence row that tells it
// so. A host in maintenance still runs its daemon and still receives
// replication, and while it reboots the backoff bounds what it costs.
//
// The address is the one memberlist last showed for the host while that still
// names the recorded IP — it carries the gossip port, which the recorded
// address does not — and otherwise the recorded address, which memberlist
// dials on this node's own gossip port. A bare address equal to ours would
// dial ourselves and is skipped.
func remergeTargets(hosts []HostRecord, visible []PeerInfo, lastAddr map[string]string, selfName, selfAddr string) []remergeTarget {
	seen := make(map[string]bool, len(visible))
	for _, p := range visible {
		seen[p.Name] = true
	}
	var out []remergeTarget
	for _, h := range hosts {
		if h.Name == selfName || h.Address == "" || seen[h.Name] {
			continue
		}
		addr := h.Address
		if last := lastAddr[h.Name]; last != "" {
			if ip, row := gossipIP(last), net.ParseIP(h.Address); ip != nil && row != nil && ip.Equal(row) {
				addr = last
			}
		}
		if addr == selfAddr {
			continue
		}
		out = append(out, remergeTarget{Name: h.Name, Addr: addr})
	}
	return out
}

// noteGossipAddr remembers the gossip address memberlist showed for a peer, so
// the re-merge pass can dial it — port included — after it drops out.
func (c *Client) noteGossipAddr(name, addr string) {
	if name == "" || addr == "" || name == c.hostName {
		return
	}
	c.gossipAddrMu.Lock()
	if c.gossipAddrs == nil {
		c.gossipAddrs = map[string]string{}
	}
	c.gossipAddrs[name] = addr
	c.gossipAddrMu.Unlock()
}

// missingMembers is remergeTargets over this node's hosts table, its current
// gossip view, and the gossip addresses it has seen. A failed hosts read
// yields nothing: unlike the isolated path, which falls back to the seeds, a
// node that sees peers loses nothing by skipping one pass.
func (c *Client) missingMembers(ctx context.Context, selfAddr string) []remergeTarget {
	visible := c.Members()
	for _, p := range visible {
		c.noteGossipAddr(p.Name, p.Addr)
	}
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("gossip: re-merge could not read the hosts table; skipping this pass", "error", err)
		}
		return nil
	}
	c.gossipAddrMu.Lock()
	last := maps.Clone(c.gossipAddrs)
	c.gossipAddrMu.Unlock()
	return remergeTargets(hosts, visible, last, c.hostName, selfAddr)
}

// maintainMembership runs the re-join loop until ctx ends.
//
// interval is the base pass interval; zero is rejoinInterval.
func (c *Client) maintainMembership(ctx context.Context, seeds []string, selfAddr string, interval time.Duration) {
	if interval <= 0 {
		interval = rejoinInterval
	}
	r := &rejoiner{
		peerCount: func() int { return len(c.Members()) },
		targets: func() []string {
			hosts, err := ListHosts(ctx, c)
			if err != nil {
				// Seeds alone are still better than nothing: this node is
				// isolated, and a local read failure is not a reason to stop
				// trying to find the cluster.
				slog.Warn("gossip: re-join could not read the hosts table; using seeds alone", "error", err)
				hosts = nil
			}
			return rejoinTargets(seeds, hosts, c.hostName, selfAddr)
		},
		join: cancellableJoin(ctx, func(ts []string) (int, error) {
			if c.list == nil {
				return 0, nil
			}
			return c.list.Join(ts)
		}),
		missing: func() []remergeTarget { return c.missingMembers(ctx, selfAddr) },
	}

	rep := &isolationReporter{c: c, host: c.hostName, now: time.Now}
	for {
		// Jittered so nodes recovering from one partition do not dial together.
		// 30–45 s: the package's symmetric jitter, centred so the range is the
		// one this loop has always had.
		d := jittered(interval+interval/4, 0.2)
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		c.membershipTick(ctx, r, rep)
	}
}

// membershipTick is one pass of the re-join loop: attempt a re-join if this
// node sees nobody, or re-merge the listed hosts it is missing if it sees some;
// log the outcome, and keep the isolation condition current.
func (c *Client) membershipTick(ctx context.Context, r *rejoiner, rep *isolationReporter) {
	attempted, joined, err := r.tick()
	if ctx.Err() != nil {
		// Close cancelled this pass. Nothing it learned is worth writing into
		// a store that is about to close.
		return
	}
	// Isolated means this pass had to try AND still sees nobody. A pass that
	// did not try either sees peers already or has nobody to find (a
	// single-node cluster with no seeds) — neither is isolation.
	//
	// Decided by the peers visible AFTER the attempt, not by Join's count: a
	// seed list that names this node (the shape a fleet sharing one join_peers
	// list has) lets Join reach itself and return (1, nil) while the node
	// still sees no one.
	isolated := attempted && r.peerCount() == 0
	rep.report(ctx, isolated, err)
	if !attempted {
		// Seeing peers is not seeing the cluster. A re-merge is not isolation
		// either: it neither raises gossip_isolated nor marks the replica
		// stale, or one dead, unremoved host would hold every node stale.
		if r.peerCount() > 0 {
			res := r.remerge()
			if ctx.Err() != nil {
				return // Close cancelled the dial; its outcome means nothing
			}
			c.logRemerge(res)
		}
		return
	}
	// The isolated path only attempts when this node sees no peer at all, so whatever it
	// held as caught up no longer covers what the cluster may be deciding
	// without it. Backstop for the leave event, which is the primary reset.
	c.MarkReplicaStale("sees no gossip peers (re-join loop)")
	if isolated {
		// REPORTED every attempt, not once at startup. "joined 0 of N" is
		// the signal an operator needs, and logging it once and carrying on
		// is what made a whole partition invisible.
		slog.Warn("gossip: this node sees no peers and could not re-join",
			"joined", joined, "error", err)
		return
	}
	if err != nil {
		// Some targets answered and the node now sees peers, so this pass
		// recovered; the partial failure is worth a line, not a condition.
		slog.Warn("gossip: re-joined after losing every peer, but some targets failed",
			"joined", joined, "error", err)
		return
	}
	slog.Info("gossip: re-joined after losing every peer", "peers", joined)
}

// logRemerge reports a re-merge pass. A pass that dialled says what came back
// and what did not: a host the cluster lists that gossip cannot reach is a
// finding, and the backoff already bounds how often it is repeated.
func (c *Client) logRemerge(res remergeResult) {
	if len(res.recovered) > 0 {
		slog.Info("gossip: re-merged hosts the cluster lists that were missing from membership",
			"hosts", res.recovered)
	}
	if len(res.missing) > 0 {
		slog.Warn("gossip: hosts the cluster lists are missing from membership and did not answer a re-join",
			"hosts", res.missing, "error", res.err)
	}
}

// cancellableJoin wraps a join so the loop can stop waiting for it.
//
// memberlist.Join takes no context and dials its targets one at a time, each
// bounded only by its TCP timeout: an isolated node with ten unreachable
// targets sits in a single Join for about 100 s. Close waits for the loop, so
// shutdown waited with it — past systemd's stop timeout. On cancellation the
// join is left to finish on its own goroutine; it touches only memberlist,
// which Close shuts down next, never the database.
func cancellableJoin(ctx context.Context, join func([]string) (int, error)) func([]string) (int, error) {
	return func(targets []string) (int, error) {
		type result struct {
			n   int
			err error
		}
		ch := make(chan result, 1)
		go func() {
			n, err := join(targets)
			ch <- result{n, err}
		}()
		select {
		case r := <-ch:
			return r.n, r.err
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}
