package corrosion

import (
	"context"
	"log/slog"
	"math/rand"
	"slices"
	"time"
)

// rejoinInterval is how often an ISOLATED node retries the cluster. Jittered so
// N nodes coming back from the same partition do not dial in lockstep.
const rejoinInterval = 30 * time.Second

// rejoiner re-joins the gossip cluster when this node can no longer see anyone.
//
// list.Join runs once, at startup, and a failure is logged and stepped over.
// Peer discovery for replication and anti-entropy both derive from Members(),
// so a node whose seeds were unavailable at boot -- or whose membership aged out
// across a long partition -- has an empty peer set for as long as the process
// lives. Anti-entropy cannot repair against a peer it never discovers, and the
// only known cure was a rolling daemon restart, because a restart was the only
// thing that ever called Join again.
//
// The seams are fields so the policy is testable without a real memberlist: the
// interesting behaviour is WHEN it dials and WHAT it dials, neither of which
// needs a gossip stack to pin.
type rejoiner struct {
	peerCount func() int
	targets   func() []string
	join      func([]string) (int, error)
}

// tick performs at most one re-join attempt.
//
// It dials only when the visible peer set is EMPTY. A node that can already see
// peers has nothing to rediscover, and re-joining on a timer regardless would
// add exactly the O(N) periodic chatter that makes the fleet's sizing claim
// hard to defend.
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

// maintainMembership runs the re-join loop until ctx ends.
func (c *Client) maintainMembership(ctx context.Context, seeds []string, selfAddr string) {
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
		join: func(ts []string) (int, error) {
			if c.list == nil {
				return 0, nil
			}
			return c.list.Join(ts)
		},
	}

	rep := &isolationReporter{c: c, host: c.hostName, now: time.Now}
	for {
		// Jittered so nodes recovering from one partition do not dial together.
		d := rejoinInterval + time.Duration(rand.Int63n(int64(rejoinInterval/2)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		c.membershipTick(ctx, r, rep)
	}
}

// membershipTick is one pass of the re-join loop: attempt a re-join if this
// node sees nobody, log the outcome, and keep the isolation condition current.
func (c *Client) membershipTick(ctx context.Context, r *rejoiner, rep *isolationReporter) {
	attempted, joined, err := r.tick()
	// Isolated means this pass had to try AND got nowhere. A pass that did not
	// try either sees peers already or has nobody to find (a single-node
	// cluster with no seeds) — neither is isolation.
	rep.report(ctx, attempted && (err != nil || joined == 0), err)
	if !attempted {
		return
	}
	if err != nil {
		// REPORTED every attempt, not once at startup. "joined 0 of N" is
		// the signal an operator needs, and logging it once and carrying on
		// is what made a whole partition invisible.
		slog.Warn("gossip: this node sees no peers and could not re-join",
			"joined", joined, "error", err)
		return
	}
	slog.Info("gossip: re-joined after losing every peer", "peers", joined)
}
