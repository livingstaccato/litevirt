package fleet

// Message faults on the recovery-claim RPCs (docs/design/recovery-claims.md
// §3.15 "Duplicated or reordered message", "Message lost"; §7.1 "Claim-RPC
// faults").
//
// Like every LinkFault this sits on the RECEIVING voter, as part of
// faultUnaryInterceptor, keyed by the caller's mTLS common name, and applies to
// PrepareRecoveryClaim and AcceptRecoveryClaim only. What it does to one RPC is
// its ClaimFate:
//
//   - ClaimDropRequest: the request never arrives. The voter changes nothing;
//     the proposer sees Unavailable.
//   - ClaimDropReply: the voter handles the request and commits, and the reply
//     is lost on the way back: the proposer sees Unavailable for a promise or
//     an accept the voter durably made.
//   - ClaimDuplicate: the request arrives twice. The proposer gets the second
//     answer, which is the one a retransmission would produce.
//   - ClaimHold: the request is held in the network and the proposer sees
//     Unavailable at once. The held request is delivered after the NEXT claim
//     RPC on the same link has been handled — so it reaches the voter after a
//     newer round from the same sender — or when the link's fault is replaced
//     or ReleaseHeldClaims runs. This is both "reordered" and "delayed until
//     after a newer round": its answer goes nowhere, as a reply that arrives
//     after the proposer gave up on the call goes nowhere.
//
// A fate is drawn from a per-link PRNG seeded from Options.FaultSeed and the
// link's name (a separate stream from the push faults'), four draws per RPC,
// so the same sequence of claim RPCs on a link always meets the same sequence
// of fates. A scenario that needs an exact schedule sets a ClaimScript, which
// is consulted first.
//
// The proposer's own vote is a local call and never crosses a link, so it is
// never faulted. That is the production shape: a coordinator cannot lose a
// message to itself.

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand/v2"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ClaimFate is what the network does to one claim RPC.
type ClaimFate int

const (
	// ClaimDefault defers to the link's ClaimFault probabilities (a script's
	// "no opinion").
	ClaimDefault ClaimFate = iota
	ClaimDeliver
	ClaimDropRequest
	ClaimDropReply
	ClaimDuplicate
	ClaimHold
)

func (f ClaimFate) String() string {
	switch f {
	case ClaimDeliver:
		return "deliver"
	case ClaimDropRequest:
		return "drop-request"
	case ClaimDropReply:
		return "drop-reply"
	case ClaimDuplicate:
		return "duplicate"
	case ClaimHold:
		return "hold"
	}
	return "default"
}

// ClaimFault is the per-RPC probability of each fate on one link's Prepare and
// Accept RPCs. The zero value delivers everything.
type ClaimFault struct {
	DropRequest float64
	DropReply   float64
	Duplicate   float64
	Hold        float64
}

// ClaimMsg is one claim RPC as a ClaimScript sees it.
type ClaimMsg struct {
	From, To string
	Method   string // PrepareRecoveryClaim | AcceptRecoveryClaim
	Seq      int    // this link's claim RPCs so far, from 0
}

// ClaimScript decides a claim RPC's fate; ClaimDefault leaves it to the link.
type ClaimScript func(ClaimMsg) ClaimFate

// ClaimStats counts what the claim injector did on one directed link.
type ClaimStats struct {
	Calls         int
	Delivered     int
	DroppedReq    int
	DroppedReply  int
	Duplicated    int
	Held          int
	HeldDelivered int
}

// claimLink is the claim injector's state for one directed link, kept beside
// the push injector's in linkState.
type claimLink struct {
	rng   *rand.Rand
	held  []heldPush
	stats ClaimStats
}

// faultedClaimMethods are the claim RPCs that carry a ballot.
var faultedClaimMethods = map[string]bool{
	"PrepareRecoveryClaim": true,
	"AcceptRecoveryClaim":  true,
}

func (c *Cluster) claimRNG(from, to string) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(linkName(from, to) + "/claims"))
	return rand.New(rand.NewPCG(uint64(c.opts.FaultSeed), h.Sum64()))
}

// claimLinkState returns (creating) the claim injector state for from→n.
// Caller holds n.faults.mu.
func (n *Node) claimLinkState(from string) *claimLink {
	ls := n.link(from)
	if ls.claim == nil {
		ls.claim = &claimLink{rng: n.cluster.claimRNG(from, n.Name)}
	}
	return ls.claim
}

// SetClaimScript installs (nil removes) a cluster-wide claim schedule.
func (c *Cluster) SetClaimScript(s ClaimScript) {
	c.claimScriptMu.Lock()
	c.claimScript = s
	c.claimScriptMu.Unlock()
}

func (c *Cluster) claimScriptFate(m ClaimMsg) ClaimFate {
	c.claimScriptMu.Lock()
	s := c.claimScript
	c.claimScriptMu.Unlock()
	if s == nil {
		return ClaimDefault
	}
	return s(m)
}

// ClaimStats reports what the claim injector has done on from→to so far.
func (c *Cluster) ClaimStats(from, to *Node) ClaimStats {
	to.faults.mu.Lock()
	defer to.faults.mu.Unlock()
	return to.claimLinkState(from.Name).stats
}

// ReleaseHeldClaims delivers every claim RPC any link is holding, in the order
// each link held them — the network finally giving up the stragglers.
func (c *Cluster) ReleaseHeldClaims() {
	for _, to := range c.Nodes {
		for _, from := range c.Nodes {
			if from != to {
				to.deliverHeldClaims(from.Name, to.takeHeldClaims(from.Name))
			}
		}
	}
}

func (n *Node) takeHeldClaims(from string) []heldPush {
	n.faults.mu.Lock()
	defer n.faults.mu.Unlock()
	cl := n.claimLinkState(from)
	held := cl.held
	cl.held = nil
	return held
}

// deliverHeldClaims hands held claim RPCs to the voter. Their senders have long
// stopped waiting, so the answers are discarded.
func (n *Node) deliverHeldClaims(from string, held []heldPush) {
	for _, h := range held {
		_, _ = h.handler(h.ctx, h.req)
		n.faults.mu.Lock()
		n.claimLinkState(from).stats.HeldDelivered++
		n.faults.mu.Unlock()
	}
}

// claimFaultIntercept applies the link's claim fault to one Prepare or Accept.
func (n *Node) claimFaultIntercept(ctx context.Context, req any, from, method string, handler grpc.UnaryHandler) (any, error) {
	n.faults.mu.Lock()
	ls := n.link(from)
	f := ls.fault.Claim
	cl := n.claimLinkState(from)
	seq := cl.stats.Calls
	cl.stats.Calls++
	// Always four draws, so the fate sequence depends only on how many claim
	// RPCs the link has carried, whatever a script decided.
	dropReq, dropReply, dup, hold := cl.rng.Float64(), cl.rng.Float64(), cl.rng.Float64(), cl.rng.Float64()
	n.faults.mu.Unlock()

	fate := n.cluster.claimScriptFate(ClaimMsg{From: from, To: n.Name, Method: method, Seq: seq})
	if fate == ClaimDefault {
		switch {
		case dropReq < f.DropRequest:
			fate = ClaimDropRequest
		case dropReply < f.DropReply:
			fate = ClaimDropReply
		case hold < f.Hold:
			fate = ClaimHold
		case dup < f.Duplicate:
			fate = ClaimDuplicate
		default:
			fate = ClaimDeliver
		}
	}

	unavailable := func(what string) error {
		return status.Errorf(codes.Unavailable, "fleet claim fault: %s %s->%s %s", method, from, n.Name, what)
	}
	n.faults.mu.Lock()
	switch fate {
	case ClaimDropRequest:
		cl.stats.DroppedReq++
	case ClaimDropReply:
		cl.stats.DroppedReply++
	case ClaimDuplicate:
		cl.stats.Duplicated++
	case ClaimHold:
		cl.stats.Held++
		cl.held = append(cl.held, heldPush{ctx: context.WithoutCancel(ctx), req: req, handler: handler})
	}
	n.faults.mu.Unlock()

	switch fate {
	case ClaimDropRequest:
		return nil, unavailable("dropped")
	case ClaimHold:
		return nil, unavailable("held in the network")
	}
	resp, err := handler(ctx, req)
	if fate == ClaimDuplicate && err == nil {
		resp, err = handler(ctx, req)
	}
	n.faults.mu.Lock()
	cl.stats.Delivered++
	n.faults.mu.Unlock()
	// What the network held behind this one arrives after it.
	n.deliverHeldClaims(from, n.takeHeldClaims(from))
	if fate == ClaimDropReply {
		return nil, unavailable(fmt.Sprintf("reply lost (the voter answered err=%v)", err))
	}
	return resp, err
}

// Crash stops n's daemon for good, mid-whatever it was doing: every link into
// and out of it fails (Kill), its push loop stops, and its gRPC server stops
// answering. Its database stays as the crash left it — the disk survives — but
// nothing it does afterwards can reach any other node.
func (c *Cluster) Crash(n *Node) {
	c.Kill(n)
	if n.replStarted {
		n.repl.Stop()
		n.replStarted = false
	}
	if n.GRPCSrv != nil {
		n.GRPCSrv.Stop()
	}
}
