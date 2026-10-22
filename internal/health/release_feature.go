package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ReleaseUseConfirmer asks host whether its replica holds the used record of
// (token, feature). Injected from the daemon
// (grpcapi.Server.PeerHoldsReleaseFeatureUse). An unreachable host errors.
type ReleaseUseConfirmer func(ctx context.Context, host, token, feature string) (bool, error)

// SetReleaseUseConfirmer injects the acknowledgement a first use waits on.
// Without one no first use can be acknowledged: fail closed.
func (c *Checker) SetReleaseUseConfirmer(fn ReleaseUseConfirmer) {
	c.mu.Lock()
	c.releaseConfirm = fn
	c.mu.Unlock()
}

// SetUnknownReleaseTokenObserver injects what to do when a peer's Ping
// advertises a release token this build does not know: the daemon looks at
// that peer's used records without blocking anything
// (corrosion.AntiEntropy.OnUnknownReleaseToken) — never a probation (N2).
// Called once per token per Checker.
func (c *Checker) SetUnknownReleaseTokenObserver(fn func(peer, token string)) {
	c.mu.Lock()
	c.unknownReleaseObserver = fn
	c.mu.Unlock()
}

// noteAdvertised reports, once per token, a release token a peer advertises
// that this build does not know.
func (c *Checker) noteAdvertised(peer string, caps []string) {
	for _, tok := range caps {
		if !strings.HasPrefix(tok, "release_") || corrosion.ReleaseTokenKnown(tok) {
			continue
		}
		c.mu.Lock()
		fn := c.unknownReleaseObserver
		seen := c.unknownReleaseSeen[tok]
		// Marked seen only once someone was told (N7): a token seen before the
		// observer is wired is reported on the next Ping that carries it.
		if fn != nil && !seen {
			if c.unknownReleaseSeen == nil {
				c.unknownReleaseSeen = map[string]bool{}
			}
			c.unknownReleaseSeen[tok] = true
		}
		c.mu.Unlock()
		if fn != nil && !seen {
			fn(peer, tok)
		}
	}
}

// mintGrant is the only FeatureGrant minter, claimed at init: no other package
// can claim it after this one has.
var mintGrant = capabilities.ClaimGrantMinter()

// RestoreAutomationContinuityReleaseUse restores a completed historical first
// use barrier from a verified continuity lineage. It does not assert a current
// peer list or sweep time, and never mints a grant. Ordinary WithFeature follows.
func (c *Checker) RestoreAutomationContinuityReleaseUse(ctx context.Context, proof *corrosion.AutomationContinuityReleaseEvidence) error {
	feature := capabilities.FeatureAutomationIdentityContinuity
	info, ok := capabilities.LookupFeature(feature)
	if !ok || info.Token != capabilities.Release202702V1 || c.db == nil {
		return status.Error(codes.FailedPrecondition, "continuity release restoration unavailable")
	}
	if err := c.db.ValidateAutomationContinuityReleaseEvidence(ctx, proof); err != nil {
		return err
	}
	// Validation has completed its local transaction. Marker ownership and the
	// replicated use write must never run while holding the Client mutex.
	c.mu.Lock()
	base := c.activationMarkerBase
	if base != "" {
		c.activated[info.Token] = true
	}
	c.mu.Unlock()
	if base == "" {
		return status.Error(codes.Unavailable, "continuity activation marker unavailable")
	}
	if !c.DurablyLatched(info.Token) {
		c.persistActivationMarker(base, info.Token)
	}
	if !c.DurablyLatched(info.Token) {
		return status.Error(codes.Unavailable, "continuity activation marker not durable")
	}
	return corrosion.RecordReleaseFeatureUse(ctx, c.db, info.Token, string(feature), c.hostName, true)
}

// releaseAckTimeout bounds how long a first use waits for every recipient to
// acknowledge its record. A var so tests can shrink it.
var releaseAckTimeout = 30 * time.Second

// releaseAckPoll is the interval between acknowledgement rounds.
const releaseAckPoll = 100 * time.Millisecond

// WithFeature runs write — the write that stores a release feature's data —
// only once the feature's gate has passed on THIS node, and hands it the
// FeatureGrant that proves it. A writer of feature data takes the grant and
// calls Check before it writes; nothing else mints one. Call it on the node
// that performs the write, not on the node that accepted the request.
//
// The gate:
//
//  1. An undeclared feature is refused with Internal (the set is closed).
//  2. Until the feature's release token has DURABLY latched, FailedPrecondition:
//     "the cluster upgrade must finish first (<feature> needs <token>)".
//  3. Once per process per feature, this node puts its OWN used record on its
//     own outgoing stream before its first write (C1): feature data from any
//     origin then has that origin's record ahead of it, so a receiver that
//     cannot keep it trips before applying it, whichever stream reaches it.
//     - If the replica holds an ACKNOWLEDGED record (any node's), re-recording
//     it is enough.
//     - Otherwise this is a first use, or a first use whose acknowledgement
//     never completed. Every host this node replicates to must still advertise
//     the token (fresh Pings): a host rolled back after the latch holds it off.
//     The record is written, and then EVERY one of those hosts must answer that
//     its replica holds it (I1) before the record is marked acknowledged and the
//     write may run — so the record is durable and replicated, not merely
//     queued, before any feature data exists. A host that does not answer in
//     time refuses the write with Unavailable; the record stays (monotone) and
//     the next attempt waits again.
//  4. Any failure to record refuses the write.
//
// The write's own error is returned unchanged.
func (c *Checker) WithFeature(ctx context.Context, feature capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	if err := c.requireFeature(ctx, feature); err != nil {
		return err
	}
	return write(ctx, mintGrant(feature))
}

// FeatureAvailable reports whether feature is declared and its release token
// has DURABLY latched here, asking no peer (m7). It is a hint for a caller that
// falls back rather than fails, never a grant: WithFeature can still refuse,
// and is still the only way to write the feature's data.
func (c *Checker) FeatureAvailable(feature capabilities.Feature) bool {
	info, ok := capabilities.LookupFeature(feature)
	return ok && c.DurablyLatched(info.Token)
}

// FeatureRefusal is WithFeature's latch step alone, for an entry-node
// fail-fast that must not record or grant anything: nil when feature's release
// token has durably latched here — driving the latch first, so a call made the
// moment the last host finishes upgrading does not wait for the HA monitor —
// else the same FailedPrecondition WithFeature returns (the lagging hosts with
// their versions, and the pointer to `lv cluster upgrade-status`). It writes no
// used record, so a request that later fails leaves none; the node that writes
// the feature's data still goes through WithFeature.
func (c *Checker) FeatureRefusal(ctx context.Context, feature capabilities.Feature) error {
	_, err := c.latchOrRefuse(ctx, feature)
	return err
}

// latchOrRefuse drives and checks the feature's token latch (the first step of
// WithFeature) and returns the feature's token.
func (c *Checker) latchOrRefuse(ctx context.Context, feature capabilities.Feature) (string, error) {
	info, ok := capabilities.LookupFeature(feature)
	if !ok {
		return "", status.Errorf(codes.Internal, "release feature %q is not declared by this build", feature)
	}
	tok := info.Token
	if !c.DurablyLatched(tok) {
		// Drive the latch from here too, so the first use after a roll does
		// not wait for the HA monitor's turn.
		c.Enforced(ctx, tok)
		if !c.DurablyLatched(tok) {
			return tok, releaseRefusal(feature, tok, c.releaseLaggards(ctx, tok))
		}
	}
	return tok, nil
}

func releaseRefusal(feature capabilities.Feature, tok, why string) error {
	msg := fmt.Sprintf("the cluster upgrade must finish first (%s needs %s)", feature, tok)
	if why != "" {
		msg += ": " + why
	}
	return status.Error(codes.FailedPrecondition, msg)
}

// requireFeature is WithFeature's gate (see there).
func (c *Checker) requireFeature(ctx context.Context, feature capabilities.Feature) error {
	tok, err := c.latchOrRefuse(ctx, feature)
	if err != nil {
		return err
	}
	refuse := func(why string) error { return releaseRefusal(feature, tok, why) }
	c.mu.Lock()
	recorded := c.featuresRecorded[feature]
	c.mu.Unlock()
	if recorded {
		return nil
	}
	present, acked, err := corrosion.ReleaseFeatureState(ctx, c.db, tok, string(feature))
	if err != nil {
		return status.Errorf(codes.Unavailable, "read whether %s is in use: %v", feature, err)
	}
	record := func(acked bool) error {
		if err := corrosion.RecordReleaseFeatureUse(ctx, c.db, tok, string(feature), c.hostName, acked); err != nil {
			if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
				return refuse("the cluster policy table is not writable yet")
			}
			return status.Errorf(codes.Unavailable,
				"could not record that %s is in use, so the write is refused: %v", feature, err)
		}
		return nil
	}
	if present && acked {
		// Every recipient held it once; this node's own copy goes on its own
		// stream ahead of its data.
		if err := record(true); err != nil {
			return err
		}
	} else {
		targets, rerr := c.releaseRecipients(ctx, tok)
		if rerr != nil {
			if errors.Is(rerr, errReleaseLagging) {
				return refuse(c.releaseLaggards(ctx, tok))
			}
			return refuse(rerr.Error())
		}
		if err := record(false); err != nil {
			return err
		}
		if err := c.awaitReleaseAcks(ctx, targets, tok, string(feature)); err != nil {
			return err
		}
		if err := record(true); err != nil {
			return err
		}
	}
	c.mu.Lock()
	if c.featuresRecorded == nil {
		c.featuresRecorded = map[capabilities.Feature]bool{}
	}
	c.featuresRecorded[feature] = true
	c.mu.Unlock()
	return nil
}

// releaseRecipients re-confirms, from fresh Pings, that every host this node
// replicates to (and every voting-eligible host) advertises tok, and returns
// the hosts that must acknowledge a first use, this node excluded: those, plus
// every member of the voter set (N3) — a voter in maintenance included,
// because a later probation majority is drawn from the voter set. A powered-off
// maintenance host that is not a voter is neither, and does not block.
func (c *Checker) releaseRecipients(ctx context.Context, tok string) ([]string, error) {
	if ok, _ := c.CapabilityActive(ctx, tok); !ok {
		return nil, errReleaseLagging
	}
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return nil, fmt.Errorf("read hosts: %v", err)
	}
	voters, err := c.voters(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the voter set: %v", err)
	}
	set := map[string]bool{}
	for _, h := range c.activationTargets(hosts, tok) {
		set[h] = true
	}
	for v := range voters {
		set[v] = true
	}
	delete(set, c.hostName)
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out, nil
}

// awaitReleaseAcks waits until every target answers that its replica holds the
// record, or refuses with Unavailable naming those that did not.
func (c *Checker) awaitReleaseAcks(ctx context.Context, targets []string, tok, feature string) error {
	if len(targets) == 0 {
		return nil
	}
	c.mu.Lock()
	confirm := c.releaseConfirm
	c.mu.Unlock()
	if confirm == nil {
		return status.Errorf(codes.Unavailable,
			"cannot confirm that %s's use is recorded on every host (no acknowledgement path); the write is refused", feature)
	}
	deadline := time.Now().Add(releaseAckTimeout)
	pending := append([]string(nil), targets...)
	for {
		// Every pending recipient at once (N10), so one slow host costs one
		// timeout per round, not one each.
		held := make([]bool, len(pending))
		probation := make([]bool, len(pending))
		var wg sync.WaitGroup
		for i, h := range pending {
			wg.Add(1)
			go func(i int, h string) {
				defer wg.Done()
				cctx, cancel := context.WithTimeout(ctx, capActivationTimeout)
				ok, err := confirm(cctx, h, tok, feature)
				cancel()
				held[i] = err == nil && ok
				probation[i] = errors.Is(err, corrosion.ErrReleaseProbation)
			}(i, h)
		}
		wg.Wait()
		var still []string
		inProbation := map[string]bool{}
		for i, h := range pending {
			if !held[i] {
				still = append(still, h)
				inProbation[h] = probation[i]
			}
		}
		pending = still
		if len(pending) == 0 {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			slog.Warn("release feature: a first use was not acknowledged by every recipient; refusing the write",
				"feature", feature, "token", tok, "unacknowledged", pending)
			voters, _ := c.voters(ctx)
			var hints []string
			for _, h := range pending {
				switch {
				case inProbation[h]:
					// A live host that applies nothing until its probation
					// lifts (m1): removing it is not the way out.
					hints = append(hints, fmt.Sprintf("%s is in release probation and holds no new record until it "+
						"lifts (see `lv cluster upgrade-status`)", h))
				case voters[h]:
					hints = append(hints, fmt.Sprintf("%s is a voter: if it is gone for good, `lv cluster voter rm %s` "+
						"removes it and lets this proceed", h, h))
				}
			}
			msg := fmt.Sprintf("%s's use is recorded here but not yet acknowledged by %s; the write is refused "+
				"until every host holds the record — retry", feature, strings.Join(pending, ", "))
			if len(hints) > 0 {
				msg += ". " + strings.Join(hints, "; ")
			}
			return status.Error(codes.Unavailable, msg)
		}
		select {
		case <-ctx.Done():
		case <-time.After(releaseAckPoll):
		}
	}
}

// errReleaseLagging: some host this node must hear the token from does not
// advertise it now.
var errReleaseLagging = errors.New("a host does not advertise the release token")

// releaseLaggards names, for a refusal, every host this node must hear the
// token from that does not advertise it now, with its reported build version,
// and points at the status command (UX 1). It pings every target (a refusal
// is rare, and the operator needs the whole list, not the first miss).
func (c *Checker) releaseLaggards(ctx context.Context, tok string) string {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return "not every host this one replicates to runs a build that keeps it yet — see `lv cluster upgrade-status`"
	}
	version := map[string]string{}
	for _, h := range hosts {
		version[h.Name] = h.Version
	}
	c.mu.Lock()
	pinger := c.peerPinger
	c.mu.Unlock()
	targets := c.activationTargets(hosts, tok)
	lag := make([]string, len(targets))
	var wg sync.WaitGroup
	for i, h := range targets {
		if h == c.hostName {
			continue
		}
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			if pinger == nil {
				lag[i] = h + " (unreachable)"
				return
			}
			pctx, cancel := context.WithTimeout(ctx, capActivationTimeout)
			caps, _, err := pinger(pctx, h)
			cancel()
			switch {
			case err != nil:
				lag[i] = h + " (unreachable)"
			case !capabilities.Has(caps, tok):
				v := version[h]
				if v == "" {
					v = "version unknown"
				}
				lag[i] = h + " (" + v + ")"
			}
		}(i, h)
	}
	wg.Wait()
	var out []string
	for _, l := range lag {
		if l != "" {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return "the release token has not latched on this host yet; it latches by itself shortly — see " +
			"`lv cluster upgrade-status`"
	}
	return "not on this release yet: " + strings.Join(out, ", ") + " — see `lv cluster upgrade-status`"
}
