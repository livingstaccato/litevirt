package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
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
// advertises a release token this build does not know: the daemon puts the node
// in release probation (corrosion.Client.EnterReleaseProbation). Called once
// per token per Checker.
func (c *Checker) SetUnknownReleaseTokenObserver(fn func(token string)) {
	c.mu.Lock()
	c.unknownReleaseObserver = fn
	c.mu.Unlock()
}

// noteAdvertised reports, once per token, a release token a peer advertises
// that this build does not know.
func (c *Checker) noteAdvertised(caps []string) {
	for _, tok := range caps {
		if !strings.HasPrefix(tok, "release_") || corrosion.ReleaseTokenKnown(tok) {
			continue
		}
		c.mu.Lock()
		fn := c.unknownReleaseObserver
		seen := c.unknownReleaseSeen[tok]
		if c.unknownReleaseSeen == nil {
			c.unknownReleaseSeen = map[string]bool{}
		}
		c.unknownReleaseSeen[tok] = true
		c.mu.Unlock()
		if fn != nil && !seen {
			fn(tok)
		}
	}
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
	return write(ctx, capabilities.MintFeatureGrant(feature))
}

// requireFeature is WithFeature's gate (see there).
func (c *Checker) requireFeature(ctx context.Context, feature capabilities.Feature) error {
	info, ok := capabilities.LookupFeature(feature)
	if !ok {
		return status.Errorf(codes.Internal, "release feature %q is not declared by this build", feature)
	}
	tok := info.Token
	refuse := func(why string) error {
		msg := fmt.Sprintf("the cluster upgrade must finish first (%s needs %s)", feature, tok)
		if why != "" {
			msg += ": " + why
		}
		return status.Error(codes.FailedPrecondition, msg)
	}
	if !c.DurablyLatched(tok) {
		// Drive the latch from here too, so the first use after a roll does
		// not wait for the HA monitor's turn.
		c.Enforced(ctx, tok)
		if !c.DurablyLatched(tok) {
			return refuse("not every host this one replicates to runs a build that keeps it yet")
		}
	}

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
// replicates to (and every voter) advertises tok, and returns them, this node
// excluded.
func (c *Checker) releaseRecipients(ctx context.Context, tok string) ([]string, error) {
	if ok, reason := c.CapabilityActive(ctx, tok); !ok {
		return nil, fmt.Errorf("a host this one replicates to does not advertise it now (%s); a host "+
			"rolled back after the upgrade must be upgraded again or removed", reason)
	}
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return nil, fmt.Errorf("read hosts: %v", err)
	}
	var out []string
	for _, h := range c.activationTargets(hosts, tok) {
		if h != c.hostName {
			out = append(out, h)
		}
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
		var still []string
		for _, h := range pending {
			cctx, cancel := context.WithTimeout(ctx, capActivationTimeout)
			held, err := confirm(cctx, h, tok, feature)
			cancel()
			if err != nil || !held {
				still = append(still, h)
			}
		}
		pending = still
		if len(pending) == 0 {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			slog.Warn("release feature: a first use was not acknowledged by every recipient; refusing the write",
				"feature", feature, "token", tok, "unacknowledged", pending)
			return status.Errorf(codes.Unavailable,
				"%s's use is recorded here but not yet acknowledged by %s; the write is refused until every "+
					"host holds the record — retry", feature, strings.Join(pending, ", "))
		}
		select {
		case <-ctx.Done():
		case <-time.After(releaseAckPoll):
		}
	}
}
