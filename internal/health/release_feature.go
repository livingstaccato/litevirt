package health

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// RequireFeature is the one gate a release feature's write goes through
// (capabilities.Feature). Call it immediately before the write the feature's
// data needs; write only if it returns nil.
//
// It refuses with FailedPrecondition — "the cluster upgrade must finish first
// (<feature> needs <token>)" — until the feature's release token has DURABLY
// latched here. Once it has, the feature's first use is RECORDED, replicated,
// before this returns nil:
//
//   - The record is a cluster_policies row (corrosion.RecordReleaseFeatureUse),
//     committed with its mutation-log entry, so it is on this node's ordered
//     replication stream ahead of the caller's write. A node rolled back onto
//     an older build that knows the release-token rule applies the record
//     before the data, and the record quarantines it.
//   - A first use re-confirms, from fresh Pings, that every host this node
//     replicates to still advertises the token. The latch is monotone, so a
//     host rolled back after it formed does not unlatch it, and that host may
//     have started unquarantined because nothing was used yet. While it runs,
//     no feature may be used for the first time.
//   - If the record cannot be written — the policy table is gated, the node is
//     WAL-quarantined, the disk failed — it refuses. A write with no record
//     would let a rollback believe the feature unused and keep running over
//     data it drops.
//
// A use already recorded (on any node; the row replicates) passes with one
// local read, then from memory. A feature outside the declared set is refused
// with Internal: the set is closed, and an undeclared name is a programming
// error, not an operator one.
func (c *Checker) RequireFeature(ctx context.Context, feature capabilities.Feature) error {
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
	used, err := corrosion.ReleaseFeatureUsed(ctx, c.db, tok, string(feature))
	if err != nil {
		return status.Errorf(codes.Unavailable, "read whether %s is in use: %v", feature, err)
	}
	if !used {
		if ok, reason := c.CapabilityActive(ctx, tok); !ok {
			return refuse("a host this one replicates to does not advertise it now (" + reason +
				"); a host rolled back after the upgrade must be upgraded again or removed")
		}
		if err := corrosion.RecordReleaseFeatureUse(ctx, c.db, tok, string(feature), c.hostName); err != nil {
			if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
				return refuse("the cluster policy table is not writable yet")
			}
			return status.Errorf(codes.Unavailable,
				"could not record that %s is in use, so the write is refused: %v", feature, err)
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
