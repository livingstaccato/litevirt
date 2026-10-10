package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// preflightCapabilityRollback reports the capability tokens this node has already
// latched that THIS BINARY has never heard of — that is, evidence that a newer
// binary ran here and this one is a rollback below it. An empty result means the
// node is clean.
//
// This is the only place in the codebase that reads the marker DIRECTORY instead
// of iterating the token list. Everywhere else does the opposite, and that
// asymmetry is the whole bug: Checker.SetActivationMarker loads markers by
// walking capabilities.All() and Stat'ing each expected path, so a binary
// predating token X has no "X" string to look for, never looks, and starts as if
// nothing were ever latched. There is no cluster-side record to fall back on
// either — capabilities are only ever carried in a live PingResponse and no
// schema column holds them.
//
// It deliberately does NOT key on schema version. A DB forward of the binary is
// explicitly tolerated (schema.go), because that tolerance is what keeps a schema
// bump reversible and a mixed-version rolling upgrade legal. Gating on it would
// break the upgrade path this is supposed to protect.
//
// Note the shape of the guarantee: this only fires on a rollback to a build that
// CONTAINS this check. It cannot retroactively catch a rollback to an already
// released binary. Shipping it is what makes the next rollback detectable, which
// is the OnFailure-auto-rollback path that motivated it.
//
// RELEASE TOKENS. A marker may carry a rollback rule (capabilities.MarkerContent).
// The one rule this build honours is `rollback: safe_if_unused`, which a release
// token's marker carries: every effect of a release token is behind
// health.Checker.RequireFeature, which records a feature's use in a replicated
// row before the feature writes anything. So an unknown token whose marker says
// safe_if_unused, and for which uses() holds no recorded use, wrote nothing this
// build could drop, and does not quarantine. Anything else does: no rule, a
// rule this build does not know, a recorded use, or a used set that cannot be
// read (nil uses included — nothing then proves the token unused).
//
// A recorded use of a token this build does not know quarantines with or
// without a marker: the token latched while this node was away, and its
// features write what this build cannot keep. A use that arrives AFTER startup
// trips the same quarantine at the replication apply (corrosion
// release_features.go).
//
// Builds older than the release token's own build read no rule: they still
// quarantine on every marker they do not know, used or not. That cannot be
// fixed from here.
func preflightCapabilityRollback(dataDir string, uses func() ([]corrosion.ReleaseFeatureUse, error)) []string {
	if os.Getenv("LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK") == "1" {
		slog.Warn("preflight: capability-rollback detection disabled by " +
			"LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK=1; this node will emit replicated writes " +
			"even if it is a rollback below a token it already latched")
		return nil
	}
	if dataDir == "" {
		return nil
	}
	latched, err := health.ActivationMarkersOnDisk(dataDir)
	if err != nil {
		// The only error Glob returns is a malformed pattern, which ours is not.
		// Log rather than fail: an unreadable data dir is its own problem and the
		// daemon will hit it again immediately.
		slog.Warn("preflight: could not scan capability activation markers", "error", err)
		return nil
	}
	// The used set is read at most once, and only when something needs it.
	var (
		used     map[string][]string
		usedErr  error
		usedRead bool
	)
	readUses := func() (map[string][]string, error) {
		if usedRead {
			return used, usedErr
		}
		usedRead = true
		if uses == nil {
			usedErr = errors.New("no reader for the recorded release-feature uses")
			return nil, usedErr
		}
		list, err := uses()
		if err != nil {
			usedErr = err
			return nil, err
		}
		used = map[string][]string{}
		for _, u := range list {
			used[u.Token] = append(used[u.Token], u.Feature)
		}
		return used, nil
	}

	unknown := map[string]bool{}
	var safeIfUnused []string
	for _, token := range latched {
		if corrosion.ReleaseTokenKnown(token) {
			// A retired token's marker was written by an OLDER binary, so it is
			// the opposite of rollback evidence. This build ignores the latch.
			if capabilities.Retired(token) {
				slog.Info("preflight: ignoring the activation marker of a retired capability token",
					"capability", token)
			}
			continue
		}
		rule, rerr := health.ActivationMarkerRollbackRule(dataDir, token)
		if rerr != nil || rule != capabilities.RollbackSafeIfUnused {
			unknown[token] = true
			continue
		}
		// Whether any of its features is used is decided below, with every
		// other token's; here only that the used set CAN be read.
		if _, err := readUses(); err != nil {
			slog.Error("preflight: cannot read which release features are in use, so a "+
				"safe_if_unused token cannot be shown unused; quarantining",
				"capability", token, "error", err)
			unknown[token] = true
			continue
		}
		safeIfUnused = append(safeIfUnused, token)
	}
	// A recorded use of a token this build does not know quarantines, marker
	// or not — a safe_if_unused marker included.
	if u, err := readUses(); err == nil {
		for token, feats := range u {
			if !unknown[token] && !corrosion.ReleaseTokenKnown(token) {
				slog.Error("preflight: features of a release this build does not know are in use",
					"capability", token, "features", feats)
				unknown[token] = true
			}
		}
	} else if uses != nil && !isNoSuchTable(err) {
		// The used set exists to be read; a read failure with no marker to
		// decide on is logged, and the runtime check at apply still holds.
		slog.Warn("preflight: could not read the recorded release-feature uses", "error", err)
	}
	for _, token := range safeIfUnused {
		if !unknown[token] {
			slog.Warn("preflight: this binary predates a latched release token none of whose "+
				"features has been used; not quarantining (rollback: safe_if_unused). Its peers "+
				"refuse every first use of its features while this node runs",
				"capability", token)
		}
	}
	out := make([]string, 0, len(unknown))
	for tok := range unknown {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// isNoSuchTable reports a read before the schema exists (a brand-new node).
func isNoSuchTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}

// releaseFeatureUseReader reads the recorded release-feature uses from db.
func releaseFeatureUseReader(ctx context.Context, db *corrosion.Client) func() ([]corrosion.ReleaseFeatureUse, error) {
	return func() ([]corrosion.ReleaseFeatureUse, error) { return corrosion.ListReleaseFeatureUses(ctx, db) }
}
