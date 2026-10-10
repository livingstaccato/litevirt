package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
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
// health.Checker.WithFeature, which records a feature's use, and waits for every
// replication recipient to hold the record, before the feature writes anything.
// An unknown token whose marker says safe_if_unused, and for which uses() holds
// no recorded use, is not quarantined — but not trusted either: this replica's
// "nothing used" is not proof, so the node starts in release PROBATION
// (preflightRollback), emitting nothing until a voter majority has been asked.
// Anything else quarantines: no rule, a rule this build does not know, a
// recorded use, or a used set that cannot be read (nil uses included — nothing
// then proves the token unused).
//
// A recorded use this build cannot honour — an unknown token, or a feature it
// does not declare under a token it knows — quarantines with or without a marker: the token latched while this node was away, and its
// features write what this build cannot keep. A use that arrives AFTER startup
// trips the same quarantine at the replication apply (corrosion
// release_features.go).
//
// Builds older than the release token's own build read no rule: they still
// quarantine on every marker they do not know, used or not. That cannot be
// fixed from here.
func preflightCapabilityRollback(dataDir string, uses func() ([]corrosion.ReleaseFeatureUse, error)) []string {
	q, _ := preflightRollback(dataDir, uses)
	return q
}

// preflightRollback is preflightCapabilityRollback with the second answer the
// safe_if_unused rule needs: the tokens whose marker passed it only on this
// replica's word. Those are a PROBATION, not a pass (C1): this replica may lack
// a record its peers hold, so the node emits nothing until a voter majority
// has been asked (corrosion.AntiEntropy.VerifyReleaseProbation).
func preflightRollback(dataDir string, uses func() ([]corrosion.ReleaseFeatureUse, error)) (quarantine, probation []string) {
	if os.Getenv("LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK") == "1" {
		slog.Warn("preflight: capability-rollback detection disabled by " +
			"LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK=1; this node will emit replicated writes " +
			"even if it is a rollback below a token it already latched")
		return nil, nil
	}
	if dataDir == "" {
		return nil, nil
	}
	latched, err := health.ActivationMarkersOnDisk(dataDir)
	if err != nil {
		// The only error Glob returns is a malformed pattern, which ours is not.
		// Log rather than fail: an unreadable data dir is its own problem and the
		// daemon will hit it again immediately.
		slog.Warn("preflight: could not scan capability activation markers", "error", err)
		return nil, nil
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
			for _, f := range feats {
				// An unknown token, or a feature this build does not declare
				// under a token it knows (I3): either way it cannot keep the data.
				if name := corrosion.UnhonouredUse(token, f); name != "" && !unknown[name] {
					slog.Error("preflight: a feature this build cannot keep the data of is in use",
						"capability", token, "feature", f)
					unknown[name] = true
				}
			}
		}
	} else if uses != nil && !isNoSuchTable(err) {
		// The used set exists to be read; a read failure with no marker to
		// decide on is logged, and the runtime check at apply still holds.
		slog.Warn("preflight: could not read the recorded release-feature uses", "error", err)
	}
	for _, token := range safeIfUnused {
		if !unknown[token] && probationLiftConfirmed(dataDir, token) {
			slog.Info("preflight: a voter majority already confirmed no feature of this release token is "+
				"in use; not entering release probation again", "capability", token)
			continue
		}
		if !unknown[token] {
			slog.Warn("preflight: this binary predates a latched release token none of whose "+
				"features is recorded used here; entering release probation (rollback: "+
				"safe_if_unused) until a voter majority confirms it",
				"capability", token)
			probation = append(probation, token)
		}
	}
	for tok := range unknown {
		quarantine = append(quarantine, tok)
	}
	sort.Strings(quarantine)
	sort.Strings(probation)
	return quarantine, probation
}

// isNoSuchTable reports a read before the schema exists (a brand-new node).
func isNoSuchTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}

// releaseFeatureUseReader reads the recorded release-feature uses from db.
func releaseFeatureUseReader(ctx context.Context, db *corrosion.Client) func() ([]corrosion.ReleaseFeatureUse, error) {
	return func() ([]corrosion.ReleaseFeatureUse, error) { return corrosion.ListReleaseFeatureUses(ctx, db) }
}

// probationLiftPrefix is the basename prefix of the record that a release
// probation below token was confirmed and lifted: <data_dir>/<prefix>.<token>,
// holding the sha256 of the token's activation marker at that time.
const probationLiftPrefix = "release_probation_lifted"

func probationLiftPath(dataDir, token string) string {
	return filepath.Join(dataDir, probationLiftPrefix+"."+token)
}

// markerDigest is the sha256 of token's activation marker, or "" if unreadable.
func markerDigest(dataDir, token string) string {
	b, err := os.ReadFile(health.ActivationMarkerPath(dataDir, token))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// persistProbationLift records that a voter majority confirmed no use of
// tokens, bound to each token's current marker (C-R2-1). A later boot below
// the same marker does not re-enter probation — a cluster-wide restart would
// otherwise put every voter back in it at once. A use that arrives later still
// quarantines (at the apply, and at the next boot's preflight), and a
// different marker — a later rollback — is checked afresh.
func persistProbationLift(dataDir string, tokens []string) error {
	if dataDir == "" {
		return nil
	}
	for _, tok := range tokens {
		d := markerDigest(dataDir, tok)
		if d == "" {
			continue
		}
		if err := os.WriteFile(probationLiftPath(dataDir, tok), []byte(d+"\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// probationLiftConfirmed reports whether a lift was recorded for token's
// current marker.
func probationLiftConfirmed(dataDir, token string) bool {
	b, err := os.ReadFile(probationLiftPath(dataDir, token))
	if err != nil {
		return false
	}
	d := markerDigest(dataDir, token)
	return d != "" && strings.TrimSpace(string(b)) == d
}
