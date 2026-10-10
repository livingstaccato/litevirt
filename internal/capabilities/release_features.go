package capabilities

import (
	"errors"
	"fmt"
	"sort"
)

// Release features: the closed set of features a release token opens, and the
// rollback rule its activation marker carries.
//
// A release used to add one mandatory, ReplicationGated token per feature, each
// claiming only "this build keeps the new fields". Every such token is a marker
// a rolled-back binary does not know, so a rollback quarantined the node whether
// or not anyone had used the feature. One release token plus a per-feature USED
// bit keeps the claim and makes the rollback cost proportional to use: a
// rolled-back node quarantines only for a feature that was actually used.
//
// HOW A FEATURE IS OPENED. Declare it below (a constant and a releaseFeatures
// entry with a one-line description). Run every write of the feature's data
// through health.Checker.WithFeature(ctx, feature, write) — on a gRPC handler,
// grpcapi.Server.WithReleaseFeature — on the node that performs the write, and
// have the writer take the FeatureGrant it is handed and Check it. The gate
// refuses with FailedPrecondition until the release token has durably latched;
// before a first use's write it records the use and waits until every
// replication recipient holds the record; and every writing node puts its own
// record on its own stream first. Never gate on Latched/Enforced(ReleaseToken):
// that leaves no used bit, and a rolled-back node would keep running over data
// it drops. release_guard_test.go fails the build on it.

// Feature names one feature of a release. Its string is written into a
// replicated cluster_policies key and so is frozen once it ships: lower-case
// letters, digits and underscores only.
type Feature string

// FeatureInfo is a declared feature's release token and its one-line
// description, the line `lv cluster upgrade-status` prints.
type FeatureInfo struct {
	Token       string
	Description string
}

// releaseFeatures is THE closed set of release features this build knows,
// keyed by name. Empty at the release's start; each feature branch adds its
// own entry beside its constant. A feature never moves to another token: a
// used bit is recorded under the token its feature was declared with.
//
// A TOKEN'S FEATURE SET IS FROZEN WHEN ITS RELEASE SHIPS. A build that knows a
// token but not one of its features cannot keep that feature's data, so a used
// record for an undeclared (token, feature) pair quarantines it exactly as an
// unknown token does (corrosion release_features.go, the rollback preflight). A
// feature added after the release — in a patch release, say — gets the NEXT
// release token, never this one: under this one, every build of the release
// that lacks it would quarantine on its first use, and every build before the
// feature landed on main would too.
var releaseFeatures = map[Feature]FeatureInfo{}

// LookupFeature returns a declared feature's token and description.
func LookupFeature(f Feature) (FeatureInfo, bool) {
	info, ok := releaseFeatures[f]
	return info, ok
}

// Features lists every declared feature, sorted by name.
func Features() []Feature {
	out := make([]Feature, 0, len(releaseFeatures))
	for f := range releaseFeatures {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// OverrideFeaturesForTest replaces the declared set for the duration of a test
// and returns the function that restores it. Tests only: the set is closed in
// production, and nothing outside a _test.go file may call this.
func OverrideFeaturesForTest(set map[Feature]FeatureInfo) (restore func()) {
	prev := releaseFeatures
	releaseFeatures = set
	return func() { releaseFeatures = prev }
}

// RollbackSafeIfUnused is the activation-marker rollback rule of a release
// token: a binary that does not know the token may skip WAL quarantine for it
// when no feature of the token has been recorded as used.
const RollbackSafeIfUnused = "safe_if_unused"

// MarkerRollbackKey is the key of the rollback rule line in an activation
// marker ("rollback: safe_if_unused").
const MarkerRollbackKey = "rollback"

// rollbackRules is every token whose activation marker carries a rollback rule.
// Only release tokens belong here: the rule is sound only for a token whose
// every effect is behind WithFeature, so that "no feature used" means
// "nothing written that a previous build cannot keep".
var rollbackRules = map[string]string{
	Release202611V1: RollbackSafeIfUnused,
}

// RollbackRule returns the rollback rule token's marker carries, or "".
func RollbackRule(token string) string {
	return rollbackRules[token]
}

// MarkerContent is what a token's durable activation marker holds. A token
// with no rule keeps the historical "1\n". A rule rides on a second line, so
// an older binary — which only Stats a marker — reads it the same way.
func MarkerContent(token string) []byte {
	if rule := RollbackRule(token); rule != "" {
		return []byte("1\n" + MarkerRollbackKey + ": " + rule + "\n")
	}
	return []byte("1\n")
}

// Honoured reports whether this build keeps the data of feature under token:
// it declares the feature, under that token.
func Honoured(token string, feature Feature) bool {
	info, ok := releaseFeatures[feature]
	return ok && info.Token == token
}

// ruleAwareBelow records, per token with a rollback rule, whether the build
// directly below it — the one a rollback below the token lands on — reads
// marker rules at all. False for the first release token: every build before
// it quarantines on any marker it does not know, rule or not. A later release
// token's entry is true, because the build below it is a release-token build.
var ruleAwareBelow = map[string]bool{
	Release202611V1: false,
}

// RuleHonouredBelow reports whether a rollback below token lands on a build
// that reads its marker's rollback rule. False for any token without a rule.
func RuleHonouredBelow(token string) bool {
	return RollbackRule(token) != "" && ruleAwareBelow[token]
}

// FeatureGrant is the proof that a release feature's gate passed on THIS node
// in this process: the feature's release token has durably latched, and the
// feature's use is recorded, replicated and on this node's own outgoing stream.
// A writer of a feature's data takes one and calls Check before it writes.
//
// The zero value grants nothing. Only health.Checker.WithFeature mints one
// (MintFeatureGrant), which the release-feature guard
// (internal/capabilities/release_guard_test.go) enforces: a grant obtained any
// other way would let a write skip the used bit a rollback relies on.
type FeatureGrant struct {
	feature Feature
	minted  bool
}

// ErrNoFeatureGrant is returned by FeatureGrant.Check for a grant that does not
// cover the feature asked about.
var ErrNoFeatureGrant = errors.New("release feature write without a grant from its gate")

// Check returns nil only for a grant minted for exactly f.
func (g FeatureGrant) Check(f Feature) error {
	if !g.minted || g.feature != f {
		return fmt.Errorf("%w: %s", ErrNoFeatureGrant, f)
	}
	return nil
}

// Feature is the feature g was minted for ("" for the zero value).
func (g FeatureGrant) Feature() Feature { return g.feature }

// MintFeatureGrant mints a grant for f. ONLY health.Checker.WithFeature may
// call it, after the gate has passed; the release-feature guard fails the
// build for any other caller.
func MintFeatureGrant(f Feature) FeatureGrant {
	return FeatureGrant{feature: f, minted: true}
}
