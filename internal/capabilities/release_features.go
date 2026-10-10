package capabilities

import "sort"

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
// entry with a one-line description), then call
// health.Checker.RequireFeature(ctx, feature) — on a gRPC handler,
// grpcapi.Server.RequireReleaseFeature — immediately before the write the
// feature's data needs. It refuses with FailedPrecondition until the release
// token has durably latched; on the feature's first use it records the use,
// replicated, BEFORE returning nil, and refuses the write if it cannot. Never
// gate on Latched/Enforced(ReleaseToken) alone: that leaves no used bit, and a
// rolled-back node would keep running over data it drops.

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
// every effect is behind RequireFeature, so that "no feature used" means
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
