package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A node that latched a capability token and is then rolled back to a binary
// predating that token has no way to notice.
//
// The durable activation markers are one file per token, and they are loaded by
// iterating capabilities.All() — the token list COMPILED INTO THE RUNNING BINARY —
// and Stat'ing each expected path. Nothing scans the directory. So a rolled-back
// binary has no "latched_hardware_v2" string to look for, never looks, and starts
// clean. There is no cluster-side record either: capabilities travel only in a
// live PingResponse, and no schema column holds them. The schema version is the
// one durable signal, and it is deliberately tolerated so that a schema bump stays
// reversible and a mixed-version rolling upgrade keeps working — so it must not be
// used for this.
//
// The detection therefore has to be the one place that reads the marker DIRECTORY
// rather than the token list: a marker whose token this build has never heard of
// is proof that a newer binary ran here and latched something.

func TestPreflightCapabilityRollback_FlagsAMarkerThisBuildDoesNotKnow(t *testing.T) {
	dir := t.TempDir()
	writeMarker(t, dir, "some_future_token_v9")

	got := preflightCapabilityRollback(dir, noUses)
	if len(got) != 1 || got[0] != "some_future_token_v9" {
		t.Fatalf("preflightCapabilityRollback = %v, want [some_future_token_v9]; without this "+
			"the node rejoins and writes with no record that it ever latched anything", got)
	}
}

// TestPreflightCapabilityRollback_IgnoresKnownTokens is the half that stops this
// from being a self-inflicted outage: every healthy node has markers for the
// tokens it has latched, and treating those as a rollback would quarantine the
// entire fleet.
func TestPreflightCapabilityRollback_IgnoresKnownTokens(t *testing.T) {
	dir := t.TempDir()
	known := capabilities.All()
	if len(known) == 0 {
		t.Fatal("capabilities.All() is empty; this test proves nothing")
	}
	for _, tok := range known {
		writeMarker(t, dir, tok)
	}

	if got := preflightCapabilityRollback(dir, noUses); len(got) != 0 {
		t.Fatalf("preflightCapabilityRollback = %v on a node holding only tokens this build "+
			"knows; a healthy fleet would be quarantined", got)
	}
}

// TestPreflightCapabilityRollback_CleanNodeIsClean covers the ordinary case.
func TestPreflightCapabilityRollback_CleanNodeIsClean(t *testing.T) {
	if got := preflightCapabilityRollback(t.TempDir(), noUses); len(got) != 0 {
		t.Fatalf("preflightCapabilityRollback = %v on a node with no markers at all", got)
	}
}

// TestPreflightCapabilityRollback_ReportsEveryUnknownToken: a rollback across more
// than one release skips more than one token, and the operator needs all of them
// to know what to reseed.
func TestPreflightCapabilityRollback_ReportsEveryUnknownToken(t *testing.T) {
	dir := t.TempDir()
	writeMarker(t, dir, "future_b")
	writeMarker(t, dir, "future_a")
	if len(capabilities.All()) > 0 {
		writeMarker(t, dir, capabilities.All()[0])
	}

	got := preflightCapabilityRollback(dir, noUses)
	if len(got) != 2 || got[0] != "future_a" || got[1] != "future_b" {
		t.Fatalf("preflightCapabilityRollback = %v, want [future_a future_b] sorted", got)
	}
}

// TestPreflightCapabilityRollback_OverrideLetsAnOperatorRecover: the quarantine is
// cleared by an operator who has reseeded, and there must be a way to say so
// without deleting marker files by hand.
func TestPreflightCapabilityRollback_OverrideLetsAnOperatorRecover(t *testing.T) {
	dir := t.TempDir()
	writeMarker(t, dir, "some_future_token_v9")
	t.Setenv("LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK", "1")

	if got := preflightCapabilityRollback(dir, noUses); len(got) != 0 {
		t.Fatalf("preflightCapabilityRollback = %v with the override set", got)
	}
}

// TestPreflightCapabilityRollback_RetiredTokenIsNotARollback: canonical_registry_v1
// shipped in v1.4.0 behind enforcement.canonical_registry and was retired on
// 2026-10-04, before anything wrote the shape it gated. A cluster that opted in
// still holds its durable marker. This build no longer advertises, latches or
// enforces the token, but it must still RECOGNISE the marker: an unknown marker
// reads as "a newer binary ran here", so a node upgrading onto this build would
// start in WAL quarantine and emit nothing — an upgrade mistaken for a rollback.
//
// The literal is deliberate. The test pins the on-disk name an older binary
// wrote, which renaming a Go identifier must not change.
func TestPreflightCapabilityRollback_RetiredTokenIsNotARollback(t *testing.T) {
	dir := t.TempDir()
	const retired = "canonical_registry_v1"
	if err := os.WriteFile(health.ActivationMarkerPath(dir, retired), []byte("1\n"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	if got := preflightCapabilityRollback(dir, noUses); len(got) != 0 {
		t.Fatalf("preflightCapabilityRollback = %v on a node holding the durable marker of the "+
			"retired %s; it would start in WAL quarantine on an UPGRADE", got, retired)
	}

	// A retired marker must not hide a genuine rollback beside it.
	writeMarker(t, dir, "some_future_token_v9")
	if got := preflightCapabilityRollback(dir, noUses); len(got) != 1 || got[0] != "some_future_token_v9" {
		t.Fatalf("preflightCapabilityRollback = %v, want [some_future_token_v9]", got)
	}
}

func writeMarker(t *testing.T, dir, token string) {
	t.Helper()
	path := filepath.Join(dir, "split_brain_activated."+token)
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("write marker %s: %v", path, err)
	}
}

// noUses is a recorded-use reader over a cluster where no release feature has
// ever been used.
func noUses() ([]corrosion.ReleaseFeatureUse, error) { return nil, nil }

const futureRelease = "release_2099_01_v1"

func writeMarkerContent(t *testing.T, dir, token, content string) {
	t.Helper()
	if err := os.WriteFile(health.ActivationMarkerPath(dir, token), []byte(content), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
}

// A LATER release's token, rolled back onto this build. Its marker carries the
// safe_if_unused rule, so this build quarantines only if one of its features
// was used — the whole point of one release token instead of one per feature.
func TestPreflightCapabilityRollback_SafeIfUnusedReleaseTokenUnused(t *testing.T) {
	dir := t.TempDir()
	writeMarkerContent(t, dir, futureRelease, "1\nrollback: safe_if_unused\n")
	q, p := preflightRollback(dir, noUses)
	if len(q) != 0 {
		t.Fatalf("quarantine = %v for a release token none of whose features was "+
			"used; the node would be quarantined for nothing", q)
	}
	// But not trusted either: its own replica may lack a record its peers hold
	// (C1), so it starts in probation until a voter majority has been asked.
	if len(p) != 1 || p[0] != futureRelease {
		t.Fatalf("probation = %v, want [%s]: a replica's own \"nothing used\" is not proof", p, futureRelease)
	}
}

func TestPreflightCapabilityRollback_SafeIfUnusedReleaseTokenUsed(t *testing.T) {
	dir := t.TempDir()
	writeMarkerContent(t, dir, futureRelease, "1\nrollback: safe_if_unused\n")
	uses := func() ([]corrosion.ReleaseFeatureUse, error) {
		return []corrosion.ReleaseFeatureUse{{Token: futureRelease, Feature: "widgets", RecordedBy: "n2"}}, nil
	}
	if got := preflightCapabilityRollback(dir, uses); len(got) != 1 || got[0] != futureRelease {
		t.Fatalf("preflightCapabilityRollback = %v, want [%s]: a feature of it was used, and this "+
			"build would drop its data", got, futureRelease)
	}
}

// A use of a DIFFERENT token says nothing about this one.
func TestPreflightCapabilityRollback_SafeIfUnusedIgnoresOtherTokensUses(t *testing.T) {
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		"widgets": {Token: capabilities.ReleaseToken, Description: "w"},
	}))
	dir := t.TempDir()
	writeMarkerContent(t, dir, futureRelease, "1\nrollback: safe_if_unused\n")
	uses := func() ([]corrosion.ReleaseFeatureUse, error) {
		return []corrosion.ReleaseFeatureUse{{Token: capabilities.ReleaseToken, Feature: "widgets"}}, nil
	}
	if got := preflightCapabilityRollback(dir, uses); len(got) != 0 {
		t.Fatalf("preflightCapabilityRollback = %v; a use of this build's own release token is "+
			"not a use of %s", got, futureRelease)
	}
}

// The used set cannot be read: nothing proves the token unused, so fail closed.
func TestPreflightCapabilityRollback_SafeIfUnusedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeMarkerContent(t, dir, futureRelease, "1\nrollback: safe_if_unused\n")
	broken := func() ([]corrosion.ReleaseFeatureUse, error) { return nil, errors.New("disk on fire") }
	if got := preflightCapabilityRollback(dir, broken); len(got) != 1 || got[0] != futureRelease {
		t.Fatalf("preflightCapabilityRollback = %v with an unreadable used set, want [%s]", got, futureRelease)
	}
	if got := preflightCapabilityRollback(dir, nil); len(got) != 1 || got[0] != futureRelease {
		t.Fatalf("preflightCapabilityRollback = %v with no used-set reader, want [%s]", got, futureRelease)
	}
}

// Only the rule this build understands lifts the quarantine: a marker with no
// rule, or a rule this build has never heard of, keeps today's behaviour.
func TestPreflightCapabilityRollback_OnlyTheKnownRuleLiftsQuarantine(t *testing.T) {
	for name, content := range map[string]string{
		"no rule":      "1\n",
		"unknown rule": "1\nrollback: safe_if_quiet\n",
		"other key":    "1\nnote: safe_if_unused\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeMarkerContent(t, dir, futureRelease, content)
			if got := preflightCapabilityRollback(dir, noUses); len(got) != 1 || got[0] != futureRelease {
				t.Fatalf("preflightCapabilityRollback = %v for marker %q, want [%s]", got, content, futureRelease)
			}
		})
	}
}

// A recorded use of a token this build does not know quarantines even with no
// marker on this node: it latched while this node was away, and its features
// write what this build cannot keep.
func TestPreflightCapabilityRollback_UseOfUnknownTokenWithoutMarker(t *testing.T) {
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		"known": {Token: capabilities.ReleaseToken, Description: "k"},
	}))
	uses := func() ([]corrosion.ReleaseFeatureUse, error) {
		return []corrosion.ReleaseFeatureUse{
			{Token: futureRelease, Feature: "widgets"},
			{Token: futureRelease, Feature: "gadgets"},
			{Token: capabilities.ReleaseToken, Feature: "known"},
		}, nil
	}
	if got := preflightCapabilityRollback(t.TempDir(), uses); len(got) != 1 || got[0] != futureRelease {
		t.Fatalf("preflightCapabilityRollback = %v, want [%s]", got, futureRelease)
	}
}

// TestPreflightCapabilityRollback_ReadsTheReplicatedUsedSet: the same decision
// over the real cluster_policies rows, the reader the daemon wires.
func TestPreflightCapabilityRollback_ReadsTheReplicatedUsedSet(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	dir := t.TempDir()
	writeMarkerContent(t, dir, futureRelease, string(capabilities.MarkerContent(capabilities.ReleaseToken)))
	reader := releaseFeatureUseReader(ctx, db)
	if got := preflightCapabilityRollback(dir, reader); len(got) != 0 {
		t.Fatalf("preflightCapabilityRollback = %v with nothing used", got)
	}
	if err := corrosion.RecordReleaseFeatureUse(ctx, db, futureRelease, "widgets", "n2", false); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	if got := preflightCapabilityRollback(dir, reader); len(got) != 1 || got[0] != futureRelease {
		t.Fatalf("preflightCapabilityRollback = %v after a use, want [%s]", got, futureRelease)
	}
}

// TestPreflightCapabilityRollback_UndeclaredFeatureOfAKnownToken (I3): this
// build knows the release token but not the feature recorded used under it —
// a build from before that feature landed. It cannot keep the data.
func TestPreflightCapabilityRollback_UndeclaredFeatureOfAKnownToken(t *testing.T) {
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		"widgets": {Token: capabilities.ReleaseToken, Description: "w"},
	}))
	uses := func() ([]corrosion.ReleaseFeatureUse, error) {
		return []corrosion.ReleaseFeatureUse{
			{Token: capabilities.ReleaseToken, Feature: "widgets"},
			{Token: capabilities.ReleaseToken, Feature: "email_target_secret"},
		}, nil
	}
	want := capabilities.ReleaseToken + "/email_target_secret"
	if got := preflightCapabilityRollback(t.TempDir(), uses); len(got) != 1 || got[0] != want {
		t.Fatalf("preflightCapabilityRollback = %v, want [%s]", got, want)
	}
}

// TestPreflightRollback_NoProbationWithoutARule: a known token, or an unknown
// one without the rule, never puts a node in probation — the first is fine and
// the second is quarantined outright.
func TestPreflightRollback_NoProbationWithoutARule(t *testing.T) {
	dir := t.TempDir()
	writeMarker(t, dir, capabilities.SplitBrainGateV1)
	writeMarker(t, dir, "some_future_token_v9")
	q, p := preflightRollback(dir, noUses)
	if len(p) != 0 || len(q) != 1 {
		t.Fatalf("quarantine=%v probation=%v, want one quarantined token and no probation", q, p)
	}
	// A used safe_if_unused token is quarantined, not in probation.
	writeMarkerContent(t, dir, futureRelease, "1\nrollback: safe_if_unused\n")
	usedFuture := func() ([]corrosion.ReleaseFeatureUse, error) {
		return []corrosion.ReleaseFeatureUse{{Token: futureRelease, Feature: "widgets"}}, nil
	}
	if _, p := preflightRollback(dir, usedFuture); len(p) != 0 {
		t.Fatalf("probation = %v for a token already shown used", p)
	}
}
