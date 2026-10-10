package capabilities

import (
	"slices"
	"testing"
)

// TestHardwareV2Registered proves the hardware_v2 token is registered in both the
// full known-token set (All) and this build's advertised set (Supported), so peers
// see it via Ping.Capabilities and the latch machinery can reference it by name.
func TestHardwareV2Registered(t *testing.T) {
	if HardwareV2 != "hardware_v2" {
		t.Fatalf("HardwareV2 = %q, want %q", HardwareV2, "hardware_v2")
	}
	if !slices.Contains(Supported(), HardwareV2) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), HardwareV2)
	}
	if !slices.Contains(All(), HardwareV2) {
		t.Fatalf("All() = %v, want it to contain %q", All(), HardwareV2)
	}
}

// TestAuditSignatureV1Registered pins the audit_signature_v1 token in both sets.
// Supported() is what peers see via Ping, so the cluster can never latch a token
// missing from it; All() is what health.SetActivationMarker walks to preload the
// durable latch markers and what daemon rollback detection diffs against, so a
// token absent there loses its latch across a restart.
func TestAuditSignatureV1Registered(t *testing.T) {
	if AuditSignatureV1 != "audit_signature_v1" {
		t.Fatalf("AuditSignatureV1 = %q, want %q", AuditSignatureV1, "audit_signature_v1")
	}
	if !slices.Contains(Supported(), AuditSignatureV1) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), AuditSignatureV1)
	}
	if !slices.Contains(All(), AuditSignatureV1) {
		t.Fatalf("All() = %v, want it to contain %q", All(), AuditSignatureV1)
	}
}

func TestCapacityAdmissionV1Registered(t *testing.T) {
	if CapacityAdmissionV1 != "capacity_admission_v1" {
		t.Fatalf("CapacityAdmissionV1 = %q, want %q", CapacityAdmissionV1, "capacity_admission_v1")
	}
	if !slices.Contains(Supported(), CapacityAdmissionV1) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), CapacityAdmissionV1)
	}
	if !slices.Contains(All(), CapacityAdmissionV1) {
		t.Fatalf("All() = %v, want it to contain %q", All(), CapacityAdmissionV1)
	}
}

// TestNetBoxIPAMV1Registered pins the netbox_ipam_v1 token in both sets.
// Supported() is what peers see via Ping, so the cluster can never latch a token
// missing from it; All() is what health.SetActivationMarker walks to preload the
// durable latch markers and what daemon rollback detection diffs against, so a
// token absent there loses its latch across a restart.
func TestNetBoxIPAMV1Registered(t *testing.T) {
	if NetBoxIPAMV1 != "netbox_ipam_v1" {
		t.Fatalf("NetBoxIPAMV1 = %q, want %q", NetBoxIPAMV1, "netbox_ipam_v1")
	}
	if !slices.Contains(Supported(), NetBoxIPAMV1) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), NetBoxIPAMV1)
	}
	if !slices.Contains(All(), NetBoxIPAMV1) {
		t.Fatalf("All() = %v, want it to contain %q", All(), NetBoxIPAMV1)
	}
}

// TestNetBoxMirrorV1Registered pins the netbox_mirror_v1 token in both sets.
//
// Supported() is what peers see via Ping, so a token missing from it can never
// latch and the inventory mirror would stay inert on a correctly configured
// cluster. All() is what health.SetActivationMarker walks to preload the durable
// per-token latch markers, and what the daemon's rollback detection diffs
// against — a token absent THERE latches once and then silently loses the latch
// on the next restart, which for this token means the mirror stops on a node
// reboot and starts again only after the cluster re-negotiates.
func TestNetBoxMirrorV1Registered(t *testing.T) {
	if NetBoxMirrorV1 != "netbox_mirror_v1" {
		t.Fatalf("NetBoxMirrorV1 = %q, want %q", NetBoxMirrorV1, "netbox_mirror_v1")
	}
	if !slices.Contains(Supported(), NetBoxMirrorV1) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), NetBoxMirrorV1)
	}
	if !slices.Contains(All(), NetBoxMirrorV1) {
		t.Fatalf("All() = %v, want it to contain %q", All(), NetBoxMirrorV1)
	}
}

// TestCanonicalRegistryV1Retired pins the retirement of the first canonical
// registry-credential token. It is neither advertised (Supported) nor known as a
// live token (All, which the checker walks to load latches), so no node latches
// or enforces it again. It IS retired, so the rollback preflight still
// recognises the marker a cluster that latched it holds.
func TestCanonicalRegistryV1Retired(t *testing.T) {
	const tok = "canonical_registry_v1"
	if RetiredCanonicalRegistryV1 != tok {
		t.Fatalf("RetiredCanonicalRegistryV1 = %q, want %q: the on-disk marker name is frozen",
			RetiredCanonicalRegistryV1, tok)
	}
	if slices.Contains(Supported(), tok) {
		t.Errorf("Supported() advertises the retired %s", tok)
	}
	if slices.Contains(All(), tok) {
		t.Errorf("All() lists the retired %s, so the checker would load its marker as a live latch", tok)
	}
	if !Retired(tok) || !slices.Contains(RetiredTokens(), tok) {
		t.Errorf("%s is not retired, so its marker would WAL-quarantine an upgraded node", tok)
	}
}

// TestRetiredTokensAreDisjointFromAll: a token is live or retired, never both.
// One in both sets would be loaded as a latch AND reported as ignored.
func TestRetiredTokensAreDisjointFromAll(t *testing.T) {
	for _, tok := range RetiredTokens() {
		if slices.Contains(All(), tok) {
			t.Errorf("%s is both retired and in All()", tok)
		}
	}
}

// TestReleaseTokenRegistered pins the release token's registration. Every one
// of these sets matters: Supported is what peers latch on, All is what the
// checker loads markers for and what the rollback preflight treats as known,
// Mandatory is what the HA monitor drives with no flag, and ReplicationGated is
// what makes a maintenance host on the previous build hold the latch off.
func TestReleaseTokenRegistered(t *testing.T) {
	const tok = "release_2026_11_v1"
	if ReleaseToken != tok || Release202611V1 != tok {
		t.Fatalf("ReleaseToken = %q, Release202611V1 = %q, want %q: the marker name is frozen",
			ReleaseToken, Release202611V1, tok)
	}
	if !slices.Contains(Supported(), tok) {
		t.Errorf("Supported() does not advertise %s, so it can never latch", tok)
	}
	if !slices.Contains(All(), tok) {
		t.Errorf("All() lacks %s, so its latch is lost across a restart and its marker quarantines", tok)
	}
	if !Mandatory(tok) {
		t.Errorf("%s is not mandatory, so nothing drives its latch", tok)
	}
	if !ReplicationGated(tok) {
		t.Errorf("%s is not replication-gated, so it latches across a maintenance host on the old build", tok)
	}
	if Retired(tok) {
		t.Errorf("%s is retired", tok)
	}
}

// TestReleaseTokenMarkerCarriesRollbackRule: the marker is what a LATER build's
// rollback lands on, and the rule has to be on disk for that build to read.
// A token with no rule keeps the historical content byte for byte.
func TestReleaseTokenMarkerCarriesRollbackRule(t *testing.T) {
	if got := string(MarkerContent(ReleaseToken)); got != "1\nrollback: safe_if_unused\n" {
		t.Errorf("MarkerContent(%s) = %q, want the safe_if_unused rule", ReleaseToken, got)
	}
	if got := string(MarkerContent(SplitBrainGateV1)); got != "1\n" {
		t.Errorf("MarkerContent(%s) = %q, want %q", SplitBrainGateV1, got, "1\n")
	}
	for tok := range rollbackRules {
		if !slices.Contains(All(), tok) {
			t.Errorf("rollback rule for %s, which is not a live token", tok)
		}
	}
}

// TestReleaseFeaturesAreWellFormed: a feature's name is written into a
// replicated key ("release_feature/<token>/<feature>"), so a slash or an
// upper-case letter would make two spellings of one feature, and its token must
// be one this build knows.
func TestReleaseFeaturesAreWellFormed(t *testing.T) {
	for _, f := range Features() {
		info, _ := LookupFeature(f)
		if f == "" {
			t.Errorf("an empty feature name is declared")
		}
		for _, r := range string(f) {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
				t.Errorf("feature %q: %q is not a lower-case letter, digit or underscore", f, r)
			}
		}
		if !slices.Contains(All(), info.Token) || RollbackRule(info.Token) != RollbackSafeIfUnused {
			t.Errorf("feature %q gates on %q, which is not a live release token", f, info.Token)
		}
		if info.Description == "" {
			t.Errorf("feature %q has no description for upgrade-status", f)
		}
	}
}

// TestFeatureGrant_OnlyAMintedGrantForTheFeatureChecks: the zero value, and a
// grant for another feature, refuse.
func TestFeatureGrant_OnlyAMintedGrantForTheFeatureChecks(t *testing.T) {
	var zero FeatureGrant
	if zero.Check("widgets") == nil {
		t.Error("the zero FeatureGrant passed Check")
	}
	g := MintFeatureGrant("widgets")
	if err := g.Check("widgets"); err != nil {
		t.Errorf("a grant for widgets: %v", err)
	}
	if g.Check("gadgets") == nil {
		t.Error("a grant for widgets passed Check for gadgets")
	}
}

// TestReleaseTokenRuleIsNotHonouredBelowIt: every build below the first
// release token predates marker rules, so a rollback below it quarantines
// whatever was used — upgrade-status must not say otherwise.
func TestReleaseTokenRuleIsNotHonouredBelowIt(t *testing.T) {
	if RuleHonouredBelow(Release202611V1) {
		t.Errorf("RuleHonouredBelow(%s) = true; the build below it reads no rule", Release202611V1)
	}
	if RuleHonouredBelow(SplitBrainGateV1) {
		t.Errorf("RuleHonouredBelow(%s) = true for a token with no rule", SplitBrainGateV1)
	}
}

// TestHonoured: a (token, feature) pair is honoured only when this build
// declares the feature under that token.
func TestHonoured(t *testing.T) {
	defer OverrideFeaturesForTest(map[Feature]FeatureInfo{"widgets": {Token: ReleaseToken, Description: "w"}})()
	if !Honoured(ReleaseToken, "widgets") {
		t.Error("a declared feature under its token is not honoured")
	}
	if Honoured(ReleaseToken, "gadgets") || Honoured("release_2099_01_v1", "widgets") {
		t.Error("an undeclared pair is honoured")
	}
}
