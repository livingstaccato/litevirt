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

// TestFirewallIPv6V1Retired pins the retirement of the tenant-firewall
// branch's own token. A build of that branch advertised it on a lab cluster,
// so a node there may hold its marker: it must stay recognised (retired), and
// never be advertised, loaded as a latch, or reused. IPv6 rules and NIC
// guards are release features now (firewall_ipv6, nic_guards).
func TestFirewallIPv6V1Retired(t *testing.T) {
	const tok = "firewall_ipv6_v1"
	if RetiredFirewallIPv6V1 != tok {
		t.Fatalf("RetiredFirewallIPv6V1 = %q, want %q: the on-disk marker name is frozen", RetiredFirewallIPv6V1, tok)
	}
	if slices.Contains(Supported(), tok) || Mandatory(tok) || ReplicationGated(tok) {
		t.Errorf("the retired %s is still advertised, mandatory or replication-gated", tok)
	}
	if slices.Contains(All(), tok) {
		t.Errorf("All() lists the retired %s, so the checker would load its marker as a live latch", tok)
	}
	if !Retired(tok) || !slices.Contains(RetiredTokens(), tok) {
		t.Errorf("%s is not retired, so its marker would WAL-quarantine an upgraded lab node", tok)
	}
	for _, f := range []Feature{FeatureFirewallIPv6, FeatureNICGuards} {
		if !Honoured(ReleaseToken, f) {
			t.Errorf("%s is not a feature of %s", f, ReleaseToken)
		}
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

// TestRelayHealthV1Registered pins relay_health_v1 (colonelpanik/litevirt#175):
// advertised, known, mandatory (a fact about the binary — it reads the relay
// demotion rows) and replication-gated (every recipient elects relays from
// what it receives, so every recipient must read them).
func TestRelayHealthV1Registered(t *testing.T) {
	if RelayHealthV1 != "relay_health_v1" {
		t.Fatalf("RelayHealthV1 = %q, want %q", RelayHealthV1, "relay_health_v1")
	}
	if !slices.Contains(Supported(), RelayHealthV1) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), RelayHealthV1)
	}
	if !slices.Contains(All(), RelayHealthV1) {
		t.Fatalf("All() = %v, want it to contain %q", All(), RelayHealthV1)
	}
	if !Mandatory(RelayHealthV1) {
		t.Fatal("relay_health_v1 must be mandatory: a flag would let one node elect a different relay set")
	}
	if !ReplicationGated(RelayHealthV1) {
		t.Fatal("relay_health_v1 must be replication-gated: every replication recipient elects relays")
	}
}

// TestVRRPUnicastV1Registered: advertised (the grpcapi filter withholds it
// while enforcement.vrrp_unicast is off), known, flag-gated rather than
// mandatory, and confirmed against every replication recipient.
func TestVRRPUnicastV1Registered(t *testing.T) {
	if VRRPUnicastV1 != "vrrp_unicast_v1" {
		t.Fatalf("VRRPUnicastV1 = %q, want %q", VRRPUnicastV1, "vrrp_unicast_v1")
	}
	if !slices.Contains(Supported(), VRRPUnicastV1) || !slices.Contains(All(), VRRPUnicastV1) {
		t.Fatalf("vrrp_unicast_v1 missing from Supported() or All()")
	}
	if Mandatory(VRRPUnicastV1) {
		t.Fatal("vrrp_unicast_v1 has a kill switch (enforcement.vrrp_unicast); it is not mandatory")
	}
	if !ReplicationGated(VRRPUnicastV1) {
		t.Fatal("vrrp_unicast_v1 must wait for every replication recipient: a maintenance host may run an LB")
	}
}

// TestSpecConflictV1Registered pins spec_conflict_v1: advertised, known,
// mandatory (a fact about the binary — how it resolves two edits of one spec
// at one generation) and replication-gated (every recipient decodes the
// epoch-carrying edit and resolves as the rest do).
func TestSpecConflictV1Registered(t *testing.T) {
	if SpecConflictV1 != "spec_conflict_v1" {
		t.Fatalf("SpecConflictV1 = %q, want %q", SpecConflictV1, "spec_conflict_v1")
	}
	if !slices.Contains(Supported(), SpecConflictV1) {
		t.Fatalf("Supported() = %v, want it to contain %q", Supported(), SpecConflictV1)
	}
	if !slices.Contains(All(), SpecConflictV1) {
		t.Fatalf("All() = %v, want it to contain %q", All(), SpecConflictV1)
	}
	if !Mandatory(SpecConflictV1) {
		t.Fatal("spec_conflict_v1 must be mandatory: a flag would let one node keep a different version of a spec")
	}
	if !ReplicationGated(SpecConflictV1) {
		t.Fatal("spec_conflict_v1 must be replication-gated: every recipient decodes the epoch-carrying edit")
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
	g := mintGrant("widgets")
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

// TestGrantMinter_ClaimedOnce: the gate claims the only minter at init; a
// second claimant — any other package trying to mint grants — panics.
func TestGrantMinter_ClaimedOnce(t *testing.T) {
	grantMinterClaimed.Store(false)
	t.Cleanup(func() { grantMinterClaimed.Store(false) })
	mint := ClaimGrantMinter()
	if mint("widgets").Check("widgets") != nil {
		t.Fatal("the claimed minter's grant does not check")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a second ClaimGrantMinter did not panic")
		}
	}()
	_ = ClaimGrantMinter()
}

// frozenReleaseFeatures pins, per release token, the exact feature set the
// release ships with. A TOKEN'S FEATURE SET IS FROZEN WHEN ITS RELEASE SHIPS
// (releaseFeatures): a build that knows the token but not one of its features
// cannot keep that feature's data, and it advertises the token, is counted
// toward its latch and is accepted as a sender all the same — so a feature added
// to a shipped token turns every host on the shipped build into one that acks a
// first use and then WAL-quarantines itself. A feature added later is declared
// under the NEXT release token, whose list is pinned here as a new entry.
//
// Editing an existing entry is a release-engineering decision, not a code
// change: it is only ever right before that release has shipped, as one
// reviewed change to releaseFeatures and to this pin together.
// (release_2026_11_v1 gained nic_guards and redfish_fence that way, and later
// ha_disarm, nic_mtu and replication_rate, and then firewall_synflood, firewall_log
// and firewall_tag_groups, and then host_incarnation, and then automation_stream
// and sg_projects, before it shipped.)
var frozenReleaseFeatures = map[string][]Feature{
	Release202611V1: {
		"automation_stream",
		"backup_zstd",
		"container_replication",
		"drain_failback",
		"email_target_secret",
		"firewall_ipv6",
		"firewall_log",
		"firewall_synflood",
		"firewall_tag_groups",
		"ha_disarm",
		"host_incarnation",
		"iscsi_lun_claim",
		"login_policy",
		"nic_guards",
		"nic_mtu",
		"pit_overlay",
		"redfish_fence",
		"replication_rate",
		"returning_boot",
		"sg_projects",
		"usb_mounts_memory",
		"vm_disk_nic_io",
		"vm_limits",
	},
	// Not shipped yet: corrected only by one reviewed change here and in
	// releaseFeatures together.
	Release202612V1: {
		"fence_ssh",
	},
	Release202702V1: {"automation_identity_continuity"},
}

// TestReleaseFeatureSetIsFrozen (m6): every release token's declared features
// are exactly its pinned list, and every release token has one.
func TestReleaseFeatureSetIsFrozen(t *testing.T) {
	byToken := map[string][]Feature{}
	for _, f := range Features() {
		info, _ := LookupFeature(f)
		byToken[info.Token] = append(byToken[info.Token], f)
	}
	for _, tok := range ReleaseTokens() {
		if _, ok := frozenReleaseFeatures[tok]; !ok {
			t.Errorf("release token %s has no pinned feature list in frozenReleaseFeatures", tok)
		}
	}
	for tok, want := range frozenReleaseFeatures {
		got := byToken[tok]
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("features declared under %s = %v, want exactly %v: a shipped release token's feature "+
				"set is frozen; declare a new feature under the next release token", tok, got, want)
		}
	}
	for tok := range byToken {
		if _, ok := frozenReleaseFeatures[tok]; !ok {
			t.Errorf("features are declared under %s, which has no pinned list", tok)
		}
	}
}

// TestUserIncarnationV1Registered pins user_incarnation_v1: advertised,
// known, mandatory and replication-gated.
func TestUserIncarnationV1Registered(t *testing.T) {
	if UserIncarnationV1 != "user_incarnation_v1" {
		t.Fatalf("UserIncarnationV1 = %q", UserIncarnationV1)
	}
	if !slices.Contains(Supported(), UserIncarnationV1) || !slices.Contains(All(), UserIncarnationV1) {
		t.Fatal("user_incarnation_v1 must be advertised and known")
	}
	if !Mandatory(UserIncarnationV1) {
		t.Fatal("user_incarnation_v1 must be mandatory: it states how this build orders a delete and a re-create")
	}
	if !ReplicationGated(UserIncarnationV1) {
		t.Fatal("user_incarnation_v1 must be replication-gated: every recipient must decode its statements and keep the tombstone")
	}
}

// TestProjectIncarnationV1Registered pins project_incarnation_v1: advertised,
// known, mandatory and replication-gated.
func TestProjectIncarnationV1Registered(t *testing.T) {
	if ProjectIncarnationV1 != "project_incarnation_v1" {
		t.Fatalf("ProjectIncarnationV1 = %q", ProjectIncarnationV1)
	}
	if !slices.Contains(Supported(), ProjectIncarnationV1) || !slices.Contains(All(), ProjectIncarnationV1) {
		t.Fatal("project_incarnation_v1 must be advertised and known")
	}
	if !Mandatory(ProjectIncarnationV1) {
		t.Fatal("project_incarnation_v1 must be mandatory: it states which bindings this build lets grant on a re-created project")
	}
	if !ReplicationGated(ProjectIncarnationV1) {
		t.Fatal("project_incarnation_v1 must be replication-gated: every recipient must decode its statements and guard")
	}
}

// TestNetBoxIPRepointV1Registered pins netbox_ip_repoint_v1: advertised,
// known, mandatory (a fact about the binary — it decodes the lease re-point
// statement) and replication-gated (that statement is a shape a
// previous-release recipient has no ledger entry for).
func TestNetBoxIPRepointV1Registered(t *testing.T) {
	if NetBoxIPRepointV1 != "netbox_ip_repoint_v1" {
		t.Fatalf("NetBoxIPRepointV1 = %q", NetBoxIPRepointV1)
	}
	if !slices.Contains(Supported(), NetBoxIPRepointV1) || !slices.Contains(All(), NetBoxIPRepointV1) {
		t.Fatal("netbox_ip_repoint_v1 must be advertised and known")
	}
	if !Mandatory(NetBoxIPRepointV1) {
		t.Fatal("netbox_ip_repoint_v1 must be mandatory: it states what this build decodes")
	}
	if !ReplicationGated(NetBoxIPRepointV1) {
		t.Fatal("netbox_ip_repoint_v1 must be replication-gated: every recipient must decode the re-point")
	}
}

// TestNextReleaseTokenRegistered pins release_2026_12_v1's registration, as
// TestReleaseTokenRegistered pins release_2026_11_v1's, and that a rollback
// below it lands on a build that reads its marker's rule.
func TestNextReleaseTokenRegistered(t *testing.T) {
	const tok = "release_2026_12_v1"
	if Release202612V1 != tok {
		t.Fatalf("Release202612V1 = %q, want %q: the marker name is frozen", Release202612V1, tok)
	}
	if !slices.Contains(Supported(), tok) || !slices.Contains(All(), tok) || !Mandatory(tok) || !ReplicationGated(tok) {
		t.Fatalf("%s: supported=%v all=%v mandatory=%v replicationGated=%v; want all true", tok,
			slices.Contains(Supported(), tok), slices.Contains(All(), tok), Mandatory(tok), ReplicationGated(tok))
	}
	if RollbackRule(tok) != RollbackSafeIfUnused || !slices.Contains(ReleaseTokens(), tok) {
		t.Fatalf("%s: rollback rule %q, release tokens %v", tok, RollbackRule(tok), ReleaseTokens())
	}
	if !RuleHonouredBelow(tok) {
		t.Errorf("RuleHonouredBelow(%s) = false; the build below it is a release-token build", tok)
	}
	if info, ok := LookupFeature(FeatureFenceSSH); !ok || info.Token != tok {
		t.Errorf("fence_ssh is declared under %q, want %s", info.Token, tok)
	}
}
