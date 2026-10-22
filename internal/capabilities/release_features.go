package capabilities

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync/atomic"
	"testing"
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
	// Writers names every function that writes the feature's data, as
	// "<package dir>.<Func>" or "<package dir>.<Type>.<Method>" (for example
	// "internal/corrosion.UpdateVMLimits"). Each must take a FeatureGrant;
	// release_guard_test.go checks it.
	Writers []string
}

// releaseFeatures is THE closed set of release features this build knows,
// keyed by name. A feature never moves to another token: a used bit is
// recorded under the token its feature was declared with.
//
// A TOKEN'S FEATURE SET IS FROZEN WHEN ITS RELEASE SHIPS. A build that knows a
// token but not one of its features cannot keep that feature's data, so a used
// record for an undeclared (token, feature) pair quarantines it exactly as an
// unknown token does (corrosion release_features.go, the rollback preflight). A
// feature added after the release — in a patch release, say — gets the NEXT
// release token, never this one: under this one, every build of the release
// that lacks it would quarantine on its first use, and every build before the
// feature landed on main would too. Worse, the latch, a push's declaration and
// a peer's advertisement are all per TOKEN: a build that knows the token but
// not the feature is counted toward the latch and accepted as a sender, so the
// first use is not refused — every such host acknowledges it and then
// quarantines itself.
//
// release_2026_11_v1's set is declared here IN FULL, before any of its feature
// branches lands, because it ships together (capabilities_test.go
// frozenReleaseFeatures pins it, so adding to it fails CI). Each branch adds
// only its Writers to its own entry and its writes through WithFeature; a
// declared feature nobody writes yet is simply unused. Until the release
// ships, the list may still be corrected — a feature's grain or description —
// by one reviewed change to this map and to frozenReleaseFeatures together;
// after it ships, never.
//
// GRAIN. One feature is one used bit: the first write of ANY of its data marks
// it used, and from then on a rollback below the token quarantines. So a
// feature must not bundle data written by default with data written only on
// request. The firewall branch gates per-NIC guards — on by default for every
// new NIC, so used on the first NIC created after the latch — on nic_guards,
// and IPv6 rules on firewall_ipv6, so a cluster with no IPv6 rule can still
// roll back below the release. drain_failback is used by default in the same
// way: every drain after the latch records the VMs it moved, because
// `lv host failback --all` may be asked for them later, so the first drain
// after the latch marks it used. Its other data, the cluster failback policy,
// is nothing failback can act on without those records, so it shares the bit.
var releaseFeatures = map[Feature]FeatureInfo{
	FeatureVMLimits: {Token: Release202611V1, Description: "Per-VM CPU limit and shares, and NIC bandwidth limits",
		Writers: []string{"internal/grpcapi.admitLimitedSpec", "internal/grpcapi.admitLimitUpdate",
			"internal/corrosion.InsertVMWithReleaseFeatures", "internal/corrosion.MutateDesiredSpecWithReleaseFeatures"}},
	FeatureVMDiskNICIO: {Token: Release202611V1, Description: "Per-disk discard and I/O limits and per-NIC queues; discard defaults on for new disks",
		Writers: []string{"internal/corrosion.InsertVMWithTuning", "internal/corrosion.MutateDesiredSpecTuning",
			"internal/corrosion.InsertVMWithReleaseFeatures", "internal/corrosion.MutateDesiredSpecWithReleaseFeatures"}},
	FeatureEmailTargetSecret: {Token: Release202611V1, Description: "Email notification targets with a stored SMTP password",
		Writers: []string{"internal/corrosion.InsertEmailTargetWithSecret"}},
	FeatureLoginPolicy:   {Token: Release202611V1, Description: "Account disable and expiry, the mandatory second factor, directory identity binding and session directory groups for group role bindings (used by default: the first directory or second-factor login, or user create or delete)", Writers: loginPolicyWriters},
	FeatureDrainFailback: {Token: Release202611V1, Description: "Failback after a drain: the record every drain writes of the VMs it moved, and the cluster failback policy", Writers: []string{"internal/corrosion.PutDrainOrigin", "internal/corrosion.SetFailbackPolicy"}},
	FeatureFirewallIPv6: {Token: Release202611V1, Description: "IPv6 security-group, cluster and host firewall rules, and IPv6 ip-set elements",
		Writers: []string{"internal/corrosion.InsertSGRuleWithGrant", "internal/corrosion.InsertClusterFirewallRuleWithGrant", "internal/corrosion.InsertHostFirewallRuleWithGrant", "internal/corrosion.InsertIPSetWithGrant"}},
	FeatureNICGuards: {Token: Release202611V1, Description: "Per-NIC guards (source MAC and IP, DHCP server, router advertisements, VLAN tags); on by default for new NICs",
		Writers: []string{"internal/corrosion.PutNICGuard"}},
	FeatureUSBMountsMemory: {Token: Release202611V1, Description: "VM USB devices and memory hot-add; container host mounts and devices",
		Writers: []string{
			"internal/corrosion.InsertVMWithPassthrough",
			"internal/corrosion.CreateContainerAtomicWithHostAccess",
			"internal/corrosion.UpsertContainerWithHostAccess",
			"internal/corrosion.InsertVMWithReleaseFeatures",
			"internal/corrosion.MutateDesiredSpecWithReleaseFeatures",
		}},
	FeatureBackupZstd: {Token: Release202611V1, Description: "zstd chunk compression in backup repositories",
		Writers: []string{"internal/pbsstore.InitWithGrant", "internal/pbsstore.Repo.EnableCompressionWithGrant"}},
	FeatureContainerReplication: {Token: Release202611V1, Description: "Container replication to a replica host", Writers: containerReplicationWriters},
	FeaturePITOverlay: {Token: Release202611V1, Description: "Point-in-time copies of a running VM's disk through an external-snapshot overlay (replication and volume moves; used by default whenever a backup session cannot be made)",
		Writers: []string{"internal/pitoverlay.OpenWindow", "internal/grpcapi.Server.openPITWindow"}},
	FeatureRedfishFence: {Token: Release202611V1, Description: "The redfish fence strategy: a host fenced through its BMC's Redfish service, with the BMC settings and password on the sensitive lane",
		Writers: []string{"internal/grpcapi.hostFenceRedfishStatement"}},
	FeatureISCSILUNClaim: {Token: Release202611V1, Description: "Cluster-wide voter claim of each iSCSI LUN by one disk; iSCSI disk creates, rebuilds and recreates wait for it",
		Writers: []string{"internal/grpcapi.Server.decideLUNWith", "internal/grpcapi.Server.learnLUN",
			"internal/corrosion.AdvanceLUNResolved", "internal/corrosion.RecordLUNPlainDelete"}},
	FeatureHADisarm: {Token: Release202611V1, Description: "Cluster-wide HA disarm: the replicated policy that holds automatic fencing and recovery",
		Writers: []string{"internal/corrosion.SetHAPolicy"}},
	FeatureNICMTU:          {Token: Release202611V1, Description: "Per-NIC MTU", Writers: []string{"internal/corrosion.InsertVMWithReleaseFeatures", "internal/corrosion.MutateDesiredSpecWithReleaseFeatures"}},
	FeatureReplicationRate: {Token: Release202611V1, Description: "Per-schedule replication bandwidth limits", Writers: []string{"internal/corrosion.SetReplicationRate"}},
	FeatureReturningBoot: {Token: Release202611V1, Description: "A host booting from fenced, offline, maintenance, draining or joining is recorded upgrading until its daemon serves (used by default once the release latches)",
		Writers: []string{"internal/hostboot.WriteReturningBoot"}},

	// The firewall extras.
	FeatureFirewallSynflood: {Token: Release202611V1, Description: "SYN-flood protection on guest NICs: the cluster and per-host policy (recorded on for a cluster founded by this release)",
		Writers: []string{"internal/corrosion.SetFirewallSynflood", "internal/corrosion.SeedFirewallSynflood"}},
	FeatureFirewallLog: {Token: Release202611V1, Description: "Firewall logging: logged rules and the cluster and per-host log policy",
		Writers: append(slices.Clone(firewallRuleWriters), "internal/corrosion.SetFirewallLogPolicy")},
	FeatureFirewallTagGroups: {Token: Release202611V1, Description: "Firewall tag groups, per-workload firewall tags, and rules matching a tag group's addresses", Writers: firewallTagGroupWriters},

	// Used only when a removed host is added again.
	FeatureHostIncarnation: {Token: Release202611V1, Description: "Host incarnation counter: a removed host re-added under its name is a new incarnation that no copy of the removed machine's row overrides (used when a removed host is re-added)",
		Writers: []string{"internal/corrosion.AdmitHostV2", "internal/corrosion.WriteOwnEndpoint"}},

	FeatureAutomationStream: {Token: Release202611V1, Description: "Certified automation history, retained recovery provenance, and managed-resource state"},
	FeatureSGProjects:       {Token: Release202611V1, Description: "Security groups owned by a project (used when a group is created with a project)", Writers: []string{"internal/corrosion.InsertProjectSecurityGroup"}},

	// release_2026_12_v1. release_2026_11_v1's set is frozen, so a feature
	// declared after it gates on the next release token.
	//
	// fence_ssh is used by default: every host publishes its own row as soon
	// as the token latches, because a published row is what pins its sshd
	// host keys for every fence aimed at it (the legacy path included). So
	// the first daemon tick after the latch marks it used, and from then on a
	// rollback below release_2026_12_v1 quarantines.
	FeatureFenceSSH: {Token: Release202612V1, Description: "Managed node-to-node fence SSH: each host's signed fence key and sshd host keys, rendered into a restricted authorized_keys and a pinned known_hosts on every peer (used by default once the release latches)",
		Writers: []string{"internal/corrosion.PutHostFenceSSH"}},
}

// firewallRuleWriters write the three rule tables. Each takes one grant per
// feature a row can need (firewall_ipv6, firewall_log, firewall_tag_groups)
// and checks each the row needs.
var firewallRuleWriters = []string{
	"internal/corrosion.InsertSGRuleWithGrant",
	"internal/corrosion.InsertClusterFirewallRuleWithGrant",
	"internal/corrosion.InsertHostFirewallRuleWithGrant",
}

// firewallTagGroupWriters write firewall_tag_groups' data: the rule tables
// (a rule matching a tag group), the tag-group rows, a workload's firewall
// identity, and its firewall-tags row.
var firewallTagGroupWriters = append(slices.Clone(firewallRuleWriters),
	"internal/corrosion.SetFirewallTagGroup",
	"internal/corrosion.MintFirewallID",
	"internal/corrosion.SetFirewallTags",
	"internal/corrosion.ClearFirewallTags",
)

// containerReplicationWriters write container_replication's data: a container's
// replication schedule row, its direction switch, and a run's replica.
var containerReplicationWriters = []string{
	"internal/corrosion.UpsertContainerReplicationSchedule",
	"internal/corrosion.RepointContainerReplicationTarget",
	"internal/grpcapi.Server.replicateContainer",
}

// loginPolicyWriters are the writers of login_policy's data: user_lifecycle,
// the second-factor policy row, session_factors, session_groups,
// user_enrollment_codes and user_identity_bindings (the statement builders take the grant where a batch
// carries the login rules' part only when it is granted).
var loginPolicyWriters = []string{
	"internal/corrosion.SetUserLifecycle",
	"internal/corrosion.ResetUserLifecycle",
	"internal/corrosion.enableUserStatements",
	"internal/corrosion.SetTwoFactorPolicy",
	"internal/corrosion.InsertSessionWithLoginData",
	"internal/corrosion.IssueEnrollmentCode",
	"internal/corrosion.ConsumeEnrollmentCode",
	"internal/corrosion.InvalidateEnrollmentCode",
	"internal/corrosion.BindIdentity",
	"internal/corrosion.ClearIdentityBinding",
	"internal/corrosion.ClearIdentityBindingRows",
	"internal/corrosion.DeleteUserCounted",
	"internal/corrosion.reinstateAdminStatements",
	"internal/corrosion.resetAdminStatements",
}

// The features of release_2026_11_v1. Each name is written into a replicated
// key once used, so it never changes.
const (
	FeatureVMLimits             Feature = "vm_limits"
	FeatureVMDiskNICIO          Feature = "vm_disk_nic_io"
	FeatureEmailTargetSecret    Feature = "email_target_secret"
	FeatureLoginPolicy          Feature = "login_policy"
	FeatureDrainFailback        Feature = "drain_failback"
	FeatureFirewallIPv6         Feature = "firewall_ipv6"
	FeatureNICGuards            Feature = "nic_guards"
	FeatureUSBMountsMemory      Feature = "usb_mounts_memory"
	FeatureBackupZstd           Feature = "backup_zstd"
	FeatureContainerReplication Feature = "container_replication"
	FeatureISCSILUNClaim        Feature = "iscsi_lun_claim"
	FeaturePITOverlay           Feature = "pit_overlay"
	FeatureRedfishFence         Feature = "redfish_fence"
	FeatureHADisarm             Feature = "ha_disarm"
	FeatureNICMTU               Feature = "nic_mtu"
	FeatureReplicationRate      Feature = "replication_rate"
	FeatureReturningBoot        Feature = "returning_boot"

	FeatureFirewallSynflood  Feature = "firewall_synflood"
	FeatureFirewallLog       Feature = "firewall_log"
	FeatureFirewallTagGroups Feature = "firewall_tag_groups"
	FeatureHostIncarnation   Feature = "host_incarnation"
	FeatureAutomationStream  Feature = "automation_stream"
	FeatureSGProjects        Feature = "sg_projects"
)

// The features of release_2026_12_v1. Each name is written into a replicated
// key once used, so it never changes.
const (
	FeatureFenceSSH Feature = "fence_ssh"
)

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
	Release202612V1: RollbackSafeIfUnused,
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
	Release202612V1: true,
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
// The zero value grants nothing. Only health.Checker.WithFeature mints one,
// through the minter it claims at init (ClaimGrantMinter); a second claim
// panics, and the release-feature guard (release_guard_test.go) fails the
// build on any other caller. A grant obtained any other way would let a write
// skip the used bit a rollback relies on.
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

// mintGrant makes a grant for f. Reached only through ClaimGrantMinter, which
// the gate claims at init, and GrantForTest.
func mintGrant(f Feature) FeatureGrant {
	return FeatureGrant{feature: f, minted: true}
}

// grantMinterClaimed records that the one minter has been handed out.
var grantMinterClaimed atomic.Bool

// ClaimGrantMinter hands out the only function that mints FeatureGrants. The
// release-feature gate (health/release_feature.go) claims it in a package
// variable initialiser; a second claim panics, so no other package can mint a
// grant without the binary failing at start. release_guard_test.go also fails
// the build on any other caller.
func ClaimGrantMinter() func(Feature) FeatureGrant {
	if !grantMinterClaimed.CompareAndSwap(false, true) {
		panic("capabilities: the FeatureGrant minter is already claimed (by health.Checker.WithFeature); " +
			"a release feature's write must go through that gate")
	}
	return mintGrant
}

// GrantForTest mints a grant for a test's fake gate. Test code only: the
// release-feature guard fails the build on any non-test caller.
func GrantForTest(t testing.TB, f Feature) FeatureGrant {
	t.Helper()
	return mintGrant(f)
}

// ReleaseTokens lists the release tokens this build advertises (tokens with a
// rollback rule), what a push declares before the live advertisement is wired.
func ReleaseTokens() []string {
	var out []string
	for _, t := range supported {
		if RollbackRule(t) != "" {
			out = append(out, t)
		}
	}
	return out
}
