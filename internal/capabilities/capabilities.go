// Package capabilities defines the named split-brain-hardening feature tokens a
// daemon advertises via PingResponse.capabilities, and the set THIS build
// supports.
//
// Tokens gate fail-closed safety checks. A check activates (starts refusing, and
// for the proof table starts WAL-replicating to that peer) ONLY once every
// enforcement-relevant member advertises its token — read via a fresh peer Ping,
// never from stale replicated rows and never from schema_version (too coarse;
// unchanged by a schema-neutral phase). Activation is recomputed from fresh Pings;
// once confirmed cluster-wide it LATCHES durably (per token, via a marker file), so
// a later partition — where support can't be re-confirmed — fails closed rather
// than reverting to the legacy ungated path.
package capabilities

import "sort"

const (
	// SplitBrainGateV1 gates the composable dangerous-action gate (Phase 1): both
	// the use of the non-LWW runtime_action_proofs table AND enforcement of the
	// quorum/proof gate. WAL relay of proof mutations is suppressed per-peer to any
	// node not advertising this token; the peer-only sensitive anti-entropy lane
	// additionally carries proofs as a convergence net. Both apply the bespoke
	// MONOTONE merge (any node holding the table ships that resolver in the same v38
	// binary), so single-use can't be broken by an ordinary-LWW apply.
	SplitBrainGateV1 = "split_brain_gate_v1"
	// VIPDemoteV1 is the MINORITY-side Phase-2 token: this node can confirmed-stop keepalived
	// and remove/verify its own VIP locally on quorum loss. A SOFTWARE capability: no hardware
	// watchdog is required to advertise it or to self-demote — the watchdog is only an
	// OPTIONAL self-fence backstop for the corner where a demote can't be confirmed.
	VIPDemoteV1 = "vip_demote_v1"
	// VIPReleaseProbeV1 is the MAJORITY-side Phase-2 trust token: this node answers by-VIP
	// participant/absence probes (CheckVIPParticipant, direct or relayed) AUTHORITATIVELY, so
	// peers may trust its "not claiming" answer as a release proof when reclaiming a VIP. A node
	// may advertise one of {VIPDemoteV1, VIPReleaseProbeV1} without the other; the two flip
	// together as the Phase-2 pair. Also a software capability (no watchdog).
	VIPReleaseProbeV1 = "vip_release_probe_v1"
	// SharedStorageFenceV1 gates proof-grade fencing for a cross-host ownership
	// TRANSFER start of a VM with a writable SHARED disk (nfs/ceph/rbd/iscsi). Once
	// enforced cluster-wide, auto-promote / reschedule of such a VM requires a
	// proof-grade fence of the old owner — a confirmed power-off (IPMI) or an
	// operator manual-confirm — carried in the proof's fence_epoch; a best-effort
	// SSH "success" (never confirms power-off) is rejected. A local-disk transfer
	// (a replica is a different image; no shared-write hazard) keeps today's gate.
	// Host-fence-gated, NOT storage-level exclusivity. Gated (config kill-switch +
	// latch) because it changes live failover behavior for shared-disk VMs.
	SharedStorageFenceV1 = "shared_storage_fence_v1"
	// FenceEpochV1 gates Phase-5 fence-epoch staleness enforcement.
	FenceEpochV1 = "fence_epoch_v1"
	// OwnerEpochV1 gates Phase-5 enforcement, advertised only after Phase-4 backfill.
	OwnerEpochV1 = "owner_epoch_v1"

	// LeaseTermLedgerV1 gates WRITING to the term ledger at all — one step below
	// LeaseTermV1, which gates deciding on what is written.
	//
	// It exists for the replication contract, not for policy. leader_lease_terms
	// gained the first replicated statement shape of its life in this work, and a
	// peer on the previous release has no ledger entry for that fingerprint: an
	// unregistered shape BACK-PRESSURES rather than degrading (the apply is
	// rejected, the batch rolls back, and that peer's replication watermark
	// stalls, head-of-line blocking the stream into every not-yet-rolled node).
	// The pre-stage migration pass does not help — it equalizes DB schema, and
	// the statement ledger is a property of the BINARY.
	//
	// So the mint waits for proof that no such peer is listening, and a
	// capability latch is exactly that proof: a node on the old build cannot
	// advertise a token it has never heard of.
	//
	// That argument only holds over the right set of peers, which is why this
	// token is in replicationGated. An ordinary latch is computed over
	// VOTING-eligible members, and "listening" is not a property of voting: a
	// host in `maintenance` — the normal state for one queued to be upgraded
	// next — is skipped by the voting sweep while the replicator, which filters
	// on nothing but memberlist membership, keeps streaming to it. Over the
	// voting set alone this latch could form with the old-build peer still
	// listening, proving nothing about the only host it was meant to wait for.
	//
	// Deliberately advertised UNCONDITIONALLY — no config flag, in the
	// SplitBrainGateV1 style — so terms begin minting on their own the moment the
	// roll completes. Gating the mint on LeaseTermV1 instead would have been
	// cheaper, but no term would exist until an operator enabled enforcement, so
	// enforcement would latch onto an empty ledger; a term is meant to be an
	// audit fact before anything decides on one (docs/operating-model.md).
	LeaseTermLedgerV1 = "lease_term_ledger_v1"

	// CredentialsSplitV1 gates moving the three secret COLUMNS of public
	// inventory tables — hosts.ipmi_pass, users.password_hash and
	// tokens.token_hash — into their own sensitive-lane tables
	// (host_fence_credentials, user_credentials, token_credentials).
	//
	// This release DUAL-WRITES: once latched, every writer writes the credential
	// table and the old column in one batch, and nothing clears an old column.
	// Readers take the credential row whenever one exists and the old column
	// only when none does; they never date a secret by the PARENT row's
	// updated_at, which unrelated writes bump (the #267 race). A secret written
	// by a node that has not latched yet is recognised by its entry carrying no
	// credential statement, and absorbed into the credential row where it is
	// applied (corrosion/credentials_absorb.go). A rollback below the latch is
	// still not clean: the rolled-back binary enters WAL quarantine
	// (preflightCapabilityRollback) and emits no replicated writes until it is
	// upgraded again or reseeded. What the two copies buy is that its
	// old-column reader still validates tokens, checks passwords and fences,
	// where a cleared column lost all three, and that upgrading again loses
	// nothing. Clearing the old columns, which is what finally
	// takes the secrets out of the operator-safe state dump, arrives in a later
	// release behind a second mandatory, ReplicationGated token
	// (docs/design/credentials-clear.md).
	//
	// It states two facts about the BINARY, which is why it is mandatory and has
	// no config flag:
	//
	//   - it can DECODE the credential tables' statement shapes. They are the
	//     first replicated shapes those tables ever had, and an unregistered shape
	//     back-pressures a previous-release peer rather than degrading: its apply
	//     fails closed, the batch rolls back and its watermark stalls. So nothing
	//     writes to the credential tables until this token has latched.
	//   - it READS a credential from the credential table, falling back to the
	//     old column only where no credential row exists. A previous-release
	//     node reads only the old column, which is why this release keeps
	//     writing it.
	//
	// The first fact must hold of every host this node REPLICATES TO, not
	// merely of every host that votes, so the token is in replicationGated. A
	// host parked in `maintenance` on the old build still receives every
	// statement; a latch computed over voting members alone would stall its
	// stream on the first credential-table write.
	//
	// A flag would be worse than useless: driveCapabilityLatches skips an
	// unlatched token whose flag is off, so a flag-gated split would never latch,
	// the later release's clear (which needs the credential tables populated)
	// could never follow, and the secrets would stay in the public dump forever.
	// There is nothing an
	// operator could correctly decline — the split changes where a secret is
	// stored, not a policy.
	CredentialsSplitV1 = "credentials_split_v1"

	// HostMembershipSplitV1 gates moving a host's coordinator-owned membership
	// facts — hosts.state and hosts.isolation_epoch/isolation_reason — out of
	// the shared `hosts` row into host_membership, a row of their own with its
	// own LWW clock (colonelpanik/litevirt#267). While they shared the hosts
	// row, a coordinator marking a host fenced and that host's daemon
	// reporting its version were two writes under ONE updated_at, so whichever
	// a replica applied second could be refused as older and lost.
	//
	// It states two facts about the BINARY, which is why it is mandatory and has
	// no config flag:
	//
	//   - it can DECODE host_membership's statement shapes. They are the first
	//     replicated shapes that table ever had, and an unregistered shape
	//     back-pressures a previous-release peer: its apply fails closed, the
	//     batch rolls back and its watermark stalls. So nothing writes
	//     host_membership until this token has latched.
	//   - it READS state and isolation from host_membership first. Once
	//     latched, every state and isolation change is written to BOTH
	//     host_membership and the old hosts columns, in one batch — the old
	//     columns in their previous-release shapes, so a host rolled back one
	//     release still reads every change. Nothing clears them in this
	//     release; that is a later release's step behind a second token.
	//
	// The decode claim must hold of every host this node REPLICATES TO, not
	// merely of every host that votes, so the token is in replicationGated. A
	// host parked in `maintenance` on the old build does not vote, but it still
	// receives every statement, and a host_membership statement stalls its
	// stream.
	//
	// A flag would be worse than useless, for the credentials_split_v1 reason:
	// driveCapabilityLatches skips an unlatched token whose flag is off, so a
	// flag-gated split would never latch and the lost updates would stay. The
	// split changes where a fact is stored, not a policy.
	HostMembershipSplitV1 = "host_membership_split_v1"

	// FailoverScopeV1 gates the cluster-wide failover_scope policy
	// (cluster_policies, schema v58; docs/design/region-scoped-failover.md).
	// With the policy set to `region`, a host is fenced and its workloads
	// recovered only by a quorum of its own region's voters, and recovery
	// targets stay in that region (colonelpanik/litevirt#265).
	//
	// It states two facts about the BINARY, which is why it is mandatory and
	// has no config flag:
	//
	//   - it can DECODE cluster_policies' statement shapes. They are the first
	//     replicated shapes that table ever had, and an unregistered shape
	//     back-pressures a previous-release peer: its apply fails closed and its
	//     stream stalls. So nothing writes cluster_policies until this token
	//     has latched.
	//   - it HONOURS failover_scope: its coordinator counts region quorums and
	//     keeps recovery in region, and its ExecutionGate counts its own
	//     region. The guarantee is enforced where the fence is decided, and
	//     that is whichever node holds the failover lease — any node. A
	//     coordinator that did not read the policy would fence across regions
	//     while every other node believed it would not, so the policy may not
	//     be set until every node runs a build that honours it.
	//
	// The decode claim must hold of every host this node REPLICATES TO, so the
	// token is in replicationGated. The row itself is the opt-in and it is
	// replicated, so its uniformity comes from replication, not from matching
	// config; a flag would only keep a mandatory token from latching. Standing
	// down in an incident is `lv cluster failover-scope cluster`.
	FailoverScopeV1 = "failover_scope_v1"
	// VoterConfigV1 gates the explicit voter set (colonelpanik/litevirt#251
	// step 2) and the voter side of recovery claims
	// (docs/design/recovery-claims.md §3–§5.1): the voter_configs table, the
	// claim RPCs, the node-local grant tables and the voter incarnation.
	//
	// It states a fact about the BINARY, which is why it is mandatory and has
	// no config flag: this build decodes voter_configs' statement shapes and
	// answers Prepare / Accept / GetRecoveryClaim durably. Latching it starts
	// automatic genesis; until generation 1 is adopted, VoterSet is derived
	// exactly as before. A flag would be worse than none: a node with it off
	// would count a different majority from its peers, which is the split the
	// voter set exists to prevent.
	//
	// It is advertised only once this node is READY
	// (grpcapi.VoterConfigReadiness): PRAGMA synchronous is FULL, so a promise
	// is on disk before the reply that depends on it, and the host signing key
	// loads, so this voter can sign an accept. A node that cannot vote durably
	// must not let the fleet latch across it.
	//
	// ReplicationGated: latching it permits emitting voter_configs statements,
	// whose shapes a previous-release peer has no ledger entry for, so the
	// claim must hold of every host this node replicates to, a maintenance
	// host on the previous build included.
	VoterConfigV1 = "voter_config_v1"
	// ClaimIncarnationV1 gates INCARNATION-SCOPED recovery claims
	// (docs/design/recovery-claims.md §10 item 37, colonelpanik/litevirt#250):
	// once latched, a coordinator keys every workload claim by the workload
	// row's created_at as well as (kind, name, owner epoch, attempt), so a
	// workload deleted and re-created under one name — which starts again at
	// the same owner epoch — gets a fresh claim instead of the previous
	// incarnation's decided value. Before it latches, claims are keyed as they
	// always were.
	//
	// It states a fact about the BINARY, which is why it is mandatory and has
	// no config flag: this build decodes the incarnation in a claim key, keeps
	// incarnation-scoped voter state (local_incarnation_claims, schema v63),
	// signs and verifies the v2 accept payload, seals a legacy key once it has
	// answered the incarnation-scoped form of it, and reports its legacy state
	// in the promise. A coordinator relies on EVERY voter doing all of that:
	// a voter on an older build would read an incarnation-scoped Prepare as
	// the legacy key — the very collision this token exists to end — and its
	// accept would not verify. So the format may change only once no voter
	// can be an older build. A flag would let one coordinator key by
	// incarnation while another keys the same recovery the legacy way: two
	// claims for one decision.
	//
	// ReplicationGated: the certificate on a replicated runtime_action_proofs
	// row is judged by every replica's merge (certificateVerifiesTx), and an
	// older build cannot verify a v2 accept, so the claim must hold of every
	// host this node replicates to, a maintenance host on the previous build
	// included.
	//
	// Crossing the latch is safe for a recovery claimed on both sides of it:
	// a voter's promise at the incarnation-scoped key reports what it accepted
	// at the legacy key and seals that key against every later legacy
	// Prepare and Accept, and the proposer re-proposes a legacy value unless
	// its destination proves it is another incarnation's and will never run
	// (claims.Spec.AdoptLegacy, grpcapi Server.legacyValueExcluded).
	ClaimIncarnationV1 = "claim_incarnation_v1"

	// RecoveryClaimV1 gates ENFORCEMENT of single-winner recovery claims
	// (docs/design/recovery-claims.md §3, §5.1–§5.2,
	// colonelpanik/litevirt#250): a failover coordinator collects a majority
	// certificate from the voter set before it mints a reschedule, promote or
	// relocate proof, and a destination verifies that certificate before it
	// executes one. The voter side — answering Prepare / Accept — is
	// voter_config_v1's and runs whatever this token says.
	//
	// Config-gated (enforcement.recovery_claim) and advertised CONDITIONALLY on
	// that flag, like operation_protocol_v1, and the reason is where the
	// guarantee is enforced. It is enforced at EXECUTION: a coordinator cannot
	// stop another coordinator from creating a transfer, so every flag-on node
	// relies on every peer claiming before it mints and verifying before it
	// executes. A flag-off coordinator mints an uncertified proof and a
	// flag-off destination starts one — either way it is the second owner the
	// flag-on nodes did everything right to prevent. So the latch must mean
	// CONFIG uniformity, not just a uniform build, which is the opposite of
	// shared_storage_fence_v1 (enforced where a transfer is CREATED, so no node
	// relies on a peer). TestAdvertise_RecoveryClaimWithheldWhileOff pins it.
	//
	// It is advertised only when the flag is on AND this node is READY
	// (grpcapi.RecoveryClaimReadiness, local reads only): split_brain_gate_v1
	// has latched — the certificate rides on a runtime-action proof — and this
	// node can vote durably (voter_config_v1 readiness).
	//
	// ReplicationGated: latching it permits emitting the new statement shapes
	// of runtime_action_proofs.claim_certificate (schema v60), which a
	// previous-release peer has no ledger entry for.
	//
	// Not mandatory: it states a policy, and a policy needs a flag to turn off
	// in an incident. Enforcement is the flag AND Enforced(recovery_claim_v1)
	// AND an adopted voter generation with members.
	RecoveryClaimV1 = "recovery_claim_v1"

	// PartitionPauseV1 gates the MAJORITY's reliance on a minority's partition
	// pause (docs/design/partition-pause.md, colonelpanik/litevirt#250 / #253):
	// a host that cannot see a majority of the voter set for T_pause suspends
	// (VM) or freezes (container) every workload the majority would recover
	// elsewhere. Once this token is latched, a coordinator whose best-effort
	// fence could not reach a host (assurance assumed) starts nothing for that
	// host until health.PartitionPauseWait has passed since the decision, and
	// records the fence as self_paused.
	//
	// Config-gated (enforcement.partition_pause) and advertised CONDITIONALLY
	// on that flag, for the recovery_claim_v1 reason: the guarantee is
	// enforced on the minority and RELIED ON by the majority, so a flag-off
	// peer is the copy still running when the replacement starts — not merely
	// permissive. The latch has to mean config uniformity.
	// TestAdvertise_PartitionPauseWithheldWhileOff pins it.
	//
	// The pause itself runs on the flag alone, before any latch: each node
	// latches on its own schedule, so a node that waited for its own latch
	// could be relied on by a peer that latched first. A node advertises the
	// token only while it already acts on it.
	//
	// DEFAULT ON (LoadConfig), the second exception to the default-false rule
	// beside audit_signature_v1. An explicit false is the kill switch.
	//
	// Not mandatory: it states a policy (availability against a duplicate
	// copy), and a policy needs a flag. Not ReplicationGated: it emits no new
	// statement shape — the pause record is a host-local file, and the fence
	// row and the conditions use existing shapes — so its latch is a claim
	// about what voting members DO, which is what an ordinary latch measures.
	PartitionPauseV1 = "partition_pause_v1"

	// LeaseTermV1 gates leader-lease term enforcement: once active, a
	// runtime-action proof must carry the lease term of the incarnation that
	// minted it, and an executor refuses a proof whose term is below the
	// QUORUM-observed high-water mark for that key, or whose coordinator is not
	// the holder this node recorded at that term.
	//
	// Advertised CONDITIONALLY on enforcement.lease_term AND local readiness
	// (three or more voting-eligible hosts, a readable ledger, and
	// SplitBrainGateV1 already latched), so the fleet cannot latch across a node
	// that would refuse recovery — or across one that would accept a PROOFLESS
	// protected call ungated, which is what that last predicate is for: this
	// regime gates proof-bearing calls only.
	//
	// Config-gated in the REVERSIBLE StrictMTLSIdentityV1 style rather than
	// latch-only, and for a specific reason: the quorum barrier makes protected
	// actions refuse on a partition minority, and a latched cluster that later
	// shrinks below three voting-eligible hosts arrives at that cliff with no way
	// back — a latch is one-way. Enforcement is config AND Enforced, so clearing
	// the flag is the operator's exit.
	//
	// It does NOT fix two nodes each believing they hold the lease; that needs
	// consensus. What it gives is per-executor: no single host executes for two
	// claimants of one tenure, because the CLAIM binds that host to the first
	// claimant it acted for at that term. The equal-term ledger arm alone would
	// not deliver that — it fires only once a term row has replicated, and
	// during a partition neither claimant's has. The cluster still does not
	// agree on which claimant is legitimate.
	LeaseTermV1 = "lease_term_v1"
	// IsolationEpochV1 gates the §A isolation regime: a host recorded with a
	// nonzero hosts.isolation_epoch has its replication REFUSED by every peer
	// until a verified reseed clears it. Gated because it can refuse a peer
	// outright — a pre-latch cluster behaves exactly as before, so the regime
	// rolls out incrementally, and a partition fails closed (no latch, no new
	// refusals). Deliberately NOT a version-skew check: mixed-version rolling
	// upgrades must keep working, so it gates on the recorded isolation fact.
	IsolationEpochV1 = "isolation_epoch_v1"
	// SafeFenceDefaultV1 gates the safe-fencing-default policy: once enforced
	// cluster-wide, an UNCONFIRMED best-effort fence is no longer treated as proof
	// of power-off — the coordinator requires an operator fence-confirm before
	// rescheduling (as it already does for the "manual" strategy), unless the host
	// explicitly opts into legacy proceed-anyway via LabelUnsafeAutoFailover. Gated
	// (not unconditional) because it changes live failover behavior, so a
	// mixed-version cluster must not flip mid-roll.
	SafeFenceDefaultV1 = "safe_fence_default_v1"
	// LWWSkewGuardV1 gates FUTURE-SKEW QUARANTINE for LWW merges (partial): once
	// enforced cluster-wide, an incoming row whose updated_at is beyond MaxSkew into
	// the future is quarantined (kept-local) rather than allowed to win, so a
	// fast-clock peer can't dominate last-writer-wins. Gated because a mixed-version
	// cluster must not start quarantining before every node enforces it.
	//
	// SCOPE — this is NOT a full HLC LWW fix. It only guards FUTURE skew; the
	// backward-clock case (a restart after a wall-clock step-back emitting older
	// conflict keys) is addressed separately: the monotonic-high-water persistence
	// (always-on) plus HLCLwwV1 below, which flips the conflict-key ENCODING to HLC.
	LWWSkewGuardV1 = "lww_skew_guard_v1"
	// HLCLwwV1 gates emitting the LWW conflict key (updated_at, via Client.NowTS) as
	// an HLC string instead of RFC3339Nano — the real backward-clock fix: an HLC key
	// carries a monotonic (physical-ms, logical, node-id) rank that a wall-clock
	// step-back can't undercut, and it breaks cross-node equal-instant ties
	// deterministically by node-id (killing the keep-local infinite-resync tie class).
	// Gated + config-flagged (enforcement.hlc_lww) because it changes the conflict-key
	// encoding: emission activates only once every node ADVERTISES the token (so every
	// receiver's lwwOrder can parse+instant-compare HLC — shipped ahead of emission)
	// AND the local flag is set AND the token has latched. The comparator is
	// instant-based, so a per-node canary and a flag-off rollback are both safe (a
	// fresh RFC3339 write never loses to an older HLC one). NOT a full clock rewrite:
	// updated_at is the only column that becomes HLC; wall/display columns keep RFC3339.
	HLCLwwV1 = "hlc_lww_v1"
	// StrictMTLSIdentityV1 gates the strict mTLS-identity auth model: a bearerless
	// client certificate (a distributable lv-cli cert, an unknown/empty CN, or a
	// removed host's CN) is no longer treated as admin — it must present a session
	// bearer. Peer (known-host) and on-node loopback certs keep admin authority, so
	// NO node-to-node wire behavior changes. Unlike the split-brain tokens this gates
	// an AUTH decision, so it deliberately does NOT rely on the hard fail-closed latch
	// for recovery: the daemon config flag auth.strict_mtls_identity is the real
	// enforcement switch (enforcement is config AND Enforced) and kill switch, and the
	// loopback local-root path is never gated — so a mis-flip is reversible and can
	// never lock out on-node root.
	//
	// ADVERTISED (in `supported`), enforcement default-off: this build advertises the
	// token so the cluster can latch it, but enforcement stays inert until an operator
	// sets auth.strict_mtls_identity — enforcement is config AND the latch, so a deploy
	// is behavior-neutral and the config flag is the reversible kill switch.
	StrictMTLSIdentityV1 = "strict_mtls_identity_v1"
	// ForwardedIdentityV1 gates the owner-side promotion of a forwarded user
	// identity. An entry node propagates the caller's session bearer to the owning
	// node in x-litevirt-fwd-bearer (send-side is ungated + forward-compatible);
	// once this token is enforced, the owner re-authenticates that bearer and runs
	// RBAC + audit as the REAL user instead of the peer=admin trusted-forward. A
	// forward with no bearer (a system continuation off a background context) stays
	// peer=admin/system. Owner-side validation is fail-closed: a session/user not
	// yet replicated → Unavailable (retryable), not silent admin. Config-gated
	// (auth.forwarded_identity) + reversible like StrictMTLSIdentityV1.
	//
	// ADVERTISED (in `supported`), enforcement default-off (see StrictMTLSIdentityV1) —
	// inert until auth.forwarded_identity is set. (The send-side bearer relay is always
	// on but forward-compatible: with enforcement off, no owner promotes, so the relayed
	// header is ignored.)
	ForwardedIdentityV1 = "forwarded_identity_v1"
	// RBACRealmV1 gates realm-aware role-binding grammar. Role bindings enforce
	// against realm-qualified principals (user:<name>@<realm>), so a legacy bare
	// grant (user:<name>) is inert. Once this token is enforced, a new daemon
	// stops minting bare bindings: it either REJECTS a bare grant (config on, not
	// yet latched fleet-wide — the safe pre-uniformity state) or RESOLVES it to
	// the target user's realm and stores it canonically (config on AND latched).
	// Gating on the latch is what keeps this mixed-version-safe: while any peer
	// still mints bare bindings, we refuse rather than canonicalize.
	//
	// ADVERTISED (in `supported`), enforcement default-off (see StrictMTLSIdentityV1) —
	// inert until auth.rbac_realm is set; the config flag is the reversible kill switch.
	RBACRealmV1 = "rbac_realm_v1"
	// OperationProtocolV1 gates the v41 F1 operation protocol (the operations/
	// operation_steps journal, the per-VM vm_owner_epoch/spec_generation, and the
	// active_operation_id mutation barrier). The per-host PCI observation/ownership
	// fixes activate independently, but the OPERATION protocol is only safe to rely
	// on once EVERY mutation-serving peer supports it — an old peer would direct-
	// write a spec without honoring the barrier/generations. Once latched, an
	// incompatible peer is quarantined from mutating endpoints + replication
	// sessions (with reseed-on-rejoin). Config-gated (enforcement.operation_protocol)
	// + reversible like StrictMTLSIdentityV1.
	//
	// Unlike the other reversible tokens (advertised build-static; a flag-off peer
	// is merely permissive), a peer NOT enforcing the F1 mutation barrier would
	// CORRUPT an in-flight operation — so this token is advertised CONDITIONALLY on
	// the local config flag (see Server.advertisedCapabilities). Withholding
	// advertisement when the flag is off keeps the cluster-wide latch (and thus any
	// reliance on the barrier) from happening until EVERY node has opted in —
	// enforcing the "require fleet uniformity before latching" rule. Enforcement is
	// default-off and the flag is the reversible kill switch.
	OperationProtocolV1 = "operation_protocol_v1"
	// CapacityAdmissionV1 gates the durable, operation-backed capacity admission
	// protocol. It has no standalone config flag: advertisement, latch driving,
	// and enforcement readiness follow enforcement.operation_protocol because a
	// capacity reservation is only safe when every mutator honors that journal.
	CapacityAdmissionV1 = "capacity_admission_v1"
	// LiveResizeV1 gates TRUE live CPU hot-add and balloon-memory resize (the
	// max_cpu vCPU-hotplug ceiling and the <vcpu current=N>MAX</vcpu> XML it needs).
	// Setting max_cpu is refused until this latches, because an old peer could drop
	// the field via a typed spec rewrite (labels/health reconciliation) or relay a
	// mutation that loses it — so the whole fleet must support it first. Once latched,
	// an incompatible peer is fenced from mutating/membership/replication sessions
	// (D3). Config-gated (enforcement.live_resize) + reversible like
	// StrictMTLSIdentityV1; advertised build-static (a flag-off peer is merely
	// permissive — it just won't originate max_cpu).
	LiveResizeV1 = "live_resize_v1"
	// CanonicalIdentityV1 gates natural-key identity resolution for the tables that mint a
	// random-UUID primary key but carry a UNIQUE natural key (snapshots (vm_name,name);
	// container_snapshots (host_name,ct_name,name)). Two nodes can independently mint DIFFERENT
	// ids for one logical object, whose replicated rows then collide on the secondary UNIQUE and
	// back-pressure. Once this latches cluster-wide, an upgraded receiver resolves these tables by
	// natural key (a deterministic winner over the natural-key group, collapsing the losing id
	// into the winner via a column-preserving re-key) — NOT pairwise-negotiated per sender,
	// because identity resolution mutates shared state and a per-sender flip would be
	// non-convergent. A node that hasn't latched keeps the old behavior (back-pressures the
	// collision) and converges once the whole fleet has latched.
	//
	// Like OperationProtocolV1, this token is advertised CONDITIONALLY on the local config flag
	// (enforcement.canonical_identity; see Server.advertisedCapabilities): mutating shared state
	// on a partial rollout must require CONFIG uniformity, not just a uniform build, so the
	// latch (and thus any node collapsing rows) cannot happen until every node has opted in.
	// Enforcement = the flag AND the latch; default-off + reversible.
	CanonicalIdentityV1 = "canonical_identity_v1"
	// HardwareV2 gates the source-of-truth cutover for VM hardware management (the VM
	// Hardware Foundation effort): once enforced cluster-wide, hardware reads/writes
	// move off the legacy representation onto the new one. This registration is the
	// first step only — it makes the token a known, advertised name so the latch
	// machinery can reference it by string; a later task gates advertisement on
	// per-node readiness (so a node still migrating its hardware state doesn't
	// advertise support before it's actually ready) and another adds the
	// latch/enforcement machinery itself. Additive: changes no existing token's
	// value or behavior.
	HardwareV2 = "hardware_v2"
	// VMReplaceV1 gates the guarded VM-name replacement `lv cutover` needs: giving a
	// replacement VM the name a REPLACED VM still holds.
	//
	// The name is a PRIMARY KEY and DeleteVM soft-deletes, so the replaced VM's
	// tombstone still occupies it. Nothing expressible in the pre-existing statement
	// shapes makes that transition safe on a RECEIVER. A purge of the obstruction is
	// applied unconditionally while the write meant to replace it is only LWW-gated,
	// so a delayed replay erases a tombstone and puts nothing in its place. Splitting
	// it into a relocation plus a rekey does not help: each statement is gated
	// independently, so a receiver can commit one leg and skip the other, leaving no
	// row at the name — or move a still-live VM aside when its own newer ownership
	// made the sender's delete decline there. And the merge rules decide a both-live
	// conflict at the contested name on owner/generation authority alone, so a stale
	// higher-authority copy of the replaced VM overwrites its replacement no matter
	// where the tombstone was put.
	//
	// What the operation actually needs is ONE receiver decision covering the whole
	// batch: validate the source and target incarnations and authority together, then
	// either apply every statement or none. That is a new guard protocol
	// (workload_replace_v1) plus a parent shape that preserves the REPLACEMENT's
	// incarnation while advancing authority beyond BOTH inputs — new receiver
	// semantics, which no historical-ledger entry can retrofit onto an older peer.
	//
	// So it is advertised CONDITIONALLY on the local config flag
	// (enforcement.vm_replace), like OperationProtocolV1: the latch must require
	// CONFIG uniformity, and `lv cutover` REFUSES until the token is active — before
	// it stops a domain or touches either VM. A cluster that has not opted in keeps a
	// cutover that declines, rather than one that half-applies.
	VMReplaceV1 = "vm_replace_v1"
	// ProjectAuthorityV1 gates DELEGATED project-quota admission: a node that does not
	// hold a project's D1 admission authority asks the holder to decide, instead of
	// deciding from its own replica. Reserve-then-verify alone makes two racers agree
	// only once both reservations are VISIBLE to both; corrosion is eventually
	// consistent, so two nodes that have not yet exchanged operation rows can still
	// both admit. One decider per project closes that window.
	//
	// Advertised CONDITIONALLY on the local config flag (enforcement.project_authority),
	// like OperationProtocolV1 — a peer that is not delegating still admits from its own
	// replica, so a delegating node would be serializing against a decider its peers
	// bypass, which is no serialization at all. Withholding advertisement makes the latch
	// require CONFIG uniformity, so nobody starts trusting the single decider until every
	// node routes through it.
	//
	// A holder that cannot be reached fails the admission CLOSED (the repo-wide partition
	// rule). Default-off, and the flag is the reversible kill switch.
	ProjectAuthorityV1 = "project_authority_v1"
	// AuditSignatureV1 gates the REFUSAL half of tamper-evident audit logging (v45:
	// audit_log.key_id/signature/seq, signed with the host's existing cluster key).
	// It does NOT gate signing: a signed row is backward-compatible — an old peer
	// ignores the new columns and replicates them intact, and a nil keyring reads as
	// "unsigned" rather than "broken" — so a node signs whenever
	// enforcement.audit_signature is on, latch or no latch.
	//
	// What needs a latch is the failure mode on the other side: a node that cannot
	// sign (no host key, keyring load failure) writing the audit row anyway. That row
	// is indistinguishable from one an attacker with database write access appended
	// after stripping key_id/signature — and if unsigned rows are a normal, expected
	// outcome, `lv audit verify` cannot call them a forgery. Once this token is
	// enforced the unsignable write REFUSES instead, so "unsigned" stops being a
	// legitimate state and starts being evidence.
	//
	// Advertised CONDITIONALLY on the local config flag, like OperationProtocolV1: a
	// node with the flag off still emits unsigned rows into the same cluster-wide
	// table, and a chain containing them proves nothing about the hosts that DID
	// sign. So the latch must require CONFIG uniformity, not just a uniform build —
	// enabling on one node changes nothing until every node has opted in. Default-off,
	// and the flag is the reversible kill switch (off → sign nothing, refuse nothing).
	AuditSignatureV1 = "audit_signature_v1"
	// NetBoxIPAMV1 gates binding a litevirt network to a NetBox prefix.
	//
	// The latch is required because an OLDER binary does not parse the
	// NetBoxPrefixID field on a network definition at all, and would silently
	// allocate from the builtin allocator across the whole prefix. Every node
	// observing the same replicated binding is not the same thing as every node
	// INTERPRETING it — which is why replicated state alone is not sufficient here.
	NetBoxIPAMV1 = "netbox_ipam_v1"
	// NetBoxMirrorV1 gates the NetBox INVENTORY MIRROR — the half that creates
	// `virtual_machine` and `vminterface` objects and assigns addresses to them.
	//
	// NetBox is two integrations behind one config block, and only one of them is
	// the default. The IPAM half makes NetBox the address authority: it claims
	// `ip_address` objects carrying this cluster's identity, and that identity is
	// what makes an address ours. The INVENTORY half additionally rewrites the VM
	// inventory, which an installation that already models its VMs elsewhere has
	// every reason to refuse. So mirroring is opt-in (`netbox.mirror_inventory`),
	// and with it off NetBox holds addresses carrying our identity and nothing
	// else — no `virtual_machine`, no `vminterface`, no assign or clear.
	//
	// A TOKEN rather than a plain config read, and advertised CONDITIONALLY on
	// that flag exactly as NetBoxIPAMV1 is. The mirror sweep runs on whichever
	// node holds the `netbox` leader lease, so "this installation mirrors" is a
	// CLUSTER-WIDE fact: set on some nodes only, the inventory would appear and
	// disappear as leadership moved, and every object the mirroring node created
	// would be left for a non-mirroring successor that never reaps it.
	// Withholding advertisement while the flag is off is what makes the latch
	// require CONFIG uniformity rather than merely a uniform build — enabling on
	// one node changes nothing.
	//
	// It does NOT replace NetBoxIPAMV1 for the mirror. The mirror's own tables
	// (`netbox_objects`, `netbox_sync_queue`) are v51, and a statement against a
	// table a peer's ledgers do not carry back-pressures that peer's whole
	// replication stream; netbox_ipam_v1 is the token that says every peer
	// carries them. The mirror requires BOTH latches plus the local flag.
	//
	// Default false, and the flag stays the reversible kill switch: a latch is
	// monotone and durable, so the flag has to gate the DECISION and not only the
	// advertisement or the mirror could never be turned off again.
	NetBoxMirrorV1 = "netbox_mirror_v1"
)

// supported is the set of tokens THIS build both implements AND advertises. A
// token is added here only once its machinery is fully wired, so cluster-wide
// activation of a fail-closed check can never precede a node's ability to honor it.
// (Phases 4/5 will append the epoch tokens.)
//
// ALL currently-implemented tokens are now ADVERTISED. SplitBrainGateV1 has no kill
// switch (it flips via advertisement alone); every OTHER token is gated `configFlag &&
// latch` (enforcement.* / auth.*), so advertising it is behavior-neutral until an
// operator sets its flag — the flip is decoupled from enablement. Enforcement of any
// token still activates only once every enforcement-relevant member advertises it
// (fresh Ping) and it latches per node.
//
//   - Phase 1 (SplitBrainGateV1) — FLIPPED (no config flag): the composable dangerous-action gate. Machinery +
//     activation-hardening in place and tested — full proof carried+validated for
//     promote/ApplyLB/restore, relocation token-bound proof, promote crash-idempotent
//     step resume, token-gated per-peer WAL proof replication PLUS a peer-only
//     sensitive anti-entropy convergence net (both monotone-merged), mint sites that
//     fresh-Ping the destination before stamping, marker presence forcing BOTH the
//     ExecutionGate and proof validation at execute sites, and a per-token durable
//     activation LATCH (partition fails closed, never reverts to legacy).
//   - Phase 2 (VIPDemoteV1 + VIPReleaseProbeV1) — ADVERTISED, enforcement default-off (gated by
//     enforcement.vip_self_demote / enforcement.vip_proof_reclaim): minority VIP self-demotion + majority
//     proof-gated reclaim, DECOUPLED from the watchdog. VIPDemoteV1 (minority): an isolated
//     (quorum-lost) LB host stops keepalived + removes its own VIP address — WITHOUT a
//     hardware watchdog. VIPReleaseProbeV1 (majority trust): peers reclaim a VIP only on a
//     release proof — a by-VIP absence answer (direct CheckVIPParticipant or relayed) trusted
//     ONLY from a host advertising this token. A watchdog is an OPTIONAL backstop for one
//     corner: if the demote can't be CONFIRMED and a verified watchdog is armed the node
//     self-fences; if there's no verified self-fence it keeps retrying + raises HA-degraded,
//     and the majority stays in the safe gap (no reclaim without a release/fence proof — a
//     VIP outage, not a takeover). Warmup never demotes; a
//     sub-threshold blip never demotes (monotonic hysteresis); the startup-validated
//     timing invariant keeps the isolated side finishing before any majority reclaim.
//     Covers the daemon-alive gossip-partition case. DOCUMENTED GAPS (per plan, tied to
//     later phases): automatic majority reclaim across an UNREACHABLE holder needs a
//     real fence proof OR a verified absence proof (later phases) — until then it's an
//     intentional availability degradation (VIP down + alert), and a data-plane-only
//     partition (gRPC/gossip healthy but VRRP split) needs a VIP-conflict detector
//     (Phase-6 follow-up).
//
// Advertising is done for all implemented tokens; ENABLING each (setting its config
// flag in prod) is the staged step, gated per token on its own ephemeral-partition
// validation. Once advertised, enforcement activates only after EVERY
// enforcement-relevant member advertises it (fresh Ping), it latches, AND the config
// flag is on.
// OPERATOR NOTE: with the gate enforced, a 2-worker cluster with NO witness refuses
// automated failover (even-worker + no-witness blocks HA — deliberate); add a witness or
// accept the trade-off. Validate on an ephemeral partition before flipping in prod.
//
// DE-ADVERTISING IS NOT A KILL SWITCH once a node has latched. Removing the token
// from `supported` stops NEW activation, but Enforced() first honors the durable
// per-token marker (<dataDir>/split_brain_activated.<token>) and returns true from
// it before consulting current advertised support — the whole point of the
// fail-closed latch (a partition mustn't silently re-open the legacy path).
//
// KILL SWITCH (the modern way — DO NOT delete marker files): every FLIPPABLE token
// is gated `configFlag && Enforced/Latched` at its
// decision site (auth.strict_mtls_identity/forwarded_identity, and
// enforcement.{safe_fence_default,lww_skew_guard,vip_self_demote,vip_proof_reclaim}).
// The config flag is authoritative for enforcement AND recovery: set it false +
// restart and enforcement stops regardless of the latch marker. Deleting a marker
// file to "stand down" is retired — it confuses the state machine (the HA monitor
// re-establishes the latch while the flag is on and the cluster is healthy).
//
// The MANDATORY tokens are the exception and they are listed in one place, in
// mandatory below — read it rather than trusting any prose, here or elsewhere,
// that names a single one. A mandatory token has no config flag because it does
// not state a policy an operator chooses; it states a FACT about this binary,
// and letting an operator misreport that fact is how a cluster corrupts itself.
//
// Standing one down therefore differs per token and none has a config flag
// to turn off:
//
//   - split_brain_gate_v1 flips via `supported` alone, so marker deletion
//     remains its sole stand-down.
//
//   - lease_term_ledger_v1 has no stand-down at all, deliberately. Deleting its
//     marker does nothing lasting, because the HA monitor re-establishes the
//     latch the moment the fleet is uniform and there is no flag to stop it.
//
//     ROLLING A HOST BACK DOES NOT STOP MINTING. This comment used to say it
//     did — "which the latch already reacts to, since it is ReplicationGated
//     and so consults every host still receiving replication" — and that is
//     false of the function the mint gate actually calls. wireLeaseTermLedgerGate
//     uses Checker.DurablyLatched, which reads the persisted activation markers
//     and never consults current peer support, BY DESIGN: a fail-closed latch
//     must not re-open the legacy path when a peer goes away. So a host dropped
//     below this build stops nothing, the latched nodes keep minting statement
//     shapes it cannot resolve, and an unregistered shape back-pressures its
//     whole replication stream. The host rolled back to regain control is the
//     one that stops replicating.
//
//     What an operator can stop is anything ACTING on the terms:
//     enforcement.lease_term is a real flag and is authoritative for
//     enforcement and recovery both. Terms are additive audit facts that
//     nothing reads until it is on, so that is the lever an incident wants.
//     TestDurablyLatchedIsMonotone pins the behaviour this paragraph describes.
//
//   - credentials_split_v1 has no stand-down either. A binary rolled back
//     below it enters WAL quarantine and emits no replicated writes until it
//     is upgraded again or reseeded, and it cannot decode the credential
//     tables' shapes latched peers keep sending. This release dual-writes, so
//     every old column still holds the current value: the rolled-back reader
//     still validates tokens, checks passwords and fences, and upgrading
//     again loses nothing. The irreversible step —
//     clearing the old columns — is deliberately NOT in this release; it
//     comes with a second token in a later one
//     (docs/design/credentials-clear.md).
//
//   - host_membership_split_v1 has no stand-down either, and the same
//     rollback shape as credentials_split_v1: a binary rolled back below it
//     enters WAL quarantine, and cannot decode the host_membership statements
//     latched peers keep sending. Because this release dual-writes state and
//     isolation to host_membership AND the old hosts columns, the rolled-back
//     reader still reads the current state, voter set and isolation, and
//     upgrading again loses nothing. Retiring the old columns is a later
//     release's step (docs/design/host-membership-retire-old-columns.md).
//
//   - failover_scope_v1 has no stand-down of its own: the policy it licenses
//     does. `lv cluster failover-scope cluster` returns every coordinator to
//     the cluster-wide quorum without touching the token. A binary rolled
//     back below it enters WAL quarantine, as below every latched token.
//
//   - voter_config_v1 has no flag, by design, and needs none: turning it off
//     on one node would make that node count a different majority from its
//     peers. The incident tools are decided changes, so every node moves at the
//     same generation: `lv cluster voter rm` / `add` to repair the membership,
//     `lv host rm --dead` for a voter that is fenced and gone for good,
//     `lv cluster voter force-reconfigure` when a majority is gone for good,
//     and `lv cluster voter reset` to return the whole cluster to the derived
//     set (docs/design/recovery-claims.md §3.12, §4.2, §4.3, §4.6). A binary
//     rolled back below it after it has latched enters WAL quarantine, as
//     below every latched token, whether or not a voter generation exists —
//     reset is not a rollback tool. Deleting its marker does nothing lasting:
//     the HA monitor re-establishes the latch the moment the fleet is
//     uniform. The claim tables and the adopted generation survive a
//     stand-down of enforcement.recovery_claim, which is the point: promise
//     history stays unbroken.
//
//   - claim_incarnation_v1 has no flag either: it says what format this
//     build's voters keep, and a coordinator relies on every voter keeping it.
//     It changes how a claim is KEYED, not whether anything is enforced, so
//     enforcement.recovery_claim remains the stand-down for claims as a
//     whole. A binary rolled back below it after it has latched enters WAL
//     quarantine, as below every latched token; its legacy claim table is
//     intact, and the incarnation-scoped one is left unread until it is
//     upgraded again.
//
// recovery_claim_v1 is NOT mandatory and HAS a flag, enforcement.recovery_claim,
// which is its stand-down: false on every node and a restart returns recovery
// authorization to the pre-claim behaviour; voters keep answering and keep
// their tables. A PARTIAL stand-down is the hazard the token is withheld to
// prevent (a flag-off node is the uncertified second owner). A node that has
// latched the token and turned its flag off reports it in
// PingResponse.not_enforcing, and its enforcing peers raise ha_degraded
// (unsupported_member) because it no longer advertises the token.
var supported = []string{
	SplitBrainGateV1,
	// Advertised so the cluster can latch these; enforcement stays inert until the
	// matching config kill-switch is set true (see EnforcementConfig / AuthConfig).
	// Advertising a token means "this build SUPPORTS the feature", NOT "this node is
	// currently enforcing it".
	SafeFenceDefaultV1,
	LWWSkewGuardV1,
	HLCLwwV1,
	VIPDemoteV1,
	VIPReleaseProbeV1,
	StrictMTLSIdentityV1,
	ForwardedIdentityV1,
	// SharedStorageFenceV1 stays UNCONDITIONAL despite gating a corruption
	// hazard, which is not the contradiction it looks like: the guarantee is
	// enforced where the transfer is CREATED, so no node relies on a peer
	// enforcing it. The grpcapi advertisement filter carries the full reasoning
	// and what withholding it would cost.
	SharedStorageFenceV1,
	RBACRealmV1,
	OperationProtocolV1,
	CapacityAdmissionV1,
	LiveResizeV1,
	CanonicalIdentityV1,
	HardwareV2,
	ProjectAuthorityV1,
	AuditSignatureV1,
	NetBoxIPAMV1,
	// NetBoxMirrorV1 is advertised CONDITIONALLY on netbox.mirror_inventory,
	// like OperationProtocolV1: the mirror sweep runs on ONE node under the
	// `netbox` leader lease, so a cluster that latched across a node which will
	// never mirror would have its inventory appear and disappear with
	// leadership. Withholding advertisement while the flag is off keeps the
	// cluster from latching until every node has opted in.
	NetBoxMirrorV1,
	// VMReplaceV1 is advertised CONDITIONALLY on enforcement.vm_replace (see the
	// grpcapi advertisement filter): the transition installs new receiver semantics,
	// so the latch must require CONFIG uniformity, not just a uniform build.
	VMReplaceV1,
	// OwnerEpochV1 is advertised CONDITIONALLY: enforcement.owner_epoch on AND
	// the node.s backfill readiness (no owned workload at epoch 0) — see the
	// grpcapi advertisement filter.
	OwnerEpochV1,
	// LeaseTermLedgerV1 is advertised UNCONDITIONALLY: it has no config flag, and
	// its whole purpose is to tell peers "this build understands the term
	// ledger's statement shapes". Withholding it on a flag would keep the latch
	// from forming on a fleet that is fully rolled.
	LeaseTermLedgerV1,
	// CredentialsSplitV1 is advertised UNCONDITIONALLY, for the same reason as
	// LeaseTermLedgerV1: it says "this build decodes the credential tables'
	// statement shapes and reads a credential from them", a fact no flag should
	// be able to misreport, and a flag would keep the latch from forming on a
	// fully rolled fleet.
	CredentialsSplitV1,
	// HostMembershipSplitV1 is advertised UNCONDITIONALLY, for the same reason:
	// it says "this build decodes host_membership's statement shapes and reads
	// state and isolation from it", a fact about the binary.
	HostMembershipSplitV1,
	// FailoverScopeV1 is advertised UNCONDITIONALLY: it says "this build
	// decodes cluster_policies and honours failover_scope", a fact about the
	// binary. The policy is the row, not a flag.
	FailoverScopeV1,
	// VoterConfigV1 is mandatory but advertised only when READY — this node
	// commits a promise durably (synchronous=FULL) and can sign an accept. See
	// grpcapi.VoterConfigReadiness. Readiness is a fact about this node, not a
	// policy, so it is not a flag either.
	VoterConfigV1,
	// ClaimIncarnationV1 is advertised UNCONDITIONALLY: it says "this build
	// keys claims by incarnation and seals the legacy key", a fact about the
	// binary.
	ClaimIncarnationV1,
	// RecoveryClaimV1 is advertised CONDITIONALLY: enforcement.recovery_claim
	// (default on) on AND this node ready (split_brain_gate_v1 latched, voter_config_v1
	// ready). Withheld while the flag is off because every flag-on node relies
	// on every peer honouring it — see RecoveryClaimV1 and
	// grpcapi.RecoveryClaimReadiness.
	RecoveryClaimV1,
	// PartitionPauseV1 is advertised CONDITIONALLY on
	// enforcement.partition_pause (default on): every flag-on coordinator
	// relies on the host it fences pausing, so the latch must mean every
	// voter has the flag on. See PartitionPauseV1.
	PartitionPauseV1,
	// LeaseTermV1 is advertised CONDITIONALLY: enforcement.lease_term on AND
	// this node ready (>= 3 voting-eligible hosts, readable ledger,
	// SplitBrainGateV1 latched, LeaseTermLedgerV1 durably latched — a node that
	// cannot mint a term must not advertise readiness to enforce on one). See
	// grpcapi.LeaseTermReadiness.
	LeaseTermV1,
	// IsolationEpochV1 is advertised CONDITIONALLY on enforcement.isolation_epoch,
	// like OperationProtocolV1: the regime REFUSES a peer's replication, so the
	// fleet-wide latch must require CONFIG uniformity — a node that isn't
	// enforcing would keep accepting the isolated node's state and re-inject it,
	// defeating the quarantine. Withholding advertisement while the flag is off
	// keeps the cluster from latching until every node has opted in.
	IsolationEpochV1,
}

// all is every capability token litevirt knows about (across phases), regardless
// of whether THIS build advertises it. Used to pre-load per-token durable
// activation latches at startup.
var all = []string{SplitBrainGateV1, VIPDemoteV1, VIPReleaseProbeV1, FenceEpochV1, OwnerEpochV1, SafeFenceDefaultV1, LWWSkewGuardV1, HLCLwwV1, StrictMTLSIdentityV1, ForwardedIdentityV1, SharedStorageFenceV1, RBACRealmV1, OperationProtocolV1, CapacityAdmissionV1, LiveResizeV1, CanonicalIdentityV1, HardwareV2, ProjectAuthorityV1, AuditSignatureV1, IsolationEpochV1, NetBoxIPAMV1, NetBoxMirrorV1, LeaseTermLedgerV1, CredentialsSplitV1, HostMembershipSplitV1, FailoverScopeV1, VoterConfigV1, ClaimIncarnationV1, RecoveryClaimV1, PartitionPauseV1, LeaseTermV1, VMReplaceV1}

// All returns a copy of every known capability token (all phases).
func All() []string {
	return append([]string(nil), all...)
}

// Supported returns a copy of the tokens this build advertises.
func Supported() []string {
	return append([]string(nil), supported...)
}

// replicationGated is the set of tokens whose latch is a claim about what peers
// can DECODE, rather than about what members agree to enforce.
//
// The distinction decides which peers must confirm the token before it latches,
// and getting it wrong is silent. An ordinary token gates a DECISION — a fence,
// a demote, a promote — so the members that must agree are the ones that vote,
// and health.VotingEligible is exactly right: a host in maintenance does not
// vote, and must not be able to hold a fencing decision hostage.
//
// A token in this set gates EMITTING a replicated statement shape that a
// previous-release peer has no ledger entry for. That is not a vote, it is a
// wire-format claim, and the peers it has to be true of are the ones this node
// REPLICATES TO. Those two sets are not the same: the replicator derives its
// targets from memberlist membership with no host-state filter, so a host in
// maintenance — the normal state for a host queued to be upgraded next — is
// skipped by the voting sweep while still receiving every statement we write.
// A latch formed over the voting set alone therefore proved nothing about the
// peer it was meant to wait for, and emitting the new shape stalled that peer's
// replication watermark, which head-of-line blocks the stream into it. That is
// the precise outage these tokens exist to prevent.
//
// Membership is the right set rather than "every host that is not
// decommissioned", because a host outside memberlist receives nothing and so
// cannot stall — whereas requiring an unreachable host to confirm would keep
// the latch from ever forming, and the fail-closed side of these tokens costs
// availability of the feature, not of the cluster.
var replicationGated = map[string]bool{
	LeaseTermLedgerV1: true,
	// Confirmed against every replication recipient: the
	// credential tables' shapes must be decodable by every host we stream to —
	// a maintenance host on the previous build still receives every statement.
	// (The old-column clear that also needs this is a later release's token.)
	CredentialsSplitV1: true,
	// Confirmed against every replication recipient: host_membership's shapes
	// must be decodable by every host we stream to, a maintenance host on the
	// previous build included.
	HostMembershipSplitV1: true,
	// Confirmed against every replication recipient: cluster_policies' shapes
	// must be decodable by every host we stream to.
	FailoverScopeV1: true,
	// Confirmed against every replication recipient: voter_configs' shapes
	// must be decodable by every host we stream to.
	VoterConfigV1: true,
	// Confirmed against every replication recipient: a v2 accept inside a
	// replicated certificate must be verifiable by every host we stream to.
	ClaimIncarnationV1: true,
	// Confirmed against every replication recipient: the claim_certificate
	// column's statement shapes on runtime_action_proofs must be decodable by
	// every host we stream to. Not mandatory: the flag is the opt-in.
	RecoveryClaimV1: true,
}

// ReplicationGated reports whether token's latch must be confirmed by every
// peer this node replicates to, not merely by every voting-eligible member.
// See replicationGated for why the two sets differ.
func ReplicationGated(token string) bool {
	return replicationGated[token]
}

// mandatory is every token with NO config kill switch — the ones enforced on
// every cluster with no operator opt-in.
//
// THE set, in one place. It was previously spelled out in prose in four
// (capabilities.go's KILL SWITCH block, grpcapi's tokenEnabled,
// docs/diagnostics.md, CLAUDE.md), three of which still claimed
// split_brain_gate_v1 was the only one long after it stopped being true, and
// one of which named a token that is not in this set at all. Prose copies of a
// set do not stay true; a declaration does.
//
// Adding an entry is a decision to be made in the open. It means the token
// latches on every cluster, drives enforcement with no way for an operator to
// decline, and has no config flag to turn off in an incident — so it is only
// appropriate for a token stating a FACT about the binary (what wire shapes it
// can decode, what merge resolver it carries) rather than a policy.
var mandatory = map[string]bool{
	SplitBrainGateV1:  true,
	LeaseTermLedgerV1: true,
	// A fact about the binary (it decodes and reads the credential tables),
	// not a policy. See CredentialsSplitV1 for why a flag would leave the
	// secrets in the public dump forever.
	CredentialsSplitV1: true,
	// A fact about the binary (it decodes and reads host_membership), not a
	// policy. See HostMembershipSplitV1.
	HostMembershipSplitV1: true,
	// A fact about the binary (it decodes cluster_policies and honours
	// failover_scope). The policy is the replicated row. See FailoverScopeV1.
	FailoverScopeV1: true,
	// A fact about the binary (it decodes voter_configs and answers the claim
	// RPCs durably), not a policy — and a flag would let one node count a
	// different majority from its peers. Its stand-down is the decided
	// `lv cluster voter reset`; see the KILL SWITCH notes above `supported`.
	VoterConfigV1: true,
	// A fact about the binary (it keys claims by incarnation and seals the
	// legacy key), and a coordinator relies on every voter keeping that
	// format. See ClaimIncarnationV1.
	ClaimIncarnationV1: true,
}

// Mandatory reports whether token is enforced with no config kill switch.
func Mandatory(token string) bool {
	return mandatory[token]
}

// MandatoryTokens lists the no-kill-switch tokens, sorted for stable output.
func MandatoryTokens() []string {
	out := make([]string, 0, len(mandatory))
	for tok := range mandatory {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// RetiredCanonicalRegistryV1 is the token of the first, unfinished canonical
// registry-credential design. v1.4.0 shipped it advertised behind
// enforcement.canonical_registry, and its only effect once latched was that a
// receiver ACCEPTED a replicated canonical upsert. Nothing in production ever
// wrote that shape. It was retired on 2026-10-04 so a durable one-way latch was
// not spent on a design whose writer had not shipped. The feature is planned in
// docs/design/canonical-registry-credentials.md, and ships under a NEW token:
// this name is never reused, because a cluster that latched it holds a marker
// that would otherwise read as having latched the new contract.
const RetiredCanonicalRegistryV1 = "canonical_registry_v1"

// retired is every token an earlier build could latch that this build neither
// advertises, latches nor enforces. It is not in All(), so the checker does not
// load its marker and nothing reads it as latched.
//
// It exists for one reader: the capability-rollback preflight, which treats an
// activation marker for a token this build does not know as proof that a newer
// binary ran here, and quarantines the node. A retired token's marker is the
// opposite — proof that an OLDER binary ran here — so without this set, upgrading
// a node that had latched the token would WAL-quarantine it.
//
// Removing a token from All() therefore means adding it here, in the same
// change. An entry is never removed: a marker outlives every binary that wrote it.
var retired = map[string]bool{
	RetiredCanonicalRegistryV1: true,
}

// Retired reports whether token is a retired token: one an earlier build could
// latch, which this build recognises and ignores.
func Retired(token string) bool {
	return retired[token]
}

// RetiredTokens lists the retired tokens, sorted for stable output.
func RetiredTokens() []string {
	out := make([]string, 0, len(retired))
	for tok := range retired {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// Has reports whether tokens contains want.
func Has(tokens []string, want string) bool {
	for _, t := range tokens {
		if t == want {
			return true
		}
	}
	return false
}
