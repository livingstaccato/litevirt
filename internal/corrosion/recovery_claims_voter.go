package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// The voter's rules (docs/design/recovery-claims.md §3.5–§3.7, §3.11, §4.4).
//
// Every step is one ExecuteLocal transaction: the membership check, the ballot
// check and the write read one consistent snapshot, and the reply is built only
// after the commit returns — a voter never answers "promised" or "accepted"
// unless the state behind the answer would survive a crash at that instant. A
// refusal writes nothing. Promises and accepts are kept forever and never
// downgraded (§9 Q6).

// Refusal reasons a voter answers with. The owner-probe pair are the design's
// recovery_claim_owner_reachable / recovery_claim_source_mismatch.
const (
	RefusalWrongGeneration     = "recovery_claim_wrong_generation"
	RefusalNotMember           = "recovery_claim_not_member"
	RefusalIncarnationMismatch = "recovery_claim_incarnation_mismatch"
	RefusalNoVoterConfig       = "recovery_claim_no_voter_config"
	RefusalSealed              = "recovery_claim_sealed"
	RefusalBallotStale         = "recovery_claim_ballot_stale"
	RefusalValueConflict       = "recovery_claim_value_conflict"
	RefusalInvalidValue        = "recovery_claim_invalid_value"
	RefusalOwnerReachable      = "recovery_claim_owner_reachable"
	RefusalSourceMismatch      = "recovery_claim_source_mismatch"
	RefusalProbeUnavailable    = "recovery_claim_probe_unavailable"
	// RefusalSupersedeUnproven: a Prepare past attempt 0 whose evidence that the
	// value decided at the previous attempt will never execute did not check out
	// here (§3.12) — no abandonment by its destination that verifies, and not
	// all of "fenced proof-grade, no longer a member, revoked" in this voter's
	// own replica. Retryable: replica lag delays a supersede, never admits one.
	RefusalSupersedeUnproven = "recovery_claim_supersede_unproven"
	// RefusalLegacyKeySealed: a Prepare or Accept at a LEGACY workload key —
	// one with no incarnation, from a coordinator that has not latched
	// claim_incarnation_v1 yet — at a (kind, name, epoch, attempt) this voter
	// has already answered at an incarnation-scoped key. Its promise there
	// reported its legacy state and sealed the legacy key, so a value accepted
	// at the legacy key now could be missed by the incarnation-scoped decision
	// (§10 item 37). Retryable: the coordinator latches the token and claims
	// at the incarnation-scoped key.
	RefusalLegacyKeySealed = "recovery_claim_legacy_key_sealed"
	// RefusalFeatureUnrecorded: a Prepare or Accept at a LUN key at a voter
	// whose replica does not hold iscsi_lun_claim's used record yet — a voter
	// added after the first use, before the record reached it. Its LUN state
	// would be state a rollback below the release could not see it holds,
	// unquarantined (switch review M-3). Retryable: the record replicates.
	RefusalFeatureUnrecorded = "recovery_claim_feature_unrecorded"
)

// ClaimVoterState is one voter's recorded state for a key.
type ClaimVoterState struct {
	Key              ClaimKey
	Promised         Ballot
	Accepted         Ballot // zero when nothing accepted
	Value            *ClaimValue
	ValueDigest      string
	Accept           *ClaimAccept // this voter's signed accept; nil for imported state
	ConfigGeneration int64
}

// PrepareResult is a voter's answer to Prepare.
type PrepareResult struct {
	Promised       bool
	PromisedBallot Ballot // what this voter has promised after the call
	State          ClaimVoterState
	// Legacy is, on a promise at an incarnation-scoped key, what this voter
	// accepted at the same key's LEGACY form, or nil when it accepted nothing
	// there. The promise is durable before it is reported, and from then on
	// this voter refuses the legacy key (RefusalLegacyKeySealed), so the
	// report is final (§10 item 37).
	Legacy      *ClaimVoterState
	Voter       string
	Incarnation string
	Refusal     string
	Detail      string
}

// AcceptResult is a voter's answer to Accept.
type AcceptResult struct {
	Accepted       bool
	PromisedBallot Ballot
	Accept         *ClaimAccept
	Voter          string
	Refusal        string
	Detail         string
}

// OwnerProbe reports whether this voter can reach host over the peer
// transport, with a detail naming what answered (§3.5.1). Injected by the
// server; nil refuses every workload accept (fail closed).
type OwnerProbe func(ctx context.Context, host string) (reached bool, detail string)

// voterStanding is this voter's membership as of one transaction.
type voterStanding struct {
	me          string
	incarnation string
	adopted     int64
	cfg         *VoterConfig // nil when nothing adopted
	sealed      bool         // accepted a voter_config value at key `adopted`
	// lunUsed: this replica holds iscsi_lun_claim's used record (any state,
	// as ReleaseFeatureUsed counts it). Read only for a LUN key.
	lunUsed bool
}

func readStandingTx(ctx context.Context, tx *LocalTx, me string) (voterStanding, error) {
	st := voterStanding{me: me}
	rows, err := tx.Query(ctx, `SELECT COALESCE(MAX(generation), 0) AS g FROM local_voter_adoption`)
	if err != nil {
		return st, err
	}
	if len(rows) > 0 {
		st.adopted = rows[0].Int64("g")
	}
	if st.adopted > 0 {
		rows, err := tx.Query(ctx, `SELECT `+voterConfigCols+` FROM voter_configs WHERE generation = ? AND deleted_at IS NULL`, st.adopted)
		if err != nil {
			return st, err
		}
		if len(rows) == 0 {
			return st, fmt.Errorf("adopted voter generation %d has no voter_configs row", st.adopted)
		}
		if st.cfg, err = scanVoterConfig(rows[0]); err != nil {
			return st, err
		}
	}
	rows, err = tx.Query(ctx, `SELECT incarnation FROM local_voter_incarnation WHERE id = 1`)
	if err != nil {
		return st, err
	}
	if len(rows) == 0 || rows[0].String("incarnation") == "" {
		return st, fmt.Errorf("no voter incarnation recorded")
	}
	st.incarnation = rows[0].String("incarnation")
	rows, err = tx.Query(ctx, `SELECT 1 AS one FROM local_recovery_claims
		WHERE target_kind = ? AND owner_epoch = ? AND accepted_round > 0 LIMIT 1`,
		ClaimKindVoterConfig, st.adopted)
	if err != nil {
		return st, err
	}
	st.sealed = len(rows) > 0
	if !st.sealed {
		// A survivor of a forced reconfiguration seals its generation by force
		// (§4.6 step 1): no majority of it is left to decide a change of it.
		rows, err = tx.Query(ctx, `SELECT 1 AS one FROM local_voter_seals WHERE generation = ?`, st.adopted)
		if err != nil {
			return st, err
		}
		st.sealed = len(rows) > 0
	}
	return st, nil
}

// readStandingForKeyTx is readStandingTx, plus — for a LUN key — whether this
// replica holds iscsi_lun_claim's used record, read in the same transaction
// as the step it admits.
func readStandingForKeyTx(ctx context.Context, tx *LocalTx, me string, key ClaimKey) (voterStanding, error) {
	st, err := readStandingTx(ctx, tx, me)
	if err != nil || !key.IsLUN() {
		return st, err
	}
	token := capabilities.ReleaseToken
	if info, ok := capabilities.LookupFeature(capabilities.FeatureISCSILUNClaim); ok {
		token = info.Token
	}
	rows, err := tx.Query(ctx, `SELECT 1 AS one FROM cluster_policies WHERE key = ?`,
		releaseFeatureKey(token, string(capabilities.FeatureISCSILUNClaim)))
	if err != nil {
		return st, err
	}
	st.lunUsed = len(rows) > 0
	return st, nil
}

// admit is the membership half of every Prepare and Accept (§3.5, §3.11, §4).
// v is nil for a Prepare.
func (st voterStanding) admit(key ClaimKey, gen int64, v *ClaimValue) (string, string) {
	if err := key.Validate(); err != nil {
		return RefusalInvalidValue, err.Error()
	}
	if gen != st.adopted {
		return RefusalWrongGeneration, fmt.Sprintf("%s has adopted voter generation %d, not %d", st.me, st.adopted, gen)
	}
	memberCheck := func(members *VoterConfig) (string, string) {
		m, ok := members.Member(st.me)
		if !ok {
			return RefusalNotMember, fmt.Sprintf("%s is not a member of voter generation %d", st.me, members.Generation)
		}
		if m.Incarnation != st.incarnation {
			// §3.11: a voter that lost its state under its old identity
			// abstains. Answering would let it promise against a promise it
			// forgot.
			return RefusalIncarnationMismatch, fmt.Sprintf(
				"%s abstains: its claim state is incarnation %s but it was admitted as %s (re-imaged or "+
					"reseeded?); heal with `lv cluster voter rm %s` then `lv cluster voter add %s`",
				st.me, short(st.incarnation), short(m.Incarnation), st.me, st.me)
		}
		return "", ""
	}
	if key.IsVoterConfig() {
		if key.OwnerEpoch != st.adopted {
			return RefusalWrongGeneration, fmt.Sprintf("%s decides generation %d, and %s has adopted %d",
				key, key.OwnerEpoch+1, st.me, st.adopted)
		}
		if st.cfg.Explicit() {
			if r, d := memberCheck(st.cfg); r != "" {
				return r, d
			}
		}
		if v == nil {
			return "", ""
		}
		if v.Config == nil || v.Proof != nil || v.LUN != nil || v.Automation != nil || v.SourceHost != "" || v.LeaseTerm != nil {
			return RefusalInvalidValue, "a voter_config key decides a voter config"
		}
		if !st.cfg.Explicit() {
			// Genesis (or the first generation after a reset): unanimous among
			// the proposed members, so this voter must be one of them, with the
			// incarnation it actually has.
			next := &VoterConfig{VoterConfigValue: *v.Config}
			if r, d := memberCheck(next); r != "" {
				return r, d
			}
		}
		if err := ValidateVoterChange(st.cfg, *v.Config); err != nil {
			return RefusalInvalidValue, err.Error()
		}
		return "", ""
	}
	// A workload key, a LUN key or a lease-term key.
	switch {
	case st.cfg.Explicit():
		if r, d := memberCheck(st.cfg); r != "" {
			return r, d
		}
	default:
		return RefusalNoVoterConfig, fmt.Sprintf("%s has adopted no member voter generation", st.me)
	}
	if st.sealed {
		// §4.4 rule 1: deciding g+1 seals g for workload keys.
		return RefusalSealed, fmt.Sprintf("%s has accepted a change of voter generation %d and no longer "+
			"votes on recoveries under it; retry once generation %d is adopted", st.me, st.adopted, st.adopted+1)
	}
	if key.IsLUN() {
		if !st.lunUsed {
			// The first use has every voter acknowledge the used record
			// before any LUN key is proposed; a voter without it (added since,
			// and not caught up) would hold LUN state that a rollback below
			// the release could not see, unquarantined (switch review M-3).
			return RefusalFeatureUnrecorded, fmt.Sprintf("%s does not hold the %s used record yet, and takes no "+
				"LUN allocation before it does; retry once it has replicated", st.me, capabilities.FeatureISCSILUNClaim)
		}
	}
	return validateGenerationClaimValue(key, v)
}

// validateGenerationClaimValue checks the immutable value binding, without
// current membership, sealing, release-use or owner-probe requirements. Import
// must preserve an old acceptance even when those live checks have changed.
func validateGenerationClaimValue(key ClaimKey, v *ClaimValue) (string, string) {
	if v == nil {
		return "", ""
	}
	if key.IsAutomation() {
		if err := validateAutomationValue(key, *v); err != nil {
			return RefusalInvalidValue, err.Error()
		}
		return "", ""
	}
	if v.Automation != nil {
		return RefusalInvalidValue, "automation value at another kind"
	}
	if key.IsLeaseTerm() {
		l := v.LeaseTerm
		if l == nil || v.Proof != nil || v.Config != nil || v.LUN != nil || v.Automation != nil || v.SourceHost != "" {
			return RefusalInvalidValue, "a lease_term key decides a lease term's holder"
		}
		if l.Key != key.TargetName || l.Term != key.OwnerEpoch {
			return RefusalInvalidValue, fmt.Sprintf("value holds %s term %d, key is %s", l.Key, l.Term, key)
		}
		if l.Holder == "" {
			return RefusalInvalidValue, "a lease-term value names its holder"
		}
		return "", ""
	}
	if key.IsLUN() {
		l := v.LUN
		if l == nil || v.Proof != nil || v.Config != nil || v.LeaseTerm != nil || v.SourceHost != "" {
			return RefusalInvalidValue, "a LUN key decides a LUN allocation"
		}
		if l.LUN != key.TargetName || l.Generation != key.OwnerEpoch {
			return RefusalInvalidValue, fmt.Sprintf("value allocates %s@%d, key is %s", l.LUN, l.Generation, key)
		}
		if l.ClaimID == "" || l.VMID == "" || l.VMName == "" || l.Disk == "" || l.Host == "" {
			return RefusalInvalidValue, "a LUN value names its claim, VM, disk and host"
		}
		return "", ""
	}
	if v.Proof == nil || v.Config != nil || v.LUN != nil || v.LeaseTerm != nil {
		return RefusalInvalidValue, "a workload key decides a proof"
	}
	p := v.Proof
	if p.TargetKind != key.TargetKind || p.TargetName != key.TargetName || p.OwnerEpoch != i64(key.OwnerEpoch) {
		return RefusalInvalidValue, fmt.Sprintf("value binds %s/%s@%s, key is %s",
			p.TargetKind, p.TargetName, p.OwnerEpoch, key)
	}
	if p.ID == "" || p.DestHost == "" || v.SourceHost == "" {
		return RefusalInvalidValue, "a workload value names its proof, destination and source"
	}
	return "", ""
}

const claimRowCols = `promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,
	accepted_nonce, value_json, value_digest, accept_json, config_generation`

func loadClaimRowTx(ctx context.Context, tx *LocalTx, key ClaimKey) (ClaimVoterState, bool, error) {
	if key.IsAutomation() {
		if err := key.Validate(); err != nil {
			return ClaimVoterState{}, false, err
		}
	}
	var rows []Row
	var err error
	if key.Incarnation == "" {
		rows, err = tx.Query(ctx, `SELECT `+claimRowCols+` FROM local_recovery_claims
			WHERE target_kind = ? AND target_name = ? AND owner_epoch = ? AND attempt = ?`,
			key.TargetKind, key.TargetName, key.OwnerEpoch, key.Attempt)
	} else {
		rows, err = tx.Query(ctx, `SELECT `+claimRowCols+` FROM local_incarnation_claims
			WHERE target_kind = ? AND target_name = ? AND incarnation = ? AND owner_epoch = ? AND attempt = ?`,
			key.TargetKind, key.TargetName, key.Incarnation, key.OwnerEpoch, key.Attempt)
	}
	if err != nil || len(rows) == 0 {
		return ClaimVoterState{Key: key}, false, err
	}
	st, err := scanClaimRow(key, rows[0])
	return st, err == nil, err
}

func scanClaimRow(key ClaimKey, r Row) (ClaimVoterState, error) {
	st := ClaimVoterState{
		Key:              key,
		Promised:         Ballot{Round: uint64(r.Int64("promised_round")), Coordinator: r.String("promised_coord"), Nonce: r.Bytes("promised_nonce")},
		Accepted:         Ballot{Round: uint64(r.Int64("accepted_round")), Coordinator: r.String("accepted_coord"), Nonce: r.Bytes("accepted_nonce")},
		ValueDigest:      r.String("value_digest"),
		ConfigGeneration: r.Int64("config_generation"),
	}
	if len(st.Promised.Nonce) == 0 {
		st.Promised.Nonce = nil
	}
	if len(st.Accepted.Nonce) == 0 {
		st.Accepted.Nonce = nil
	}
	if s := r.String("value_json"); s != "" {
		var v ClaimValue
		if err := decodeClaimValue(key, s, &v); err != nil {
			return st, fmt.Errorf("claim %s: stored value: %w", key, err)
		}
		st.Value = &v
	}
	if s := r.String("accept_json"); s != "" {
		var a ClaimAccept
		if err := json.Unmarshal([]byte(s), &a); err != nil {
			return st, fmt.Errorf("claim %s: stored accept: %w", key, err)
		}
		st.Accept = &a
	}
	if err := ValidateAutomationState(st); err != nil {
		return ClaimVoterState{}, err
	}
	return st, nil
}

// upsertClaimRowSQL writes a voter's whole state for a key. The row only ever
// moves forward: every caller has already checked the ballot order.
const upsertClaimRowSQL = `INSERT INTO local_recovery_claims
	(target_kind, target_name, owner_epoch, attempt, promised_round, promised_coord, promised_nonce,
	 accepted_round, accepted_coord, accepted_nonce, value_json, value_digest, accept_json,
	 config_generation, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(target_kind, target_name, owner_epoch, attempt) DO UPDATE SET
	  promised_round = excluded.promised_round, promised_coord = excluded.promised_coord,
	  promised_nonce = excluded.promised_nonce, accepted_round = excluded.accepted_round,
	  accepted_coord = excluded.accepted_coord, accepted_nonce = excluded.accepted_nonce,
	  value_json = excluded.value_json, value_digest = excluded.value_digest,
	  accept_json = excluded.accept_json, config_generation = excluded.config_generation,
	  updated_at = excluded.updated_at`

// upsertIncarnationClaimRowSQL is upsertClaimRowSQL for an incarnation-scoped
// key (§10 item 37).
const upsertIncarnationClaimRowSQL = `INSERT INTO local_incarnation_claims
	(target_kind, target_name, incarnation, owner_epoch, attempt, promised_round, promised_coord, promised_nonce,
	 accepted_round, accepted_coord, accepted_nonce, value_json, value_digest, accept_json,
	 config_generation, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(target_kind, target_name, incarnation, owner_epoch, attempt) DO UPDATE SET
	  promised_round = excluded.promised_round, promised_coord = excluded.promised_coord,
	  promised_nonce = excluded.promised_nonce, accepted_round = excluded.accepted_round,
	  accepted_coord = excluded.accepted_coord, accepted_nonce = excluded.accepted_nonce,
	  value_json = excluded.value_json, value_digest = excluded.value_digest,
	  accept_json = excluded.accept_json, config_generation = excluded.config_generation,
	  updated_at = excluded.updated_at`

// legacyKeySealedTx reports whether key is a legacy workload key this voter
// has already answered at an incarnation-scoped form of (§10 item 37). Any
// incarnation seals it: the promise that wrote the row reported this voter's
// legacy state as final.
func legacyKeySealedTx(ctx context.Context, tx *LocalTx, key ClaimKey) (bool, error) {
	if !key.IsWorkload() || key.Incarnation != "" {
		return false, nil
	}
	rows, err := tx.Query(ctx, `SELECT 1 AS one FROM local_incarnation_claims
		WHERE target_kind = ? AND target_name = ? AND owner_epoch = ? AND attempt = ? LIMIT 1`,
		key.TargetKind, key.TargetName, key.OwnerEpoch, key.Attempt)
	return len(rows) > 0, err
}

func (c *Client) refuseSealedLegacyKey(key ClaimKey) (string, string) {
	return RefusalLegacyKeySealed, fmt.Sprintf("%s has answered %s at an incarnation-scoped key, which sealed its "+
		"legacy form here; claim it with its incarnation once claim_incarnation_v1 latches", c.hostName, key)
}

func saveClaimRowTx(ctx context.Context, tx *LocalTx, st ClaimVoterState) error {
	if err := ValidateAutomationState(st); err != nil {
		return err
	}
	if st.Key.IsAutomation() {
		if err := requireAutomationFull(ctx, tx); err != nil {
			return err
		}
	}
	var vj, aj string
	if st.Value != nil {
		b, err := json.Marshal(st.Value)
		if err != nil {
			return err
		}
		vj = string(b)
	}
	if st.Accept != nil {
		b, err := json.Marshal(st.Accept)
		if err != nil {
			return err
		}
		aj = string(b)
	}
	nonce := func(b []byte) []byte {
		if b == nil {
			return []byte{}
		}
		return b
	}
	k := st.Key
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if k.Incarnation != "" {
		_, err := tx.Exec(ctx, upsertIncarnationClaimRowSQL,
			k.TargetKind, k.TargetName, k.Incarnation, k.OwnerEpoch, k.Attempt,
			int64(st.Promised.Round), st.Promised.Coordinator, nonce(st.Promised.Nonce),
			int64(st.Accepted.Round), st.Accepted.Coordinator, nonce(st.Accepted.Nonce),
			vj, st.ValueDigest, aj, st.ConfigGeneration, now)
		return err
	}
	_, err := tx.Exec(ctx, upsertClaimRowSQL,
		k.TargetKind, k.TargetName, k.OwnerEpoch, k.Attempt,
		int64(st.Promised.Round), st.Promised.Coordinator, nonce(st.Promised.Nonce),
		int64(st.Accepted.Round), st.Accepted.Coordinator, nonce(st.Accepted.Nonce),
		vj, st.ValueDigest, aj, st.ConfigGeneration, now)
	return err
}

// ClaimPrepare is phase 1 at this voter (§3.5).
func (c *Client) ClaimPrepare(ctx context.Context, key ClaimKey, b Ballot, gen int64) (PrepareResult, error) {
	res := PrepareResult{Voter: c.hostName}
	if b.Round == 0 || b.Coordinator == "" {
		res.Refusal, res.Detail = RefusalInvalidValue, "a ballot has a round >= 1 and a coordinator"
		return res, nil
	}
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if r, err := c.admitAutomationTx(ctx, tx, key, b, gen, nil, nil, nil, nil, nil); err != nil {
			return err
		} else if r != "" {
			res.Refusal = r
			return nil
		}
		st, err := readStandingForKeyTx(ctx, tx, c.hostName, key)
		if err != nil {
			return err
		}
		res.Incarnation = st.incarnation
		if r, d := st.admit(key, gen, nil); r != "" {
			res.Refusal, res.Detail = r, d
			return nil
		}
		if sealed, err := legacyKeySealedTx(ctx, tx, key); err != nil {
			return err
		} else if sealed {
			res.Refusal, res.Detail = c.refuseSealedLegacyKey(key)
			return nil
		}
		row, _, err := loadClaimRowTx(ctx, tx, key)
		if err != nil {
			return err
		}
		res.State = row
		switch cmp := CompareBallots(row.Promised, b); {
		case cmp > 0:
			res.PromisedBallot = row.Promised
			res.Refusal = RefusalBallotStale
			res.Detail = fmt.Sprintf("%s has promised %s, above %s", c.hostName, row.Promised, b)
			return nil
		case cmp == 0:
			// The same Prepare again: the promise is already on disk.
		default:
			row.Promised = b
			if key.IsAutomation() && row.ConfigGeneration != gen {
				row.Accept = nil // a retained acceptance's signature binds its old generation
			}
			row.ConfigGeneration = gen
			if err := saveClaimRowTx(ctx, tx, row); err != nil {
				return err
			}
		}
		res.Promised = true
		res.PromisedBallot = b
		res.State = row
		if key.IsWorkload() && key.Incarnation != "" {
			// The incarnation-scoped row is on disk (written above, or by an
			// earlier step at this key), so the legacy key is sealed here from
			// this transaction on and what it holds is final.
			legacy, found, err := loadClaimRowTx(ctx, tx, key.Legacy())
			if err != nil {
				return err
			}
			if found && !legacy.Accepted.IsZero() && legacy.Value != nil {
				res.Legacy = &legacy
			}
		}
		return nil
	})
	if err != nil {
		return PrepareResult{}, err
	}
	return res, nil
}

var errClaimNeedsOwnerCheck = errors.New("claim value needs the owner check")

// errClaimNeedsSourceCheck is the owner check without the probe: for a value
// this voter already accepted at the legacy form of an incarnation-scoped key.
var errClaimNeedsSourceCheck = errors.New("claim value needs the source cross-check")

// ClaimAccept is phase 2 at this voter (§3.5, §3.5.1). probe is consulted only
// for a workload value this voter has not accepted before, and outside the
// transaction: it is network I/O and must not hold the database lock.
func (c *Client) ClaimAccept(ctx context.Context, key ClaimKey, b Ballot, v ClaimValue, gen int64,
	signer *ClaimSigner, probe OwnerProbe) (AcceptResult, error) {
	if key.IsAutomation() && isAutomationContinuityValue(v) {
		return c.claimAcceptContinuityRecovery(ctx, key, b, v, gen, signer, continuityLocal, ClaimCertificate{})
	}
	return c.claimAccept(ctx, key, b, v, gen, signer, probe, nil, nil, nil)
}

func (c *Client) claimAccept(ctx context.Context, key ClaimKey, b Ballot, v ClaimValue, gen int64,
	signer *ClaimSigner, probe OwnerProbe, owner *ownerAcceptPreparation, continuity *continuityAcceptPreparation, keyPrepared *keyAcceptPreparation) (AcceptResult, error) {
	return c.claimAcceptValue(ctx, key, b, v, gen, signer, probe, owner, continuity, keyPrepared, prepareKeyAcceptValue(v))
}

// Only this call's owned incoming parse may be reused. All live admission and
// commit checks still run, and retained rows are decoded independently.
func (c *Client) claimAcceptValue(ctx context.Context, key ClaimKey, b Ballot, v ClaimValue, gen int64,
	signer *ClaimSigner, probe OwnerProbe, owner *ownerAcceptPreparation, continuity *continuityAcceptPreparation, keyPrepared *keyAcceptPreparation, incoming *keyAcceptValue) (AcceptResult, error) {
	res := AcceptResult{Voter: c.hostName}
	var digest string
	var err error
	if incoming != nil {
		v, digest = incoming.value, incoming.digest
	} else {
		digest, err = v.Digest()
		if err != nil {
			res.Refusal, res.Detail = RefusalInvalidValue, err.Error()
			return res, nil
		}
	}
	if b.Round == 0 || b.Coordinator == "" {
		res.Refusal, res.Detail = RefusalInvalidValue, "a ballot has a round >= 1 and a coordinator"
		return res, nil
	}
	if signer == nil || signer.Name() != c.hostName {
		return res, fmt.Errorf("no claim signing key for %s", c.hostName)
	}
	if key.IsAutomation() && signer.key == nil {
		return res, fmt.Errorf("no claim signing key for %s", c.hostName)
	}
	if key.IsAutomation() && !signer.AutomationTransportEligible() {
		res.Refusal = RefusalAutomationUnavailable
		return res, nil
	}
	ownerChecked := false
	for {
		res = AcceptResult{Voter: c.hostName}
		err := c.executeLocal(ctx, func(tx *LocalTx) error {
			if r, err := c.admitAutomationTx(ctx, tx, key, b, gen, &v, owner, continuity, keyPrepared, incoming); err != nil {
				return err
			} else if r != "" {
				res.Refusal = r
				return nil
			}
			st, err := readStandingForKeyTx(ctx, tx, c.hostName, key)
			if err != nil {
				return err
			}
			if r, d := st.admit(key, gen, &v); r != "" {
				res.Refusal, res.Detail = r, d
				return nil
			}
			if sealed, err := legacyKeySealedTx(ctx, tx, key); err != nil {
				return err
			} else if sealed {
				res.Refusal, res.Detail = c.refuseSealedLegacyKey(key)
				return nil
			}
			row, _, err := loadClaimRowTx(ctx, tx, key)
			if err != nil {
				return err
			}
			if CompareBallots(row.Promised, b) > 0 {
				res.PromisedBallot = row.Promised
				res.Refusal = RefusalBallotStale
				res.Detail = fmt.Sprintf("%s has promised %s, above %s", c.hostName, row.Promised, b)
				return nil
			}
			if row.Accepted.Equal(b) && row.ValueDigest != digest {
				// Two values at one ballot is a proposer bug; refusing keeps
				// "the highest accepted value" well defined.
				res.Refusal = RefusalValueConflict
				res.Detail = fmt.Sprintf("%s already accepted a different value at %s", c.hostName, b)
				return nil
			}
			if row.Accepted.Equal(b) && row.Accept != nil && row.Accept.ConfigGeneration == gen &&
				(!key.IsAutomation() || len(row.Accept.CertPEM) <= MaxAutomationSignerBytes) {
				// A repeated Accept: the signed accept is already on disk.
				// An imported automation acceptance can carry older, larger
				// signing metadata; re-sign its unchanged value below instead
				// of emitting a certificate outside the supported frame budget.
				res.Accepted, res.PromisedBallot, res.Accept = true, row.Promised, row.Accept
				return nil
			}
			if key.IsWorkload() && row.ValueDigest != digest && !ownerChecked {
				// A value this voter has not accepted before: it checks the
				// precondition itself first (§3.5.1). A value it already holds
				// was checked when it first accepted it, and is not re-probed.
				//
				// Nor is one it accepted at the LEGACY form of this key, which
				// the proposer's bridge re-proposes here after
				// claim_incarnation_v1 latched (§10 item 37): re-probing it
				// would stall a value chosen just before the owner came back,
				// the §3.15 case the rule exists for. Its source is still
				// cross-checked against this voter's row OF THIS INCARNATION,
				// which the legacy acceptance could not have been: a value a
				// previous incarnation decided names that incarnation's owner.
				legacyHeld := false
				if key.Incarnation != "" {
					legacy, found, err := loadClaimRowTx(ctx, tx, key.Legacy())
					if err != nil {
						return err
					}
					legacyHeld = found && !legacy.Accepted.IsZero() && legacy.ValueDigest == digest
				}
				if !legacyHeld {
					return errClaimNeedsOwnerCheck
				}
				return errClaimNeedsSourceCheck
			}
			a, err := signer.Sign(key, gen, b, digest, st.incarnation)
			if err != nil {
				return err
			}
			if continuity != nil {
				cfg, err := automationEstablishedAuthorityTx(ctx, tx, c.hostName, gen)
				if err != nil {
					return err
				}
				cert := ClaimCertificate{Key: key, ConfigGeneration: gen, Ballot: b, ValueDigest: digest, Accepts: []ClaimAccept{a}}
				if err := continuity.proof.verifier.Verify(cert, CertExpectation{Key: key, ConfigGeneration: gen, ValueDigest: digest, Electorate: cfg.Members, Quorum: 1}); err != nil {
					return err
				}
			}
			row.Promised, row.Accepted = b, b
			row.Value, row.ValueDigest, row.Accept = &v, digest, &a
			row.ConfigGeneration = gen
			if err := saveClaimRowTx(ctx, tx, row); err != nil {
				return err
			}
			if key.IsLeaseTerm() {
				if err := pruneLeaseTermClaimsTx(ctx, tx, key.TargetName); err != nil {
					return err
				}
			}
			res.Accepted, res.PromisedBallot, res.Accept = true, b, &a
			return nil
		}, c.keyCommitSeams(ctx, key, keyPrepared))
		if errors.Is(err, errClaimNeedsOwnerCheck) || errors.Is(err, errClaimNeedsSourceCheck) {
			if r, d := c.checkClaimOwner(ctx, key, v, probe, errors.Is(err, errClaimNeedsOwnerCheck)); r != "" {
				res.Refusal, res.Detail = r, d
				return res, nil
			}
			ownerChecked = true
			continue
		}
		if err != nil {
			return AcceptResult{}, err
		}
		if key.IsAutomation() && res.Accepted && c.automationSeams != nil && c.automationSeams.beforeReply != nil {
			c.automationSeams.beforeReply()
		}
		return res, nil
	}
}

// checkClaimOwner is §3.5.1 for one workload value: the old owner itself
// refuses outright, a settled row naming a different owner refuses, and
// otherwise — when probeSource — the voter probes the named source and
// refuses if it reaches it.
func (c *Client) checkClaimOwner(ctx context.Context, key ClaimKey, v ClaimValue, probe OwnerProbe, probeSource bool) (string, string) {
	if v.SourceHost == c.hostName {
		// If this voter can answer an Accept it is up, and it must not count
		// toward certifying its own eviction.
		return RefusalOwnerReachable, fmt.Sprintf("%s is the owner", c.hostName)
	}
	owner, settled, err := c.settledOwner(ctx, key)
	if err != nil {
		return RefusalProbeUnavailable, fmt.Sprintf("%s cannot read its own row for %s: %v", c.hostName, key, err)
	}
	if settled && owner != v.SourceHost {
		return RefusalSourceMismatch, fmt.Sprintf("%s's settled row for %s/%s at epoch %d names %s, not %s",
			c.hostName, key.TargetKind, key.TargetName, key.OwnerEpoch, owner, v.SourceHost)
	}
	if !probeSource {
		return "", ""
	}
	if probe == nil {
		return RefusalProbeUnavailable, fmt.Sprintf("%s has no owner probe wired", c.hostName)
	}
	if reached, detail := probe(ctx, v.SourceHost); reached {
		return RefusalOwnerReachable, fmt.Sprintf("%s still reaches %s (%s)", c.hostName, v.SourceHost, detail)
	}
	return "", ""
}

// transferStates are row states in which the recorded owner is mid-move, so
// the row says nothing about who owns the generation being left.
var transferStates = map[string]bool{"pending": true, "starting": true, "migrating": true, "relocating": true}

// settledOwner reads this voter's own row for the target: the owner it names
// and whether that row is settled at key.OwnerEpoch (§3.5.1, the source
// cross-check). A row at another epoch, mid-transfer, or absent is not
// settled and says nothing about this key.
func (c *Client) settledOwner(ctx context.Context, key ClaimKey) (string, bool, error) {
	r, ok, err := c.claimTargetRow(ctx, key)
	if err != nil || !ok {
		return "", false, err
	}
	if r.Int64("epoch") != key.OwnerEpoch || !rowIsIncarnation(r, key) ||
		transferStates[r.String("state")] || r.String("pending") != "" {
		return "", false, nil
	}
	return r.String("host_name"), true, nil
}

// rowIsIncarnation reports whether a workload row is the incarnation key
// names. A legacy key names no incarnation, so any row may be it. A row of
// ANOTHER incarnation says nothing about key — like a row at another epoch —
// and this voter neither cross-checks against it nor waits for it: a voter
// that is behind a re-create must not refuse the new incarnation's recovery,
// and a destination executes a certificate only against its own row of the
// incarnation the certificate names (VerifyClaimCertificate), which is where
// the binding is enforced (§10 item 37).
func rowIsIncarnation(r Row, key ClaimKey) bool {
	return key.Incarnation == "" || IncarnationOf(r.String("created_at")) == key.Incarnation
}

// ClaimProbeHint is the host this voter's own row for the target names at
// key.OwnerEpoch, settled or not, or "" when there is none: the source an
// Accept for key will most likely name, so a Prepare can start the owner probe
// before the Accept arrives (§3.5.1, §10 item 36). It is a hint and decides
// nothing: the Accept probes the source its value names, whatever this said.
func (c *Client) ClaimProbeHint(ctx context.Context, key ClaimKey) (string, error) {
	r, ok, err := c.claimTargetRow(ctx, key)
	if err != nil || !ok || r.Int64("epoch") != key.OwnerEpoch || !rowIsIncarnation(r, key) {
		return "", err
	}
	return r.String("host_name"), nil
}

// claimTargetRow reads the live vms / containers row a workload key names.
func (c *Client) claimTargetRow(ctx context.Context, key ClaimKey) (Row, bool, error) {
	var q string
	switch key.TargetKind {
	case ClaimKindVM:
		q = `SELECT host_name, state, vm_owner_epoch AS epoch, pending_action_id AS pending,
				COALESCE(created_at, '') AS created_at FROM vms
			WHERE name = ? AND deleted_at IS NULL`
	case ClaimKindContainer:
		q = `SELECT host_name, state, owner_epoch AS epoch, '' AS pending,
				COALESCE(created_at, '') AS created_at FROM containers
			WHERE name = ? AND deleted_at IS NULL`
	default:
		return Row{}, false, nil
	}
	rows, err := c.Query(ctx, q, key.TargetName)
	if err != nil || len(rows) != 1 {
		return Row{}, false, err
	}
	return rows[0], true, nil
}

// ClaimState reads this voter's state for key; found=false when it has none.
func (c *Client) ClaimState(ctx context.Context, key ClaimKey) (ClaimVoterState, bool, error) {
	var st ClaimVoterState
	var found bool
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var err error
		st, found, err = loadClaimRowTx(ctx, tx, key)
		return err
	})
	return st, found, err
}

// ClaimImportSource is what a sealed voter hands an importer (§4.4 rule 2).
type ClaimImportSource struct {
	Voter string
	// Frozen reports that this voter no longer votes on workload keys under
	// the generation asked about: it has sealed it by accepting a change of it,
	// or has moved past it. Only a frozen voter's state can be imported, or a
	// value accepted after the snapshot would be missed.
	Frozen  bool
	Adopted int64
	States  []ClaimVoterState
}

// ClaimStatesForImport returns this voter's complete generation-scoped claim
// state, including promise-only keys, with whether generation gen is frozen here.
func (c *Client) ClaimStatesForImport(ctx context.Context, gen int64) (ClaimImportSource, error) {
	out := ClaimImportSource{Voter: c.hostName}
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return err
		}
		out.Adopted = st.adopted
		out.Frozen = st.adopted > gen || (st.adopted == gen && st.sealed)
		// Both tables: an importer must carry the legacy keys and the
		// incarnation-scoped ones alike (§4.4 rule 2, §10 item 37). Lease
		// terms are carried like workloads: a term decided under this
		// generation must not be decided again under the next.
		rows, err := tx.Query(ctx, `SELECT target_kind, target_name, '' AS incarnation, owner_epoch, attempt, `+claimRowCols+`
			FROM local_recovery_claims WHERE target_kind IN (?, ?, ?, ?, ?)
			UNION ALL
			SELECT target_kind, target_name, incarnation, owner_epoch, attempt, `+claimRowCols+`
			FROM local_incarnation_claims WHERE target_kind IN (?, ?)
			ORDER BY 1, 2, 3, 4, 5`, ClaimKindVM, ClaimKindContainer, ClaimKindLUN, ClaimKindAutomation, ClaimKindLeaseTerm, ClaimKindVM, ClaimKindContainer)
		if err != nil {
			return err
		}
		for _, r := range rows {
			k := ClaimKey{TargetKind: r.String("target_kind"), TargetName: r.String("target_name"),
				OwnerEpoch: r.Int64("owner_epoch"), Attempt: r.Int64("attempt"), Incarnation: r.String("incarnation")}
			s, err := scanClaimRow(k, r)
			if err != nil {
				return err
			}
			out.States = append(out.States, s)
		}
		return nil
	})
	return out, err
}

// ImportClaimsAndAdopt merges the maximum promise independently of the
// highest-ballot accepted value for each generation-scoped key, then adopts
// newGen in ONE transaction (§4.4 rules 2–3). Neither local ballot is lowered,
// and the promise is always at least the accepted ballot.
//
// For a normal certified transition, a frozen old transfer quorum intersects
// every old prepare quorum. Carrying all its promises prevents a new decision
// from being outranked by a late old acceptance. This requires complete source
// snapshots and correct proposers; forced/reset transitions without old quorum
// intersection, and old exporters that omit promises, do not provide it.
//
// It refuses unless this node's adopted generation is newGen-1: the import is
// relative to the generation it replaces.
//
// It never carries automation authority to newGen: a node adopting through
// it (a forced generation, a test) is not automation-ready afterwards. The
// ordinary certified transition uses ImportClaimsAndAdoptAutomation.
func (c *Client) ImportClaimsAndAdopt(ctx context.Context, newGen int64, from []string, states []ClaimVoterState) (int, error) {
	return c.importClaimsAndAdopt(ctx, newGen, from, states, false)
}

func (c *Client) importClaimsAndAdopt(ctx context.Context, newGen int64, from []string, states []ClaimVoterState, carryAutomation bool) (int, error) {
	imported := 0
	// Copy before any release gate or network owner can run. Import remains
	// inert accepted state: it never creates this voter's signed lineage.
	copied, err := copyContinuityImportStates(states)
	if err != nil {
		return 0, err
	}
	states = copied
	err = c.executeContinuityImport(ctx, states, func(tx *LocalTx) error {
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return err
		}
		if st.adopted >= newGen {
			return nil // already adopted: idempotent
		}
		if st.adopted != newGen-1 {
			return fmt.Errorf("cannot adopt generation %d from %d", newGen, st.adopted)
		}
		best := map[ClaimKey]ClaimVoterState{}
		for _, s := range states {
			if err := ValidateAutomationState(s); err != nil {
				return err
			}
			if !s.Key.IsGenerationScoped() {
				continue
			}
			if err := s.Key.Validate(); err != nil {
				return fmt.Errorf("import from %v: invalid key: %w", from, err)
			}
			if s.Accepted.IsZero() {
				if s.Value != nil || s.ValueDigest != "" || s.Accept != nil {
					return fmt.Errorf("import from %v: %s carries a value without an accepted ballot", from, s.Key)
				}
			} else {
				if s.Value == nil {
					return fmt.Errorf("import from %v: %s is missing its accepted value", from, s.Key)
				}
				if r, detail := validateGenerationClaimValue(s.Key, s.Value); r != "" {
					return fmt.Errorf("import from %v: %s: %s", from, s.Key, detail)
				}
				if d, err := s.Value.Digest(); err != nil || d != s.ValueDigest {
					return fmt.Errorf("import from %v: %s carries a value whose digest does not match", from, s.Key)
				}
			}
			cur := best[s.Key]
			if !s.Accepted.IsZero() && s.Accepted.Equal(cur.Accepted) && s.ValueDigest != cur.ValueDigest {
				return fmt.Errorf("import from %v: %s has conflicting values at %s", from, s.Key, s.Accepted)
			}
			if CompareBallots(s.Promised, cur.Promised) > 0 {
				cur.Promised = s.Promised
			}
			if CompareBallots(s.Accepted, cur.Accepted) > 0 {
				cur.Accepted, cur.Value, cur.ValueDigest = s.Accepted, s.Value, s.ValueDigest
			}
			best[s.Key] = cur
		}
		for k, in := range best {
			row, _, err := loadClaimRowTx(ctx, tx, k)
			if err != nil {
				return err
			}
			if !in.Accepted.IsZero() && in.Accepted.Equal(row.Accepted) && in.ValueDigest != row.ValueDigest {
				return fmt.Errorf("import from %v: %s conflicts with the local value at %s", from, k, in.Accepted)
			}
			changed := false
			if CompareBallots(in.Promised, row.Promised) > 0 {
				row.Promised = in.Promised
				changed = true
			}
			if CompareBallots(in.Accepted, row.Accepted) > 0 {
				row.Accepted, row.Value, row.ValueDigest = in.Accepted, in.Value, in.ValueDigest
				row.Accept = nil // not this voter's signature; it re-signs at newGen
				changed = true
			}
			if CompareBallots(row.Accepted, row.Promised) > 0 {
				row.Promised = row.Accepted
				changed = true
			}
			if changed {
				if k.IsAutomation() && row.ConfigGeneration != newGen {
					row.Accept = nil // the old signature binds the previous generation
				}
				row.ConfigGeneration = newGen
				if err := saveClaimRowTx(ctx, tx, row); err != nil {
					return err
				}
				imported++
			}
		}
		if carryAutomation {
			if err := carryAutomationAuthorityTx(ctx, tx, c.hostName, newGen); err != nil {
				return err
			}
		}
		return recordAdoptionTx(ctx, tx, newGen, from)
	})
	return imported, err
}

// leaseTermClaimRetention is how many terms below this voter's own newest
// recorded term of a lease it keeps lease-term claim state for.
const leaseTermClaimRetention = 8

// pruneLeaseTermClaimsTx drops this voter's lease-term claim state for terms
// of lease well below the newest term its own ledger has recorded, so the
// table does not grow by a row per takeover forever.
//
// Only below a RECORDED term, and with a margin: a claimant asks about a term
// only after the quorum high-water read showed every term up to it free, and
// a term this many below one already recorded and replicated is not one any
// claimant can get past that read for. Within the margin, and for terms that
// were decided but never recorded, the state is kept. The margin bounds the
// case, it does not exclude it: the read's quorum and the claim's majority are
// different sets, so a claimant whose read is more than the margin behind
// could re-decide a pruned term — one long superseded and fenced by the
// barrier.
func pruneLeaseTermClaimsTx(ctx context.Context, tx *LocalTx, lease string) error {
	rows, err := tx.Query(ctx, `SELECT COALESCE(MAX(term), 0) AS t FROM leader_lease_terms
		WHERE key = ? AND deleted_at IS NULL`, lease)
	if err != nil || len(rows) == 0 {
		return err
	}
	below := rows[0].Int64("t") - leaseTermClaimRetention
	if below <= 1 {
		return nil
	}
	_, err = tx.Exec(ctx, `DELETE FROM local_recovery_claims
		WHERE target_kind = ? AND target_name = ? AND owner_epoch < ?`, ClaimKindLeaseTerm, lease, below)
	return err
}
