package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
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
	Voter          string
	Incarnation    string
	Refusal        string
	Detail         string
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
		if v.Config == nil || v.Proof != nil {
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
	// A workload key.
	if !st.cfg.Explicit() {
		return RefusalNoVoterConfig, fmt.Sprintf("%s has adopted no member voter generation", st.me)
	}
	if r, d := memberCheck(st.cfg); r != "" {
		return r, d
	}
	if st.sealed {
		// §4.4 rule 1: deciding g+1 seals g for workload keys.
		return RefusalSealed, fmt.Sprintf("%s has accepted a change of voter generation %d and no longer "+
			"votes on recoveries under it; retry once generation %d is adopted", st.me, st.adopted, st.adopted+1)
	}
	if v != nil {
		if v.Proof == nil || v.Config != nil {
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
	}
	return "", ""
}

const claimRowCols = `promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,
	accepted_nonce, value_json, value_digest, accept_json, config_generation`

func loadClaimRowTx(ctx context.Context, tx *LocalTx, key ClaimKey) (ClaimVoterState, bool, error) {
	rows, err := tx.Query(ctx, `SELECT `+claimRowCols+` FROM local_recovery_claims
		WHERE target_kind = ? AND target_name = ? AND owner_epoch = ? AND attempt = ?`,
		key.TargetKind, key.TargetName, key.OwnerEpoch, key.Attempt)
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
		if err := json.Unmarshal([]byte(s), &v); err != nil {
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

func saveClaimRowTx(ctx context.Context, tx *LocalTx, st ClaimVoterState) error {
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
	_, err := tx.Exec(ctx, upsertClaimRowSQL,
		k.TargetKind, k.TargetName, k.OwnerEpoch, k.Attempt,
		int64(st.Promised.Round), st.Promised.Coordinator, nonce(st.Promised.Nonce),
		int64(st.Accepted.Round), st.Accepted.Coordinator, nonce(st.Accepted.Nonce),
		vj, st.ValueDigest, aj, st.ConfigGeneration, time.Now().UTC().Format(time.RFC3339Nano))
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
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return err
		}
		res.Incarnation = st.incarnation
		if r, d := st.admit(key, gen, nil); r != "" {
			res.Refusal, res.Detail = r, d
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
			row.ConfigGeneration = gen
			if err := saveClaimRowTx(ctx, tx, row); err != nil {
				return err
			}
		}
		res.Promised = true
		res.PromisedBallot = b
		res.State = row
		return nil
	})
	if err != nil {
		return PrepareResult{}, err
	}
	return res, nil
}

var errClaimNeedsOwnerCheck = errors.New("claim value needs the owner check")

// ClaimAccept is phase 2 at this voter (§3.5, §3.5.1). probe is consulted only
// for a workload value this voter has not accepted before, and outside the
// transaction: it is network I/O and must not hold the database lock.
func (c *Client) ClaimAccept(ctx context.Context, key ClaimKey, b Ballot, v ClaimValue, gen int64,
	signer *ClaimSigner, probe OwnerProbe) (AcceptResult, error) {
	res := AcceptResult{Voter: c.hostName}
	digest, err := v.Digest()
	if err != nil {
		res.Refusal, res.Detail = RefusalInvalidValue, err.Error()
		return res, nil
	}
	if b.Round == 0 || b.Coordinator == "" {
		res.Refusal, res.Detail = RefusalInvalidValue, "a ballot has a round >= 1 and a coordinator"
		return res, nil
	}
	if signer == nil || signer.Name() != c.hostName {
		return res, fmt.Errorf("no claim signing key for %s", c.hostName)
	}
	ownerChecked := false
	for {
		res = AcceptResult{Voter: c.hostName}
		err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			st, err := readStandingTx(ctx, tx, c.hostName)
			if err != nil {
				return err
			}
			if r, d := st.admit(key, gen, &v); r != "" {
				res.Refusal, res.Detail = r, d
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
			if row.Accepted.Equal(b) && row.Accept != nil && row.Accept.ConfigGeneration == gen {
				// A repeated Accept: the signed accept is already on disk.
				res.Accepted, res.PromisedBallot, res.Accept = true, row.Promised, row.Accept
				return nil
			}
			if key.IsWorkload() && row.ValueDigest != digest && !ownerChecked {
				// A value this voter has not accepted before: it checks the
				// precondition itself first (§3.5.1). A value it already holds
				// was checked when it first accepted it, and is not re-probed.
				return errClaimNeedsOwnerCheck
			}
			a, err := signer.Sign(key, gen, b, digest, st.incarnation)
			if err != nil {
				return err
			}
			row.Promised, row.Accepted = b, b
			row.Value, row.ValueDigest, row.Accept = &v, digest, &a
			row.ConfigGeneration = gen
			if err := saveClaimRowTx(ctx, tx, row); err != nil {
				return err
			}
			res.Accepted, res.PromisedBallot, res.Accept = true, b, &a
			return nil
		})
		if errors.Is(err, errClaimNeedsOwnerCheck) {
			if r, d := c.checkClaimOwner(ctx, key, v, probe); r != "" {
				res.Refusal, res.Detail = r, d
				return res, nil
			}
			ownerChecked = true
			continue
		}
		if err != nil {
			return AcceptResult{}, err
		}
		return res, nil
	}
}

// checkClaimOwner is §3.5.1 for one workload value: the old owner itself
// refuses outright, a settled row naming a different owner refuses, and
// otherwise the voter probes the named source and refuses if it reaches it.
func (c *Client) checkClaimOwner(ctx context.Context, key ClaimKey, v ClaimValue, probe OwnerProbe) (string, string) {
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
	var q string
	switch key.TargetKind {
	case ClaimKindVM:
		q = `SELECT host_name, state, vm_owner_epoch AS epoch, pending_action_id AS pending FROM vms
			WHERE name = ? AND deleted_at IS NULL`
	case ClaimKindContainer:
		q = `SELECT host_name, state, owner_epoch AS epoch, '' AS pending FROM containers
			WHERE name = ? AND deleted_at IS NULL`
	default:
		return "", false, nil
	}
	rows, err := c.Query(ctx, q, key.TargetName)
	if err != nil || len(rows) != 1 {
		return "", false, err
	}
	r := rows[0]
	if r.Int64("epoch") != key.OwnerEpoch || transferStates[r.String("state")] || r.String("pending") != "" {
		return "", false, nil
	}
	return r.String("host_name"), true, nil
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

// ClaimStatesForImport returns this voter's accepted workload states, with
// whether generation gen is frozen here.
func (c *Client) ClaimStatesForImport(ctx context.Context, gen int64) (ClaimImportSource, error) {
	out := ClaimImportSource{Voter: c.hostName}
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return err
		}
		out.Adopted = st.adopted
		out.Frozen = st.adopted > gen || (st.adopted == gen && st.sealed)
		rows, err := tx.Query(ctx, `SELECT target_kind, target_name, owner_epoch, attempt, `+claimRowCols+`
			FROM local_recovery_claims WHERE target_kind IN (?, ?) AND accepted_round > 0
			ORDER BY target_kind, target_name, owner_epoch, attempt`, ClaimKindVM, ClaimKindContainer)
		if err != nil {
			return err
		}
		for _, r := range rows {
			k := ClaimKey{TargetKind: r.String("target_kind"), TargetName: r.String("target_name"),
				OwnerEpoch: r.Int64("owner_epoch"), Attempt: r.Int64("attempt")}
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

// ImportClaimsAndAdopt records, for every workload key the sources hold, the
// highest-ballot accepted value as this voter's own accepted value under
// generation newGen, and adopts newGen — in ONE transaction, so a voter never
// votes under newGen without the state that makes its vote safe (§4.4 rules
// 2–3). It never downgrades local state, and raises the local promise to the
// imported ballot so the accepted ballot stays at or below the promise.
//
// It refuses unless this node's adopted generation is newGen-1: the import is
// relative to the generation it replaces.
func (c *Client) ImportClaimsAndAdopt(ctx context.Context, newGen int64, from []string, states []ClaimVoterState) (int, error) {
	imported := 0
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
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
			if !s.Key.IsWorkload() || s.Accepted.IsZero() || s.Value == nil {
				continue
			}
			if d, err := s.Value.Digest(); err != nil || d != s.ValueDigest {
				return fmt.Errorf("import from %v: %s carries a value whose digest does not match", from, s.Key)
			}
			if cur, ok := best[s.Key]; !ok || CompareBallots(s.Accepted, cur.Accepted) > 0 {
				best[s.Key] = s
			}
		}
		for k, in := range best {
			row, _, err := loadClaimRowTx(ctx, tx, k)
			if err != nil {
				return err
			}
			changed := false
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
				row.ConfigGeneration = newGen
				if err := saveClaimRowTx(ctx, tx, row); err != nil {
					return err
				}
				imported++
			}
		}
		return recordAdoptionTx(ctx, tx, newGen, from)
	})
	return imported, err
}
