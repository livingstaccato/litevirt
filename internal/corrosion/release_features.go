package corrosion

// Release-feature USED records (capabilities.ReleaseToken).
//
// A release token latches once every host this node replicates to runs a build
// that keeps the release's new data. A feature of the release is opened through
// health.Checker.WithFeature, which writes one row here,
// release_feature/<token>/<feature>, before the feature's first write, waits
// until every replication recipient holds it, and has every writing node put
// its own copy on its own stream before its first write. The row is how a node
// rolled back onto an older build learns whether that build can keep running.
//
// WHY cluster_policies. The record is a cluster fact every node must read the
// same way, which is what the table is for: replicated, repaired by
// anti-entropy, and written through the one clusterPolicyUpsertSQL shape every
// build since v58 already decodes — so it adds no statement shape a peer could
// stall on, and needs no schema change. Nothing deletes a cluster_policies row,
// so a record is MONOTONE: once a feature is used it stays used. That is the
// point — it records that data a previous build cannot keep may exist, and
// nothing proves it has all gone.
//
// THE ROLLED-BACK READER (frozen once this build ships: every later release
// token is rolled back onto it).
//   - At start, a safe_if_unused marker with no use in this replica is a
//     PROBATION, not a pass: the replica can lack a record its peers hold (a
//     pruned log, a cross-origin write, a node away during the first use). No
//     replicated writes until a voter majority's records are pulled
//     (AntiEntropy.VerifyReleaseProbation).
//   - At run time, a record is checked as it ARRIVES: a use this build cannot
//     honour (UnhonouredUse — an unknown token, or an undeclared feature under a
//     known one) trips the WAL quarantine before the next WAL statement is
//     applied, before a blob payload is merged, and — cluster_policies being
//     pulled alone first — before a paged pull's feature tables are merged.
// Quarantine stops this node's replicated writes; it does not stop it acting
// locally on data it already applied (docs/upgrades.md).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// releaseFeatureKeyPrefix prefixes every used record's cluster_policies key.
const releaseFeatureKeyPrefix = "release_feature/"

// A record's value is one of two states. "used": recorded, not yet shown to
// be held by every host this node replicates to. "acked": every such host
// acknowledged holding it before any feature data was written (I1), so a later
// writer — on any node, after any restart — need only put its own copy on its
// own stream. The key carries everything else, so concurrent writers converge.
const (
	releaseFeatureUsedValue  = "used"
	releaseFeatureAckedValue = "acked"
)

// ReleaseFeatureUse is one recorded use of a release feature.
type ReleaseFeatureUse struct {
	Token   string
	Feature string
	// RecordedBy is the host that last recorded the use. Every host that
	// writes the feature's data re-records it on its own stream, so this is
	// not the first user.
	RecordedBy string
	UpdatedAt  string
	// Acked: every replication recipient acknowledged the record.
	Acked bool
	// Tombstoned: the row carries a deleted_at. Nothing writes one; it is
	// reported, never treated as the end of the use.
	Tombstoned bool
}

// releaseUseApplyHook is a test seam called before each WAL statement is
// applied. Nil in production.
var releaseUseApplyHook func(Statement)

// validReleaseName reports whether s may be one part of a record's key: no
// slash (it would forge another token's or feature's key) and not empty.
func validReleaseName(s string) bool {
	return s != "" && !strings.ContainsAny(s, "/\x00")
}

func releaseFeatureKey(token, feature string) string {
	return releaseFeatureKeyPrefix + token + "/" + feature
}

// parseReleaseFeatureKey splits a record's key; ok is false for any other key.
func parseReleaseFeatureKey(key string) (token, feature string, ok bool) {
	rest, found := strings.CutPrefix(key, releaseFeatureKeyPrefix)
	if !found {
		return "", "", false
	}
	token, feature, found = strings.Cut(rest, "/")
	if !found || token == "" || feature == "" {
		return "", "", false
	}
	return token, feature, true
}

// RecordReleaseFeatureUse records, replicated, that feature of token is in
// use. It returns once the record has committed locally with its mutation-log
// entry, so it is on this node's replication stream ahead of any write the
// caller makes next. It refuses with ErrClusterPolicyGateClosed until this
// node may write cluster_policies, and fails under WAL quarantine — either
// way nothing is recorded and the caller must not write.
//
// Callers go through health.Checker.WithFeature, which owns the release
// token's latch; this function owns only what keeps a peer's stream alive.
func RecordReleaseFeatureUse(ctx context.Context, c *Client, token, feature, host string, acked bool) error {
	if !validReleaseName(token) || !validReleaseName(feature) {
		return fmt.Errorf("release feature record: malformed token %q or feature %q", token, feature)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	value := releaseFeatureUsedValue
	if acked {
		value = releaseFeatureAckedValue
	}
	// The one writer, and always clusterPolicyUpsertSQL: the WAL reader finds
	// the key by column name (noteReleaseUseStatements), but this is the shape
	// every receiver's ledger holds.
	return c.Execute(ctx, clusterPolicyUpsertSQL, releaseFeatureKey(token, feature), value, host, c.NowTS())
}

// ReleaseFeatureState reports whether this replica holds a record of feature
// (tombstoned or not), and whether it is acknowledged.
func ReleaseFeatureState(ctx context.Context, c *Client, token, feature string) (present, acked bool, err error) {
	rows, err := c.Query(ctx, `SELECT value FROM cluster_policies WHERE key = ?`, releaseFeatureKey(token, feature))
	if err != nil {
		return false, false, err
	}
	if len(rows) == 0 {
		return false, false, nil
	}
	return true, rows[0].String("value") == releaseFeatureAckedValue, nil
}

// ReleaseFeatureUsed reports whether this replica holds a use of feature,
// tombstoned or not.
func ReleaseFeatureUsed(ctx context.Context, c *Client, token, feature string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT 1 AS one FROM cluster_policies WHERE key = ?`,
		releaseFeatureKey(token, feature))
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// ListReleaseFeatureUses returns every use this replica holds, of any token —
// including tokens this build does not know, and tombstoned records, which the
// runtime trip counts too — sorted by token and feature.
func ListReleaseFeatureUses(ctx context.Context, c *Client) ([]ReleaseFeatureUse, error) {
	lo, hi := keyRange(releaseFeatureKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at, deleted_at FROM cluster_policies
		 WHERE key >= ? AND key < ? ORDER BY key`, lo, hi)
	if err != nil {
		return nil, err
	}
	out := make([]ReleaseFeatureUse, 0, len(rows))
	for _, r := range rows {
		token, feature, ok := parseReleaseFeatureKey(r.String("key"))
		if !ok {
			continue
		}
		out = append(out, ReleaseFeatureUse{Token: token, Feature: feature,
			RecordedBy: r.String("set_by"), UpdatedAt: r.String("updated_at"),
			Acked: r.String("value") == releaseFeatureAckedValue, Tombstoned: r.String("deleted_at") != ""})
	}
	return out, nil
}

// ReleaseTokenKnown reports whether this build knows token: a live token, or
// a retired one an older build latched.
func ReleaseTokenKnown(token string) bool {
	return capabilities.Has(capabilities.All(), token) || capabilities.Retired(token)
}

// UnhonouredUse names a recorded use this binary cannot keep the data of, or
// returns "" for one it can. A token this build does not know is named by the
// token; a feature this build does not declare under a token it knows (a build
// from before the feature landed) by "<token>/<feature>" (I3).
func UnhonouredUse(token, feature string) string {
	if !ReleaseTokenKnown(token) {
		return token
	}
	if capabilities.Honoured(token, capabilities.Feature(feature)) {
		return ""
	}
	return token + "/" + feature
}

// ReleaseUseQuarantine lists, sorted, the recorded uses this binary cannot
// honour that have arrived since start (UnhonouredUse). Non-empty means the
// node is WAL-quarantined: it is running a build older than the one that used
// them.
func (c *Client) ReleaseUseQuarantine() []string {
	c.releaseUseMu.Lock()
	defer c.releaseUseMu.Unlock()
	out := make([]string, 0, len(c.releaseUseTripped))
	for tok := range c.releaseUseTripped {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// releaseProbationPrefix starts the probation refusal reason.
const releaseProbationPrefix = "release probation: "

// releaseUseQuarantineReason is the write refusal while tripped or in
// probation, or "".
func (c *Client) releaseUseQuarantineReason() string {
	if toks := c.ReleaseUseQuarantine(); len(toks) > 0 {
		return "a feature of a newer release this build does not know is in use: " + strings.Join(toks, ",")
	}
	if toks := c.ReleaseProbation(); len(toks) > 0 {
		reason := releaseProbationPrefix + "started below latched release token(s) " + strings.Join(toks, ",") +
			" with no use recorded in this replica; waiting to confirm that with a voter majority"
		if w := c.ReleaseProbationWaitingOn(); len(w) > 0 {
			reason += "; waiting on: " + strings.Join(w, ", ")
		}
		return reason
	}
	return ""
}

// ReleaseProbationWaitingOn names what the last probation round could not
// count — each voter not answering, with why — or is empty before the first
// round and after a lift. `lv cluster upgrade-status` shows it in the
// probation's reason.
func (c *Client) ReleaseProbationWaitingOn() []string {
	c.releaseUseMu.Lock()
	defer c.releaseUseMu.Unlock()
	return append([]string(nil), c.releaseProbationWaiting...)
}

func (c *Client) setReleaseProbationWaiting(w []string) {
	c.releaseUseMu.Lock()
	c.releaseProbationWaiting = append([]string(nil), w...)
	c.releaseUseMu.Unlock()
}

// noteReleaseFeatureKey trips the quarantine when key records a use this
// binary cannot honour (UnhonouredUse). Any other key is ignored. It FAILS
// CLOSED on the record's presence alone, tombstoned or not: nothing writes a
// tombstone on a used record, so one is not evidence the use is over.
func (c *Client) noteReleaseFeatureKey(key string, via string) {
	token, feature, ok := parseReleaseFeatureKey(key)
	if !ok {
		return
	}
	name := UnhonouredUse(token, feature)
	if name == "" {
		return
	}
	c.releaseUseMu.Lock()
	if c.releaseUseTripped == nil {
		c.releaseUseTripped = map[string]bool{}
	}
	already := c.releaseUseTripped[name]
	c.releaseUseTripped[name] = true
	c.releaseUseMu.Unlock()
	if !already {
		slog.Error("release feature: a feature this build cannot keep the data of is in use; "+
			"entering WAL quarantine — no replicated writes will be emitted until this node is "+
			"upgraded again or reseeded by an operator, and it should be drained of the workloads "+
			"the feature touches (docs/upgrades.md)",
			"token", token, "feature", feature, "via", via)
	}
}

// noteReleaseUseStatements checks one WAL entry's statements, before any of
// them is applied.
func (c *Client) noteReleaseUseStatements(stmts []Statement) {
	for _, s := range stmts {
		if !strings.Contains(s.SQL, "cluster_policies") {
			continue
		}
		sh, err := parseStmtShape(s.SQL, nil)
		if err != nil || sh.Table != "cluster_policies" {
			continue
		}
		// By the column's NAME (M2): this reader is frozen once the build
		// ships, and a later writer is not bound to today's column order.
		if v, ok := guardedInsertField(sh, s, "key"); ok {
			if key, ok := v.(string); ok {
				c.noteReleaseFeatureKey(key, "replication")
			}
		}
	}
}

// noteReleaseUseRows checks a cluster_policies anti-entropy table, before it
// (or anything after it in the payload) is merged.
func (c *Client) noteReleaseUseRows(table syncTable) {
	if table.Name != "cluster_policies" {
		return
	}
	idx := indexOf(table.Columns, "key")
	if idx < 0 {
		return
	}
	for _, row := range table.Rows {
		if idx < len(row) {
			if key, ok := row[idx].(string); ok {
				c.noteReleaseFeatureKey(key, "anti-entropy")
			}
		}
	}
}

// EnterReleaseProbation puts this node in RELEASE PROBATION for tokens: it
// emits no replicated writes (quarantineReason) and applies no replicated
// state — a peer's push is refused (grpcapi PushMutations) and anti-entropy
// takes nothing (ReplicationSourceAllowed) — until a voter majority has been
// asked (AntiEntropy.VerifyReleaseProbation), whose own pull is exempt. It
// keeps advertising (N1): probation is not a WAL quarantine, its Ping says
// release_probation. Additive: a later call adds tokens.
//
// Why a node that found no recorded use still cannot run (C1): its own
// replica can lack a record its peers hold — a pruned mutation log, a
// cross-origin write, a node away during the first use — while the feature's
// data, which travels on other streams, reaches it first.
func (c *Client) EnterReleaseProbation(tokens []string) {
	if len(tokens) == 0 {
		return
	}
	c.releaseUseMu.Lock()
	if c.releaseProbation == nil {
		c.releaseProbation = map[string]bool{}
	}
	var added []string
	for _, t := range tokens {
		if !c.releaseProbation[t] {
			c.releaseProbation[t] = true
			added = append(added, t)
		}
	}
	c.releaseUseMu.Unlock()
	if len(added) > 0 {
		slog.Warn("release probation: no replicated writes until a voter majority confirms no feature "+
			"of these release tokens is in use", "tokens", added)
	}
}

// ReleaseProbation lists, sorted, the tokens this node is in probation for.
func (c *Client) ReleaseProbation() []string {
	c.releaseUseMu.Lock()
	defer c.releaseUseMu.Unlock()
	out := make([]string, 0, len(c.releaseProbation))
	for t := range c.releaseProbation {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// liftReleaseProbation ends probation for tokens — the set a verification
// round checked — and only those (N8): a token added since stays.
func (c *Client) liftReleaseProbation(tokens []string) {
	c.releaseUseMu.Lock()
	for _, t := range tokens {
		delete(c.releaseProbation, t)
	}
	c.releaseUseMu.Unlock()
}

// WALQuarantined reports a ROLLBACK quarantine: the injected predicate (a
// marker for a token this build does not know) or a tripped release use. It is
// what Ping reports as wal_quarantined, and what makes a peer record a
// rolled_back_latch isolation. Release PROBATION is deliberately not part of it
// (N1): probation refuses this node's own replicated writes, but the node keeps
// advertising and is not a rollback below anything known to be used.
func (c *Client) WALQuarantined() bool {
	if c.writeQuarantine != nil && c.writeQuarantine() != "" {
		return true
	}
	return len(c.ReleaseUseQuarantine()) > 0
}

// InReleaseProbation reports whether this node is in release probation.
func (c *Client) InReleaseProbation() bool { return len(c.ReleaseProbation()) > 0 }

// ErrReleaseProbation is what a node in release probation answers a peer's
// push or its own anti-entropy source with: back-pressure, nothing dropped.
var ErrReleaseProbation = errors.New("this node is in release probation and applies no replicated state " +
	"until a voter majority has confirmed no feature it cannot keep is in use; it lifts by itself (docs/upgrades.md)")

// ReleaseProbationRefusal returns ErrReleaseProbation, naming the tokens, while
// this node is in release probation, else nil.
func (c *Client) ReleaseProbationRefusal() error {
	if toks := c.ReleaseProbation(); len(toks) > 0 {
		return fmt.Errorf("%w (below %s)", ErrReleaseProbation, strings.Join(toks, ","))
	}
	return nil
}

// probationAnswer is one peer's answer to a probation pull.
type probationAnswer struct {
	// excluded: the peer reports itself WAL-quarantined and does not count.
	excluded bool
	// voterGeneration is the voter generation the peer has adopted (its Ping),
	// 0 when it does not say.
	voterGeneration int64
}

// probationVoterTables are the tables a probation pull merges after
// cluster_policies (I-R4-2): the voter view. A probation applies nothing else,
// so without them a host that was away while the voters changed would count
// against a voter set that no longer exists, for good. They carry no release
// feature's data.
var probationVoterTables = []string{"voter_configs", "hosts", "host_membership"}

// probationMaxPasses bounds how often one round recomputes the voter set after
// what its pulls merged changed it.
const probationMaxPasses = 3

// SetVoterAdopter injects the voter adoption pass (grpcapi.Server.
// AdoptVoterConfigs) a probation round runs when a peer reports a voter
// generation newer than this node has adopted. Adoption verifies each
// generation's certificate; a probation never counts against a generation it
// has not adopted. Unset, the round waits for the daemon's adoption loop.
func (ae *AntiEntropy) SetVoterAdopter(fn func(ctx context.Context) (int64, error)) {
	if fn == nil {
		ae.voterAdopter.Store(nil)
		return
	}
	ae.voterAdopter.Store(&fn)
}

// probationQuorum is one voter set a probation counts against: the peers to
// ask, how many of them must answer, and how it was derived.
type probationQuorum struct {
	others []string
	need   int
	// key identifies the set, so a round can tell when a merge changed it.
	key string
	// fallback: the replica holds no voter, so admitted members are asked.
	fallback bool
}

// releaseProbationQuorum computes the set a probation round counts against.
//
// A voter set (VoterSet: the adopted generation, or the derived set) needs a
// MAJORITY OF THE WHOLE SET, this node's own seat included when it is a voter
// (I-R4-1): of a three-voter set it asks one other, of five two. Every voter
// acknowledged any first use before its data was written
// (health.Checker.WithFeature), so a voter holding no record was not a voter,
// or not there, for any use; the majority is a hedge against a stale view, not
// a requirement of that invariant, and counting its own seat lets a rolled-back
// host lift with a minority of the voters dead. A one-voter set (this node)
// needs nobody.
//
// A replica with no voter at all asks a majority of its admitted members
// (m-R2-6), not counting its own seat. With no member to ask either, it lifts
// only when its hosts table holds this host and no other (m6): a one-host
// cluster whose host is in maintenance, which no other host could have
// acknowledged a use on.
func (ae *AntiEntropy) releaseProbationQuorum(ctx context.Context, self string) (probationQuorum, bool, error) {
	voters, err := VoterSet(ctx, ae.client)
	if err != nil {
		return probationQuorum{}, false, fmt.Errorf("voter set: %w", err)
	}
	var q probationQuorum
	for v := range voters {
		if v != self {
			q.others = append(q.others, v)
		}
	}
	sort.Strings(q.others)
	if len(voters) > 0 {
		q.need = MajorityOf(len(voters))
		if voters[self] {
			q.need--
		}
		if q.need > len(q.others) {
			q.need = len(q.others)
		}
		q.key = "voters:" + strings.Join(q.others, ",")
		if voters[self] {
			q.key += "+self"
		}
		return q, true, nil
	}
	q.fallback = true
	for _, p := range ae.client.Members() {
		if p.Name != "" && p.Name != self && !slices.Contains(q.others, p.Name) {
			q.others = append(q.others, p.Name)
		}
	}
	sort.Strings(q.others)
	q.key = "members:" + strings.Join(q.others, ",")
	if len(q.others) > 0 {
		q.need = len(q.others)/2 + 1
		return q, true, nil
	}
	hosts, err := ListHosts(ctx, ae.client)
	if err != nil {
		return q, false, fmt.Errorf("read hosts: %w", err)
	}
	selfSeen := false
	for _, h := range hosts {
		if h.Name != self {
			return q, false, nil
		}
		selfSeen = true
	}
	// The only host there is: need 0. A replica that does not even hold this
	// host's row knows nothing, and lifts on nothing (m-R2-6).
	return q, selfSeen, nil
}

// VerifyReleaseProbation tries once to lift this node's release probation.
//
// It pulls, from the voters releaseProbationQuorum names, their
// cluster_policies, whole and unscoped, then their voter view
// (probationVoterTables), merging each. This node's own replica does not
// count as an answer: it is the one in doubt. A voter that is itself in
// probation DOES count (C-R2-1), so hosts rolled back together lift together;
// only a WAL-quarantined voter is not counted.
//
// The voter set is this node's own view, which can be stale after an absence
// (I-R4-2). The pull merges the voter view, and each answer carries the voter
// generation the peer has adopted: a newer one than this node's makes the round
// adopt it (SetVoterAdopter) and count against the new set instead, and the
// round never lifts while a peer reports a generation this node has not
// adopted. A derived set that the merged hosts rows changed is recomputed too.
// The pull is exempt from the replication-source gate (N2) and from probation.
//
// Any use this build cannot honour, found in what was merged, trips the
// permanent quarantine and probation stays. Otherwise probation lifts — for the
// tokens this round checked only (N8). It returns false, with no error, when a
// majority was not reached or a use was found; the voters it is waiting on are
// named in the log and in the probation's reason (ReleaseProbationWaitingOn).
func (ae *AntiEntropy) VerifyReleaseProbation(ctx context.Context) (bool, error) {
	checking := ae.client.ReleaseProbation()
	if len(checking) == 0 {
		return true, nil
	}
	self := ae.client.HostName()
	pull := ae.probationPull
	if pull == nil {
		pull = ae.pullForProbation
	}
	counted := map[string]bool{} // answered, and not WAL-quarantined
	why := map[string]string{}   // asked, and does not count: why
	var newest, adopted int64    // highest generation an answer reported; this node's
	var q probationQuorum
	settled := false
	for pass := 0; pass < probationMaxPasses && !settled; pass++ {
		var ok bool
		var err error
		if q, ok, err = ae.releaseProbationQuorum(ctx, self); err != nil {
			return false, err
		}
		if !ok {
			ae.client.setReleaseProbationWaiting([]string{"no voter or admitted member to ask, and this replica " +
				"does not show this host as the only one"})
			slog.Warn("release probation: this replica holds no voter and no admitted member to ask, and does " +
				"not show this host as the only one; staying in probation — set " +
				"LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK=1 and restart to start without it (docs/upgrades.md)")
			return false, nil
		}
		if adopted, err = AdoptedVoterGeneration(ctx, ae.client); err != nil {
			return false, fmt.Errorf("adopted voter generation: %w", err)
		}
		for _, peer := range q.others {
			if countIn(counted, q.others) >= q.need {
				break
			}
			if counted[peer] || why[peer] != "" {
				continue
			}
			ans, err := pull(ctx, peer)
			switch {
			case err != nil:
				why[peer] = "unreachable"
				slog.Debug("release probation: could not pull from a peer", "peer", peer, "error", err)
			case ans.excluded:
				why[peer] = "WAL-quarantined"
				slog.Debug("release probation: not counting a WAL-quarantined peer", "peer", peer)
			default:
				counted[peer] = true
				newest = max(newest, ans.voterGeneration)
			}
		}
		if newest > adopted {
			// This node's voter set is stale. The pulls merged the newer
			// generations; adopt them (each certificate verified) and count
			// against the new set.
			if fn := ae.voterAdopter.Load(); fn != nil {
				if _, err := (*fn)(ctx); err != nil {
					slog.Debug("release probation: voter adoption did not complete", "error", err)
				}
			}
			now, err := AdoptedVoterGeneration(ctx, ae.client)
			if err != nil {
				return false, fmt.Errorf("adopted voter generation: %w", err)
			}
			if now <= adopted {
				msg := fmt.Sprintf("a peer has adopted voter generation %d and this node only %d, and cannot adopt "+
					"the newer one yet", newest, adopted)
				ae.client.setReleaseProbationWaiting([]string{msg})
				slog.Warn("release probation: this node's voter set is stale and it cannot adopt the newer "+
					"generation yet; staying in probation — set LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK=1 and "+
					"restart to start without it (docs/upgrades.md)", "peer_generation", newest, "adopted", adopted)
				return false, nil
			}
			continue
		}
		next, ok, err := ae.releaseProbationQuorum(ctx, self)
		if err != nil {
			return false, err
		}
		if ok && next.key != q.key {
			continue // the merged hosts rows changed the derived set
		}
		settled = true
	}
	have := countIn(counted, q.others)
	if !settled || have < q.need {
		var missing []string
		for _, peer := range q.others {
			if !counted[peer] {
				reason := why[peer]
				if reason == "" {
					reason = "not asked"
				}
				missing = append(missing, peer+" ("+reason+")")
			}
		}
		ae.client.setReleaseProbationWaiting(missing)
		slog.Warn("release probation: a voter majority could not be asked yet; staying in probation — if the "+
			"voters not answering are gone for good, remove them with `lv cluster voter rm <host>` on a healthy "+
			"host, or set LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK=1 and restart this one to start without the check "+
			"(docs/upgrades.md)", "answered", have, "need", q.need, "not_answering", strings.Join(missing, ", "))
		return false, nil
	}
	uses, err := ListReleaseFeatureUses(ctx, ae.client)
	if err != nil {
		return false, err
	}
	for _, u := range uses {
		ae.client.noteReleaseFeatureKey(releaseFeatureKey(u.Token, u.Feature), "probation check")
	}
	if len(ae.client.ReleaseUseQuarantine()) > 0 {
		return false, nil
	}
	slog.Info("release probation: a voter majority holds no use of a feature this build cannot keep; lifting",
		"tokens", checking, "voters_asked", have, "voter_generation", adopted)
	ae.client.setReleaseProbationWaiting(nil)
	ae.client.liftReleaseProbation(checking)
	return true, nil
}

// countIn counts the members of set among names.
func countIn(set map[string]bool, names []string) int {
	n := 0
	for _, x := range names {
		if set[x] {
			n++
		}
	}
	return n
}

// pullForProbation asks peer whether it is WAL-quarantined (excluded) and
// which voter generation it has adopted, then pulls and merges its
// cluster_policies whole, alone and first — a use found there trips the
// quarantine before anything else is merged — and then its voter view
// (probationVoterTables). NOT gated by the replication-source gate (N2).
func (ae *AntiEntropy) pullForProbation(ctx context.Context, peer string) (probationAnswer, error) {
	pctx, cancel := context.WithTimeout(ctx, antiEntropyPeerTimeout)
	defer cancel()
	client, conn, err := ae.peerClient(pctx, peer)
	if err != nil {
		return probationAnswer{}, err
	}
	defer conn.Close()
	resp, err := client.Ping(pctx, &pb.PingRequest{})
	if err != nil {
		return probationAnswer{}, err
	}
	if resp.GetWalQuarantined() {
		return probationAnswer{excluded: true}, nil
	}
	_, perr, merr := ae.pullAndMerge(pctx, client, []string{"cluster_policies"}, nil, nil, nil)
	if perr != nil {
		return probationAnswer{}, perr
	}
	if merr != nil {
		return probationAnswer{}, merr
	}
	if len(ae.client.ReleaseUseQuarantine()) == 0 {
		// The used records are what the answer is; the voter view only says
		// whom to ask next. A failure here costs a stale view, not the answer.
		if _, perr, merr := ae.pullAndMerge(pctx, client, probationVoterTables, nil, nil, nil); perr != nil || merr != nil {
			slog.Debug("release probation: could not merge a peer's voter view", "peer", peer,
				"pull_error", perr, "merge_error", merr)
		}
	}
	return probationAnswer{voterGeneration: resp.GetVoterGeneration()}, nil
}

// CheckReleaseUsesFrom pulls and merges peer's cluster_policies whole, so a
// use recorded there that this build cannot honour trips the quarantine. It
// blocks nothing while it runs. NOT gated by the replication-source gate.
func (ae *AntiEntropy) CheckReleaseUsesFrom(ctx context.Context, peer string) error {
	pctx, cancel := context.WithTimeout(ctx, antiEntropyPeerTimeout)
	defer cancel()
	client, conn, err := ae.peerClient(pctx, peer)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, perr, merr := ae.pullAndMerge(pctx, client, []string{"cluster_policies"}, nil, nil, nil)
	if perr != nil {
		return perr
	}
	return merr
}

// OnUnknownReleaseToken is what a node does when a peer advertises a release
// token this build does not know — a forward roll, normally (N2). It does NOT
// enter probation and refuses nothing: the token is replication-gated, so it
// cannot latch, and so cannot have a use, while this node is admitted and does
// not advertise it. It looks at that peer's cluster_policies anyway, so a use
// made while this node was away is found and trips the quarantine.
//
// A failed look is retried with backoff (releaseCheckBackoff, doubling to
// releaseCheckMaxBackoff) until one succeeds or ctx ends (m-R2-4).
func (ae *AntiEntropy) OnUnknownReleaseToken(ctx context.Context, peer, token string) {
	check := ae.checkFrom
	if check == nil {
		check = ae.CheckReleaseUsesFrom
	}
	backoff := releaseCheckBackoff
	for {
		err := check(ctx, peer)
		if err == nil {
			return
		}
		slog.Debug("release feature: could not look at a newer peer's used records; retrying", "peer", peer,
			"token", token, "retry_in", backoff, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > releaseCheckMaxBackoff {
			backoff = releaseCheckMaxBackoff
		}
	}
}

// releaseCheckBackoff / releaseCheckMaxBackoff pace OnUnknownReleaseToken's
// retries. Vars so tests can shrink them.
var (
	releaseCheckBackoff    = 5 * time.Second
	releaseCheckMaxBackoff = 5 * time.Minute
)

// WireUnknownReleaseObserver installs the daemon's response to a peer
// advertising a release token this build does not know: a background
// OnUnknownReleaseToken, which refuses nothing. One function so the daemon
// and the fleet harness wire it the same way.
func WireUnknownReleaseObserver(ctx context.Context, c interface {
	SetUnknownReleaseTokenObserver(func(peer, token string))
}, ae *AntiEntropy) {
	c.SetUnknownReleaseTokenObserver(func(peer, tok string) {
		go ae.OnUnknownReleaseToken(ctx, peer, tok)
	})
}

// SetReplicationSourceGate injects the predicate deciding whether this node
// may take replicated state FROM peer (anti-entropy pulls; PushMutations
// consults the server's own copy). Nil allows every peer. Wired by the daemon
// to grpcapi.Server.ReleasePeerAllowed: once a feature of a latched release
// token is used, a peer that does not advertise the token is refused (I6).
func (c *Client) SetReplicationSourceGate(fn func(ctx context.Context, peer string) error) {
	if fn == nil {
		c.replicationSourceGate.Store(nil)
		return
	}
	c.replicationSourceGate.Store(&fn)
}

// ReplicationSourceAllowed reports whether this node may take state from peer.
// A node in release probation takes state from nobody (I-R3-1): the data of a
// first use can reach it with its record pruned away, so it waits for the
// probation pull, which is exempt, to ask a voter majority first.
func (c *Client) ReplicationSourceAllowed(ctx context.Context, peer string) error {
	if err := c.ReleaseProbationRefusal(); err != nil {
		return err
	}
	fn := c.replicationSourceGate.Load()
	if fn == nil {
		return nil
	}
	return (*fn)(ctx, peer)
}

// SetAdvertisedCapabilities injects what this node advertises, sent with every
// push as ReplicateRequest.sender_capabilities so a receiver can judge it
// without dialling back (grpcapi.Server.SetReplicator wires it).
func (r *Replicator) SetAdvertisedCapabilities(fn func() []string) {
	if fn == nil {
		r.advertised.Store(nil)
		return
	}
	r.advertised.Store(&fn)
}

// advertisedCapabilities is what the push declares. Unwired — a restart, before
// the server exists — it is this build's release tokens (I-R2-2): the claim a
// receiver checks is "this binary keeps the data", a fact about the build.
func (r *Replicator) advertisedCapabilities() []string {
	if fn := r.advertised.Load(); fn != nil {
		return (*fn)()
	}
	return capabilities.ReleaseTokens()
}
