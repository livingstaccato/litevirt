package corrosion

// Release-feature USED records (capabilities.ReleaseToken).
//
// A release token latches once every host this node replicates to runs a build
// that keeps the release's new data. A feature of the release is opened through
// health.Checker.RequireFeature, which on the feature's first use writes one
// row here, release_feature/<token>/<feature>, before its caller writes the
// feature's data. The row is how a node rolled back onto an older build learns
// whether that build can keep running: none for a token means no feature of it
// ever wrote anything, so its activation marker's `rollback: safe_if_unused`
// rule lets the node start unquarantined.
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
// THE ROLLED-BACK READER. A node rolled back onto this build from a later one
// may start before the later release's first use reaches it (its preflight
// read an empty set). Replication then delivers the record and, right behind
// it on the same ordered stream, the feature's data. So the record is checked
// as it ARRIVES: a use of a token this binary does not know trips the WAL
// quarantine before the next statement is applied (WAL), or before the payload
// is merged (anti-entropy). From then on this node emits no replicated write,
// so it cannot rewrite the feature's data away.

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// releaseFeatureKeyPrefix prefixes every used record's cluster_policies key.
const releaseFeatureKeyPrefix = "release_feature/"

// releaseFeatureUsedValue is a record's value. The key carries everything; the
// value is fixed so a record replayed by two first users converges.
const releaseFeatureUsedValue = "used"

// ReleaseFeatureUse is one recorded use of a release feature.
type ReleaseFeatureUse struct {
	Token   string
	Feature string
	// FirstUsedBy is the host that recorded the use (the last writer, when two
	// hosts recorded a first use at once).
	FirstUsedBy string
	UpdatedAt   string
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
// Callers go through health.Checker.RequireFeature, which owns the release
// token's latch; this function owns only what keeps a peer's stream alive.
func RecordReleaseFeatureUse(ctx context.Context, c *Client, token, feature, host string) error {
	if !validReleaseName(token) || !validReleaseName(feature) {
		return fmt.Errorf("release feature record: malformed token %q or feature %q", token, feature)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, releaseFeatureKey(token, feature),
		releaseFeatureUsedValue, host, c.NowTS())
}

// ReleaseFeatureUsed reports whether this replica holds a use of feature.
func ReleaseFeatureUsed(ctx context.Context, c *Client, token, feature string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT 1 AS one FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		releaseFeatureKey(token, feature))
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// ListReleaseFeatureUses returns every use this replica holds, of any token —
// including tokens this build does not know — sorted by token and feature.
func ListReleaseFeatureUses(ctx context.Context, c *Client) ([]ReleaseFeatureUse, error) {
	lo, hi := keyRange(releaseFeatureKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, set_by, updated_at FROM cluster_policies
		 WHERE key >= ? AND key < ? AND deleted_at IS NULL ORDER BY key`, lo, hi)
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
			FirstUsedBy: r.String("set_by"), UpdatedAt: r.String("updated_at")})
	}
	return out, nil
}

// ReleaseTokenKnown reports whether this build knows token: a live token, or
// a retired one an older build latched.
func ReleaseTokenKnown(token string) bool {
	return capabilities.Has(capabilities.All(), token) || capabilities.Retired(token)
}

// ReleaseUseQuarantine lists, sorted, the tokens this binary does not know
// whose feature use has arrived since start. Non-empty means the node is
// WAL-quarantined: it is running a build older than the one that used them.
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

// releaseUseQuarantineReason is the write refusal while tripped, or "".
func (c *Client) releaseUseQuarantineReason() string {
	toks := c.ReleaseUseQuarantine()
	if len(toks) == 0 {
		return ""
	}
	return "a feature of a newer release this build does not know is in use: " + strings.Join(toks, ",")
}

// noteReleaseFeatureKey trips the quarantine when key records a use of a token
// this build does not know. Any other key is ignored. It FAILS CLOSED on the
// record's presence alone, tombstoned or not: nothing writes a tombstone on a
// used record, so one is not evidence the use is over.
func (c *Client) noteReleaseFeatureKey(key string, via string) {
	token, feature, ok := parseReleaseFeatureKey(key)
	if !ok || ReleaseTokenKnown(token) {
		return
	}
	c.releaseUseMu.Lock()
	if c.releaseUseTripped == nil {
		c.releaseUseTripped = map[string]bool{}
	}
	already := c.releaseUseTripped[token]
	c.releaseUseTripped[token] = true
	c.releaseUseMu.Unlock()
	if !already {
		slog.Error("release feature: a feature of a release this build does not know is in use; "+
			"entering WAL quarantine — no replicated writes will be emitted until this node is "+
			"upgraded again or reseeded by an operator",
			"token", token, "feature", feature, "via", via)
	}
}

// noteReleaseUseStatements checks one WAL entry's statements, before any of
// them is applied.
func (c *Client) noteReleaseUseStatements(stmts []Statement) {
	for _, s := range stmts {
		if len(s.Params) == 0 || !strings.Contains(s.SQL, "cluster_policies") ||
			structuralTableLabel(s.SQL) != "cluster_policies" {
			continue
		}
		if key, ok := s.Params[0].(string); ok {
			c.noteReleaseFeatureKey(key, "replication")
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
