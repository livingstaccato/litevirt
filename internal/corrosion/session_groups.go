package corrosion

// session_groups (schema v65): the directory groups a session's external-realm
// login verified — the OIDC realm's groups claim from a verified ID token, the
// LDAP realm's group search — so `group:<g>@<realm>` role bindings apply to
// that session and to no other.
//
// The groups are a snapshot taken at login and live as long as the session.
// A group the directory removes stops granting at the user's next login
// (that session's snapshot lacks it); a session already minted keeps its
// snapshot until it ends (idle timeout, hard expiry, logout, `lv session
// revoke`, or an account lifecycle change). Per session rather than per user
// so the groups travel in the session's own batch: every node that can see
// the session sees exactly the groups it was minted with, never a newer or
// older login's.
//
// Written only with a grant for capabilities.FeatureLoginPolicy: a
// previous-release peer cannot decode the table's statements. Without the
// grant the session is written alone and carries no groups, as before the
// release (group bindings then apply to nobody). Left out of anti-entropy like
// sessions.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// Bounds on what one login records: a directory that returns thousands of
// groups (or enormous names) cannot bloat every replica's session rows.
const (
	MaxSessionGroups     = 256
	MaxSessionGroupBytes = 256
)

const sessionGroupsInsertSQL = `INSERT INTO session_groups (session_id, realm, groups_json, recorded_at, updated_at) VALUES (?, ?, ?, ?, ?)`

// NormalizeSessionGroups is the set a session records: trimmed, empty and
// over-long names dropped, de-duplicated, sorted, at most MaxSessionGroups.
// It reports how many names it dropped, so the caller can say so.
func NormalizeSessionGroups(groups []string) (out []string, dropped int) {
	seen := map[string]bool{}
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" || len(g) > MaxSessionGroupBytes || strings.ContainsAny(g, "\x00\r\n") {
			dropped++
			continue
		}
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	if len(out) > MaxSessionGroups {
		dropped += len(out) - MaxSessionGroups
		out = out[:MaxSessionGroups]
	}
	return out, dropped
}

// InsertSessionWithLoginData creates a session row and, in the same batch, the
// login data the release feature login_policy carries: the second factor the
// login presented (session_factors, when factor is set) and the directory
// groups it verified (session_groups, when groups is not empty). Without a
// grant for capabilities.FeatureLoginPolicy neither is recorded and the
// session is written alone, which only ever narrows it.
func InsertSessionWithLoginData(ctx context.Context, c *Client, g capabilities.FeatureGrant, s SessionRecord, factor string, groups []string) error {
	if g.Check(capabilities.FeatureLoginPolicy) != nil || (factor == "" && len(groups) == 0) {
		return InsertSession(ctx, c, s)
	}
	stmts := []Statement{sessionInsertStatement(s)}
	now := c.NowTS()
	if factor != "" {
		stmts = append(stmts, Statement{SQL: sessionFactorInsertSQL, Params: []interface{}{s.ID, factor, s.CreatedAt, now}})
	}
	if len(groups) > 0 {
		norm, _ := NormalizeSessionGroups(groups)
		if len(norm) > 0 {
			b, err := json.Marshal(norm)
			if err != nil {
				return fmt.Errorf("encode session groups: %w", err)
			}
			stmts = append(stmts, Statement{SQL: sessionGroupsInsertSQL, Params: []interface{}{s.ID, s.Realm, string(b), s.CreatedAt, now}})
		}
	}
	return c.ExecuteBatch(ctx, stmts)
}

// SessionGroups returns the directory groups session id's login verified, nil
// for none. The groups are returned only for the realm the session was
// minted in. A read that fails is an error, never "no groups".
func SessionGroups(ctx context.Context, c *Client, id, realm string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT realm, groups_json FROM session_groups WHERE session_id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || rows[0].String("realm") != realm {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(rows[0].String("groups_json")), &out); err != nil {
		return nil, fmt.Errorf("session %s groups: %w", id, err)
	}
	return out, nil
}
