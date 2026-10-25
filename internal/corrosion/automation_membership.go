package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Automation across voter-membership changes (F1 Task 5).
//
// Automation authority (local_automation_authority) is bound to one adopted
// generation, its exact member set and this voter's incarnation, so every
// membership change ends it unless the adoption itself carries it forward.
// Only the ordinary certified transition carries it, and only in the same
// transaction that merges the sealed old majority's claim state (accepted
// envelopes and promises, ImportClaimsAndAdopt's merge) and records the
// adoption. A forced generation, a reset, a non-member adoption or a voter
// whose authority does not hold at the generation it leaves never carries it:
// that node is simply not automation-ready afterwards (fail closed).
//
// A voter that carries authority already holds its certified prefix locally:
// the authority row exists only beside a retained history whose anchors it
// verified. A lagging carried voter refuses to accept beyond its own certified
// parent until it catches up through the existing authenticated prefix fetch.
// A voter NEW to the electorate holds no prefix and gets no authority here; it
// gains both through the certified-prefix import (automation_import.go).

// ImportClaimsAndAdoptAutomation is ImportClaimsAndAdopt for an ordinary
// certified transition: the same merge and adoption, and in the same
// transaction the automation authority this voter held at newGen-1 moves to
// newGen when newGen keeps it as a member under its own incarnation and is an
// automation-eligible electorate (at least three members, within the
// certificate budget).
func (c *Client) ImportClaimsAndAdoptAutomation(ctx context.Context, newGen int64, from []string, states []ClaimVoterState) (int, error) {
	return c.importClaimsAndAdopt(ctx, newGen, from, states, true)
}

// carryAutomationAuthorityTx moves this voter's automation authority from
// newGen-1 to newGen, or leaves it where it is (and so invalid at newGen).
// It runs before the adoption row is written, so the standing it reads is the
// generation being left.
func carryAutomationAuthorityTx(ctx context.Context, tx *LocalTx, self string, newGen int64) error {
	prev := newGen - 1
	if _, err := automationEstablishedAuthorityTx(ctx, tx, self, prev); err != nil {
		if errors.Is(err, errAutomationAuthority) {
			return nil // nothing established to carry
		}
		return err
	}
	rows, err := tx.Query(ctx, `SELECT `+voterConfigCols+` FROM voter_configs WHERE generation = ? AND deleted_at IS NULL`, newGen)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("voter generation %d has no voter_configs row", newGen)
	}
	next, err := scanVoterConfig(rows[0])
	if err != nil {
		return err
	}
	if IsForcedChange(next.Change) || !next.Explicit() || len(next.Members) < 3 || automationElectorateBudget(next.Members) != nil {
		return nil
	}
	rows, err = tx.Query(ctx, `SELECT incarnation FROM local_voter_incarnation WHERE id = 1`)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("no voter incarnation recorded")
	}
	inc := rows[0].String("incarnation")
	if m, ok := next.Member(self); !ok || m.Incarnation != inc {
		return nil
	}
	res, err := tx.Exec(ctx, `UPDATE local_automation_authority SET generation = ?, members_hash = ?
		WHERE id = 1 AND generation = ? AND incarnation = ?`, newGen, MembersHash(next.Members), prev, inc)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("carry automation authority to generation %d: %d rows, %v", newGen, n, err)
	}
	return nil
}

// AutomationUsed reports whether this replica holds any automation state: an
// authority row (at any generation), retained certified history, or claim
// state for an automation slot. detail names the first found. An error is
// never "unused".
func (c *Client) AutomationUsed(ctx context.Context) (used bool, detail string, err error) {
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var err error
		used, detail, err = automationUsedTx(ctx, tx)
		return err
	})
	return used, detail, err
}

func automationUsedTx(ctx context.Context, tx *LocalTx) (used bool, detail string, err error) {
	for _, q := range []struct {
		what, sql string
		args      []any
	}{
		{"automation authority", `SELECT 1 AS one FROM local_automation_authority LIMIT 1`, nil},
		{"certified automation history", `SELECT 1 AS one FROM local_automation_history LIMIT 1`, nil},
		{"automation claim state", `SELECT 1 AS one FROM local_recovery_claims WHERE target_kind = ? LIMIT 1`, []any{ClaimKindAutomation}},
	} {
		rows, err := tx.Query(ctx, q.sql, q.args...)
		if err != nil {
			return false, "", err
		}
		if len(rows) > 0 {
			return true, q.what, nil
		}
	}
	return false, "", nil
}

// refuseResetTx is the voter's half of the reset guard: a voter holding
// automation state never accepts a reset, whichever node coordinates it. A
// reset re-derives the voter set without importing from the old majority, so
// adopting it would strand every voter's automation authority. Returns the
// refusal detail, "" to accept.
func refuseResetTx(ctx context.Context, tx *LocalTx, self string, key ClaimKey, v *ClaimValue) (string, error) {
	if !key.IsVoterConfig() || v == nil || v.Config == nil || v.Config.Change != VoterChangeReset {
		return "", nil
	}
	used, what, err := automationUsedTx(ctx, tx)
	if err != nil || !used {
		return "", err
	}
	return fmt.Sprintf("%s holds %s, and a voter reset imports nothing from the old voter majority, so it would "+
		"strand automation; this build has no automation recovery proof for it", self, what), nil
}

// AutomationMembershipStanding is this voter's automation membership as one
// transaction read it.
type AutomationMembershipStanding struct {
	// Generation is the adopted voter generation (0: none).
	Generation int64
	// Voters is the adopted generation's member count (0: none, or implicit).
	Voters int
	// Imported: this voter holds automation authority at Generation — its
	// adoption of Generation carried its complete state (or Generation is the
	// one its authority was established at).
	Imported bool
	// ImportedVoters are the members of Generation, under their member
	// incarnation, with durable local evidence that they hold automation
	// authority there: this voter when Imported, and every signer of a
	// verified automation certificate this replica anchored at Generation (a
	// voter signs an automation accept only under its own authority at that
	// generation). A member that has not signed anything at Generation yet is
	// not counted: absence of evidence is not readiness.
	ImportedVoters []string
	// Detail says why Imported is false.
	Detail string
}

// AutomationMembershipStanding reports this voter's automation membership standing.
func (c *Client) AutomationMembershipStanding(ctx context.Context) (AutomationMembershipStanding, error) {
	var out AutomationMembershipStanding
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return err
		}
		out.Generation = st.adopted
		if st.cfg == nil || !st.cfg.Explicit() {
			out.Detail = "no voter generation with members is adopted"
			return nil
		}
		out.Voters = len(st.cfg.Members)
		evidenced, err := automationEvidencedVotersTx(ctx, tx, st.cfg)
		if err != nil {
			return err
		}
		_, err = automationEstablishedAuthorityTx(ctx, tx, c.hostName, st.adopted)
		if err == nil {
			out.Imported = true
			evidenced[c.hostName] = true
		}
		for name := range evidenced {
			out.ImportedVoters = append(out.ImportedVoters, name)
		}
		sort.Strings(out.ImportedVoters)
		if out.Imported {
			return nil
		}
		if !errors.Is(err, errAutomationAuthority) {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT generation FROM local_automation_authority WHERE id = 1`)
		if err != nil {
			return err
		}
		switch {
		case len(rows) == 0:
			out.Detail = fmt.Sprintf("%s holds no automation authority: it joined the electorate without importing the "+
				"certified automation prefix, or automation was never established here", c.hostName)
		case rows[0].Int64("generation") != st.adopted:
			out.Detail = fmt.Sprintf("%s's automation authority is for voter generation %d, not the adopted %d: an "+
				"adoption that did not carry its complete automation state (forced, reset or not a member)",
				c.hostName, rows[0].Int64("generation"), st.adopted)
		default:
			out.Detail = fmt.Sprintf("%s's automation authority does not match voter generation %d's members, its "+
				"incarnation or an eligible electorate", c.hostName, st.adopted)
		}
		return nil
	})
	return out, err
}

// automationEvidenceAnchors bounds how many of the newest anchors at the
// adopted generation are read for signer evidence.
const automationEvidenceAnchors = 64

// automationEvidencedVotersTx returns the members of cfg (by name, under
// their member incarnation) that signed an accept in an automation
// certificate anchored at cfg's generation, newest first, bounded.
func automationEvidencedVotersTx(ctx context.Context, tx *LocalTx, cfg *VoterConfig) (map[string]bool, error) {
	out := map[string]bool{}
	rows, err := tx.Query(ctx, `SELECT certificate FROM local_automation_anchors WHERE generation = ?
		ORDER BY sequence DESC LIMIT ?`, cfg.Generation, automationEvidenceAnchors)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		cert, err := DecodeClaimCertificate(r.String("certificate"))
		if err != nil || cert.ConfigGeneration != cfg.Generation {
			continue
		}
		for _, a := range cert.Accepts {
			if m, ok := cfg.Member(a.Voter); ok && m.Incarnation == a.VoterIncarnation && a.ConfigGeneration == cfg.Generation {
				out[a.Voter] = true
			}
		}
		if len(out) == len(cfg.Members) {
			break
		}
	}
	return out, nil
}

// clusterPolicyAutomationOrigin is the cluster_policies key of the automation
// origin record: the founder of a cluster created on a build with automation
// writes it once (daemon seedAdminUser → grpcapi SeedAutomationOriginLoop).
const clusterPolicyAutomationOrigin = "automation_origin"

// AutomationOrigin is the founding fact automation readiness requires: this
// cluster was founded by `lv host init` on a build that knows automation, so
// its absence of automation history is genuine, not lost. A cluster without
// it — founded earlier — is not automation-ready; there is no cutover.
type AutomationOrigin struct {
	Version   int    `json:"version"`
	Founder   string `json:"founder"`
	FoundedAt string `json:"founded_at"`
}

// GetAutomationOrigin reads the origin record. ok is false when there is
// none. A row that does not decode as version 1 is an error, never absent.
func GetAutomationOrigin(ctx context.Context, c *Client) (AutomationOrigin, bool, error) {
	raw, have, err := clusterPolicyValue(ctx, c, clusterPolicyAutomationOrigin)
	if err != nil || !have {
		return AutomationOrigin{}, false, err
	}
	var o AutomationOrigin
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil || o.Version != 1 || o.Founder == "" || o.FoundedAt == "" {
		return AutomationOrigin{}, false, fmt.Errorf("unreadable automation origin record %q", raw)
	}
	return o, true, nil
}

// SeedAutomationOrigin records the origin, founded by founder, once the
// cluster_policies gate is open. wrote is false when a record already exists
// (it is never replaced) or the gate is still closed.
func SeedAutomationOrigin(ctx context.Context, c *Client, founder string) (wrote bool, err error) {
	if _, have, err := clusterPolicyValue(ctx, c, clusterPolicyAutomationOrigin); err != nil || have {
		return false, err
	}
	if !c.MayWriteClusterPolicy() {
		return false, nil
	}
	now := c.NowTS()
	raw, err := json.Marshal(AutomationOrigin{Version: 1, Founder: founder, FoundedAt: now})
	if err != nil {
		return false, err
	}
	if err := c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyAutomationOrigin, string(raw), "litevirt (founding)", now); err != nil {
		return false, err
	}
	return true, nil
}
