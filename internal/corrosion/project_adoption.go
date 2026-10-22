package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/safename"
)

// Adoption gives a project born before project_incarnation_v1 latched (its
// row holds the incarnation "") a stable incarnation of its own
// (project_adoption, release_2027_01_v1). It NAMES that lifetime; it does
// not start another one.
//
// The adopted incarnation of a canonical name is adoptedProjectIncarnation:
// a function of the row's primary key alone, so every replica computes the
// one value. Every reader of a project's incarnation treats a row holding
// exactly that value (equality, never the "a" prefix) the way it treats ""
// (projectPreIncarnation): an untagged, none- or pre-tagged binding grants
// (projectBindingHeld), a pre-tagged one is never retired
// (retireOlderProjectGrants), the quota is the bare-name key
// (projectQuotaKey), the orphan reaper's guard and the anti-entropy dump
// rule take the two for one lifetime (projectIncarnationGuardMatches,
// projectsDumpDecision), and an exact-timestamp tie between a row holding ""
// and one holding the adopted value resolves to the adopted one
// (ruleProjectAdoptionAlias). So a receiver sees the same grants and the
// same quota before and after an adoption, in any WAL or anti-entropy order,
// and a late write of the "" lifetime (a pre-tagged grant, a bare-key quota)
// still counts.
//
// The one replicated write is projectsAdoptIncarnationSQL, which sets the
// incarnation and updated_at and never touches deleted_at, stamped
// justAfterTS(U) where U is the live row's updated_at re-read in the guarded
// transaction: every adopter of a name writes the identical statement, and
// any write made after U was observed (a delete, a revive) carries a later
// physical time and wins by plain LWW.
//
// Accepted residual (re-review Q-A, M-2): a write stamped in U's own
// millisecond that the adopter never saw can sort between U and
// justAfterTS(U). Two shapes reach it: a write by another node with the same
// physical and logical time and a lower node id, and U's own node writing its
// next tick (exactly justAfterTS(U)), which the WAL keeps local as a tied
// partial UPDATE and anti-entropy settles by the tombstone rule. U is a
// pre-latch write by construction (no write after the latch leaves a live ""
// row), so both need a write made in the same millisecond as a pre-latch
// write and never delivered to the adopter. On an anti-entropy-only path the
// first can reverse a delete/revive race of that millisecond.

// projectAdoptPrefix marks an adopted incarnation; readers compare the whole
// value (adoptedProjectIncarnation), never the prefix.
const projectAdoptPrefix = "a"

// adoptedProjectIncarnation is the incarnation adoption gives canonical
// project canon: "a" and the first 128 bits of
// SHA-256("litevirt/project-adopt/v1\x00" + canon), in hex. It is a wire
// value, pinned by a test.
func adoptedProjectIncarnation(canon string) string {
	sum := sha256.Sum256([]byte("litevirt/project-adopt/v1\x00" + canon))
	return projectAdoptPrefix + hex.EncodeToString(sum[:16])
}

// projectPreIncarnation reports whether inc names the lifetime a project of
// canonical name canon was born with before project_incarnation_v1 latched:
// "" or that name's adopted incarnation.
func projectPreIncarnation(canon, inc string) bool {
	return inc == "" || inc == adoptedProjectIncarnation(canon)
}

// projectPreIncarnationOfName is projectPreIncarnation for a row's name in any
// spelling. A name with no canonical form only has "".
func projectPreIncarnationOfName(name, inc string) bool {
	if inc == "" {
		return true
	}
	canon, err := safename.CanonicalProjectName(name)
	return err == nil && projectPreIncarnation(canon, inc)
}

// projectsAdoptIncarnationSQL gives a live pre-latch row its adopted
// incarnation. It sets no deleted_at, so on a receiver whose row is already a
// newer tombstone it changes nothing it would undo.
const projectsAdoptIncarnationSQL = `UPDATE projects SET incarnation = ?, updated_at = ? WHERE name = ?`

// ProjectAdoptionCandidate is a project the adoption pass may adopt.
type ProjectAdoptionCandidate struct {
	Name      string // the one live spelling
	UpdatedAt string // its updated_at when read
}

// ProjectAdoptionScan is what an adoption pass finds: the projects it may
// adopt and the canonical names it may not, because more than one spelling
// of the name is live (an "acme" beside an "/acme") and one of them holds "".
type ProjectAdoptionScan struct {
	Candidates       []ProjectAdoptionCandidate
	BlockedSpellings []string
}

// ScanProjectAdoption reads which projects still hold the pre-latch
// incarnation. It writes nothing, so a pass that finds no candidate never
// reaches the release gate (re-review I-2).
func ScanProjectAdoption(ctx context.Context, c *Client) (ProjectAdoptionScan, error) {
	rows, err := c.Query(ctx, `SELECT name, updated_at, incarnation FROM projects WHERE deleted_at IS NULL`)
	if err != nil {
		return ProjectAdoptionScan{}, err
	}
	type live struct{ name, at, inc string }
	byCanon := map[string][]live{}
	for _, r := range rows {
		canon, err := safename.CanonicalProjectName(r.String("name"))
		if err != nil || canon == "/" || canon == "/"+DefaultProject {
			continue
		}
		byCanon[canon] = append(byCanon[canon], live{r.String("name"), r.String("updated_at"), r.String("incarnation")})
	}
	var out ProjectAdoptionScan
	for canon, ls := range byCanon {
		pre := false
		for _, l := range ls {
			pre = pre || l.inc == ""
		}
		switch {
		case !pre:
		case len(ls) > 1:
			out.BlockedSpellings = append(out.BlockedSpellings, canon)
		default:
			out.Candidates = append(out.Candidates, ProjectAdoptionCandidate{Name: ls[0].name, UpdatedAt: ls[0].at})
		}
	}
	sort.Slice(out.Candidates, func(i, j int) bool { return out.Candidates[i].Name < out.Candidates[j].Name })
	sort.Strings(out.BlockedSpellings)
	return out, nil
}

// projectAdoptionHook, when set (tests only), runs after AdoptProjectIncarnation
// has read U and before its guarded transaction.
var projectAdoptionHook func()

// AdoptProjectIncarnation gives the live pre-latch project name its adopted
// incarnation, in one guarded entry: the row must still be live, the only
// live spelling of its canonical name, hold "", and have the updated_at read
// first. It reports whether it wrote. A row that already holds the adopted
// incarnation is done (false, nil); any other change since the read is false,
// nil, for the next pass to read again.
func AdoptProjectIncarnation(ctx context.Context, c *Client, g capabilities.FeatureGrant, name string) (bool, error) {
	if err := g.Check(capabilities.FeatureProjectAdoption); err != nil {
		return false, err
	}
	canon, err := safename.CanonicalProjectName(name)
	if err != nil || canon == "/" || canon == "/"+DefaultProject {
		return false, fmt.Errorf("project %q has no incarnation to adopt", name)
	}
	rows, err := c.Query(ctx, `SELECT updated_at, incarnation FROM projects WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 || rows[0].String("incarnation") != "" {
		return false, nil
	}
	u := rows[0].String("updated_at")
	at, ok := justAfterTS(u)
	if !ok {
		return false, fmt.Errorf("project %q: updated_at %q is not a timestamp", name, u)
	}
	if h := projectAdoptionHook; h != nil {
		h()
	}
	adopted := adoptedProjectIncarnation(canon)
	return c.executeGuardedLifecycleBatch(ctx, func(tx *sql.Tx) (bool, error) {
		var upd string
		var deleted sql.NullString
		var inc string
		err := tx.QueryRowContext(ctx, `SELECT deleted_at, updated_at, incarnation FROM projects WHERE name = ?`, name).Scan(&deleted, &upd, &inc)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if deleted.Valid || upd != u || inc != "" {
			return false, nil
		}
		states, err := loadProjectStatesTx(ctx, tx)
		if err != nil {
			return false, err
		}
		return len(states[canon].live) == 1, nil
	}, []Statement{{SQL: projectsAdoptIncarnationSQL, Params: []interface{}{adopted, at, name}}}, "project", name, "rotate")
}

// ruleProjectAdoptionAlias resolves an exact-timestamp tie of two projects
// rows that differ only in their incarnation, one holding "" and the other
// the name's adopted incarnation, to the adopted one: the two name one
// lifetime, so neither side's grants or quota change. It reaches a tie when
// a delete overtakes the adoption on some receivers (re-review I-1); without
// it the policy chain leaves the split unresolved for good.
func ruleProjectAdoptionAlias() tieRule {
	return func(rv rowView) tieDecision {
		if !rv.has("incarnation") || !rv.has("name") {
			return pass
		}
		l, in := rv.localStr("incarnation"), rv.incomingStr("incarnation")
		if l == in || (l != "" && in != "") {
			return pass
		}
		canon, err := safename.CanonicalProjectName(rv.localStr("name"))
		if err != nil {
			return pass
		}
		adopted := adoptedProjectIncarnation(canon)
		if l != adopted && in != adopted {
			return pass
		}
		for _, col := range rv.cols {
			if col != "incarnation" && rv.localStr(col) != rv.incomingStr(col) {
				return pass
			}
		}
		if l == adopted {
			return decideKeepLocal("project_adoption")
		}
		return decideTakeIncoming("project_adoption")
	}
}

// projectsTieChain is the projects table's tie chain: the adoption alias
// ahead of the policy chain.
func projectsTieChain() []tieRule {
	return append([]tieRule{ruleProjectAdoptionAlias()}, policyChain()...)
}
