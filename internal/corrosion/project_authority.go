package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// D1 — project-admission authority. Project quota is a HARD admission guarantee, so
// one deterministic holder per NORMALIZED project serializes it. Authority is
// STICKY: the initial holder is minted once; it does not move merely because
// membership changes. A PLANNED handoff records an explicit transfer; an UNPLANNED
// takeover requires PROOF-GRADE fencing of the prior holder (a fence_proof_ref).
// Every transfer mints a monotonic authority_epoch; admission accepts reservations
// only from the CURRENT epoch, so a stale ex-holder's writes are rejected.

// ErrFenceProofRequired is returned when an unplanned ("fenced") takeover is
// attempted without a proof reference for the prior holder's fence.
var ErrFenceProofRequired = errors.New("corrosion: a fenced project-authority takeover requires a fence_proof_ref")

// ProjectAuthority is a project's admission-authority record. The CURRENT authority
// is the row with the maximum live authority_epoch for the project.
type ProjectAuthority struct {
	Project       string
	Epoch         int64
	Holder        string
	TransferKind  string // initial | planned | fenced
	FenceProofRef string
}

// DeterministicInitialProjectAuthority selects the sole host allowed to mint a
// project's epoch 1 authority. Membership is canonicalized so every node with
// the same active worker set reaches the same answer regardless of row order.
func DeterministicInitialProjectAuthority(project string, hosts []HostRecord) (string, error) {
	project = projectOrDefault(strings.TrimSpace(project))
	eligible := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host.State == "active" && !host.IsWitness() && host.Name != "" {
			eligible = append(eligible, host.Name)
		}
	}
	sort.Strings(eligible)
	unique := eligible[:0]
	for _, name := range eligible {
		if len(unique) == 0 || unique[len(unique)-1] != name {
			unique = append(unique, name)
		}
	}
	if len(unique) == 0 {
		return "", fmt.Errorf("no active non-witness host can hold project authority")
	}
	sum := sha256.Sum256([]byte(project))
	var n uint64
	for _, b := range sum[:8] {
		n = n<<8 | uint64(b)
	}
	return unique[n%uint64(len(unique))], nil
}

// CurrentProjectAuthority returns the highest live authority epoch for a project,
// or ok=false when the project has no authority yet.
func CurrentProjectAuthority(ctx context.Context, c *Client, project string) (ProjectAuthority, bool, error) {
	project = projectOrDefault(project)
	rows, err := c.Query(ctx,
		`SELECT project, authority_epoch, holder, transfer_kind, fence_proof_ref
		 FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL
		 ORDER BY authority_epoch DESC LIMIT 1`, project)
	if err != nil {
		return ProjectAuthority{}, false, err
	}
	if len(rows) == 0 {
		return ProjectAuthority{}, false, nil
	}
	r := rows[0]
	return ProjectAuthority{
		Project:       r.String("project"),
		Epoch:         r.Int64("authority_epoch"),
		Holder:        r.String("holder"),
		TransferKind:  r.String("transfer_kind"),
		FenceProofRef: r.String("fence_proof_ref"),
	}, true, nil
}

// ClaimInitialProjectAuthority mints epoch 1 for a project with holder, iff no
// authority exists yet. Returns applied=false (no error) if another node already
// established authority (the caller re-reads the current holder).
func ClaimInitialProjectAuthority(ctx context.Context, c *Client, project, holder string) (applied bool, err error) {
	project = projectOrDefault(project)
	now, wall := c.NowTS(), nowRFC3339()
	guard := func(tx *sql.Tx) (bool, error) {
		var n int
		qerr := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL`, project).Scan(&n)
		return n == 0, qerr
	}
	stmts := []Statement{{
		SQL: `INSERT OR IGNORE INTO project_authority_epochs
		      (project, authority_epoch, holder, transfer_kind, fence_proof_ref, created_at, updated_at, deleted_at)
		      VALUES (?, 1, ?, 'initial', '', ?, ?, NULL)`,
		Params: []interface{}{project, holder, wall, now},
	}}
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// TakeoverProjectAuthority mints epoch = expectedPrevEpoch+1 with the new holder.
// transferKind must be "planned" (an explicit relinquish/handoff) or "fenced" (an
// unplanned takeover, which REQUIRES fenceProofRef — proof the prior holder was
// fenced). Returns applied=false (no error) on a CAS miss (the current epoch is no
// longer expectedPrevEpoch — someone else transferred first).
func TakeoverProjectAuthority(ctx context.Context, c *Client, project, holder, transferKind, fenceProofRef string, expectedPrevEpoch int64) (newEpoch int64, applied bool, err error) {
	project = projectOrDefault(project)
	switch transferKind {
	case "planned":
	case "fenced":
		if fenceProofRef == "" {
			return 0, false, ErrFenceProofRequired
		}
	default:
		return 0, false, fmt.Errorf("corrosion: invalid project-authority transfer_kind %q (want planned|fenced)", transferKind)
	}
	newEpoch = expectedPrevEpoch + 1
	now, wall := c.NowTS(), nowRFC3339()
	guard := func(tx *sql.Tx) (bool, error) {
		var maxEpoch sql.NullInt64
		qerr := tx.QueryRowContext(ctx,
			`SELECT MAX(authority_epoch) FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL`, project).Scan(&maxEpoch)
		if qerr != nil {
			return false, qerr
		}
		return maxEpoch.Valid && maxEpoch.Int64 == expectedPrevEpoch, nil
	}
	stmts := []Statement{{
		SQL: `INSERT OR IGNORE INTO project_authority_epochs
		      (project, authority_epoch, holder, transfer_kind, fence_proof_ref, created_at, updated_at, deleted_at)
		      VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		Params: []interface{}{project, newEpoch, holder, transferKind, fenceProofRef, wall, now},
	}}
	applied, err = c.ExecuteBatchGuarded(ctx, guard, stmts)
	return newEpoch, applied, err
}

// ValidateProjectAuthority reports whether (project, epoch, holder) is the CURRENT
// authority — the admission check that rejects a stale ex-holder's reservation.
func ValidateProjectAuthority(ctx context.Context, c *Client, project string, epoch int64, holder string) (bool, error) {
	cur, ok, err := CurrentProjectAuthority(ctx, c, project)
	if err != nil || !ok {
		return false, err
	}
	return cur.Epoch == epoch && cur.Holder == holder, nil
}
