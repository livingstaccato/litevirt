package corrosion

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// A host's managed fence SSH publication (schema v72, release feature
// fence_ssh under release_2026_12_v1).
//
// WHAT IT IS. One row per host, written only by that host's daemon: the public
// half of its fence key, the public keys of its sshd, whether its sshd reads
// the rendered authorized_keys for every peer's address, and the CA-issued
// certificate whose key signed all of it (internal/fencessh). Every daemon
// verifies every row against the cluster CA and the CRL before it renders a
// peer's key into its authorized_keys or pins a peer's host key, so the row is
// not trusted for being here: a node can write a row naming another host, and
// the signature check refuses it.
//
// ONE ROW, ONE CLOCK. Every write replaces the whole row under its own
// updated_at, like host_fence_redfish. Nothing compares it with the hosts
// row's clock.
//
// WHO MAY WRITE. A previous-release node cannot decode the table's
// statements, so its only writer, PutHostFenceSSH, takes fence_ssh's grant:
// the gate opens once every host this node replicates to runs a build that
// knows the table, and records the use first.
//
// A REMOVED OR RE-ADMITTED HOST. Its row is retired locally on apply, beside
// its fence credential (retireReadmittedCredentials): the removed machine's
// fence key leaves every peer's authorized_keys, and a re-admitted machine
// publishes its own.

// HostFenceSSHUpsertSQL is the row's one replicated shape: an explicit upsert
// on the primary key (DispExplicitUpsert, revives a tombstone).
const HostFenceSSHUpsertSQL = `INSERT INTO host_fence_ssh (host_name, generation, fence_pubkeys, sshd_hostkeys, accepting, ever_accepting, detail, cert_pem, signature, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET generation = excluded.generation, fence_pubkeys = excluded.fence_pubkeys,
		   sshd_hostkeys = excluded.sshd_hostkeys, accepting = excluded.accepting, ever_accepting = excluded.ever_accepting,
		   detail = excluded.detail, cert_pem = excluded.cert_pem, signature = excluded.signature,
		   updated_at = excluded.updated_at, deleted_at = NULL`

// HostFenceSSHRow is one host_fence_ssh row as stored.
type HostFenceSSHRow struct {
	HostName      string
	Generation    int64
	FencePubkeys  string
	SSHDHostkeys  string
	Accepting     bool
	EverAccepting bool
	Detail        string
	CertPEM       string
	Signature     string
	UpdatedAt     string
	// Deleted: the row is a tombstone (the host was removed or re-admitted).
	Deleted bool
}

// PutHostFenceSSH writes host's fence SSH row. It is fence_ssh's data, so it
// takes the feature's grant (release_features.go); the caller signs the row
// first (internal/fencessh).
func PutHostFenceSSH(ctx context.Context, c *Client, g capabilities.FeatureGrant, r HostFenceSSHRow) error {
	if err := g.Check(capabilities.FeatureFenceSSH); err != nil {
		return err
	}
	if r.HostName == "" {
		return fmt.Errorf("fence ssh row names no host")
	}
	return c.Execute(ctx, HostFenceSSHUpsertSQL, r.HostName, r.Generation, r.FencePubkeys, r.SSHDHostkeys,
		boolInt(r.Accepting), boolInt(r.EverAccepting), r.Detail, r.CertPEM, r.Signature, c.NowTS())
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const hostFenceSSHColumns = `host_name, generation, fence_pubkeys, sshd_hostkeys, accepting, ever_accepting, detail, cert_pem, signature, updated_at, deleted_at`

// GetHostFenceSSH reads host's row, tombstone included; ok is false when the
// host has none.
func GetHostFenceSSH(ctx context.Context, c *Client, host string) (r HostFenceSSHRow, ok bool, err error) {
	rows, err := c.Query(ctx, `SELECT `+hostFenceSSHColumns+` FROM host_fence_ssh WHERE host_name = ?`, host)
	if err != nil || len(rows) == 0 {
		return HostFenceSSHRow{}, false, err
	}
	return hostFenceSSHFromRow(rows[0]), true, nil
}

// ListHostFenceSSH reads every row, tombstones included, by host name.
func ListHostFenceSSH(ctx context.Context, c *Client) ([]HostFenceSSHRow, error) {
	rows, err := c.Query(ctx, `SELECT `+hostFenceSSHColumns+` FROM host_fence_ssh ORDER BY host_name`)
	if err != nil {
		return nil, err
	}
	out := make([]HostFenceSSHRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, hostFenceSSHFromRow(r))
	}
	return out, nil
}

func hostFenceSSHFromRow(r Row) HostFenceSSHRow {
	return HostFenceSSHRow{
		HostName:      r.String("host_name"),
		Generation:    r.Int64("generation"),
		FencePubkeys:  r.String("fence_pubkeys"),
		SSHDHostkeys:  r.String("sshd_hostkeys"),
		Accepting:     r.Int64("accepting") != 0,
		EverAccepting: r.Int64("ever_accepting") != 0,
		Detail:        r.String("detail"),
		CertPEM:       r.String("cert_pem"),
		Signature:     r.String("signature"),
		UpdatedAt:     r.String("updated_at"),
		Deleted:       r.String("deleted_at") != "",
	}
}

// retireFenceSSH retires host's fence SSH row as retireFenceRedfish retires
// its Redfish row: locally, stamped with the removal's or admission's own
// updatedAt, only over a row older than that, and never logged, so every node
// derives the same tombstone from the same statement. The key material is
// cleared with it: a tombstone renders nothing.
func retireFenceSSH(ctx context.Context, tx *sql.Tx, host, updatedAt string) error {
	var cur string
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT updated_at, deleted_at FROM host_fence_ssh WHERE host_name = ?`, host).Scan(&cur, &deleted)
	switch {
	case err == sql.ErrNoRows:
		return nil
	case err != nil:
		return err
	case deleted.Valid && deleted.String != "":
		return nil
	case lwwOrder(cur, updatedAt) >= 0:
		return nil
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE host_fence_ssh SET fence_pubkeys = '', sshd_hostkeys = '', accepting = 0, ever_accepting = 0, signature = '',
		 deleted_at = ?, updated_at = ? WHERE host_name = ?`, updatedAt, updatedAt, host)
	return err
}
