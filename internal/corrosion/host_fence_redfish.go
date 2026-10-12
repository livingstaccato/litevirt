package corrosion

import (
	"context"
	"database/sql"

	"github.com/litevirt/litevirt/internal/fence"
)

// A host's Redfish BMC settings (fence_strategy = 'redfish'), schema v67.
//
// WHERE THEY LIVE. host_fence_redfish, on the sensitive lane beside
// host_fence_credentials (sensitiveTableNames): the row carries the BMC
// password, so it travels only peer-to-peer and never in the operator-safe
// state dump, and none of it is ever written to the hosts row. The ipmi
// strategy's password reached hosts.ipmi_pass first and is still being moved
// off it (credentials_split.go, credentials-clear.md); Redfish is new data
// and starts where that move ends.
//
// ONE ROW, ONE CLOCK. Every write replaces the whole row under its own
// updated_at, and readers take it whenever a live row exists. Nothing compares
// it with the hosts row's updated_at, which unrelated writes bump (the
// credentials split's #267 rule).
//
// WHO MAY WRITE. A previous-release node cannot decode the table's
// statements, and reads a 'redfish' fence strategy as best-effort SSH
// (fence.ResolveStrategy's fallback). So both are the data of the release
// feature redfish_fence: ConfigureHost writes both through the feature's gate,
// and the row's writer (grpcapi hostFenceRedfishStatement) takes its grant. The gate opens
// only once every host this node replicates to runs a build that knows both,
// and a node rolled back below the release after a use quarantines itself
// rather than fence a 'redfish' host with SSH.
//
// A REMOVED OR RE-ADMITTED HOST. Its row is retired locally on apply with the
// fence credential (retireFenceCredential), for the same reason: the new
// machine must not be fenced with the old machine's BMC.

// The writers' shapes; the writer is grpcapi's hostFenceRedfishStatement,
// which takes redfish_fence's grant. HostFenceRedfishUpsertSQL is an explicit
// upsert on the primary key (DispExplicitUpsert, revives a tombstone);
// HostFenceRedfishClearSQL is a full-primary-key update that binds updated_at
// (DispFullPKUpdate).
const (
	HostFenceRedfishUpsertSQL = `INSERT INTO host_fence_redfish (host_name, endpoint, username, password, system_id, auth, ca_pem, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET endpoint = excluded.endpoint, username = excluded.username,
		   password = excluded.password, system_id = excluded.system_id, auth = excluded.auth,
		   ca_pem = excluded.ca_pem, updated_at = excluded.updated_at, deleted_at = NULL`
	HostFenceRedfishClearSQL = `UPDATE host_fence_redfish SET endpoint = '', username = '', password = '', system_id = '',
		 auth = '', ca_pem = '', deleted_at = ?, updated_at = ? WHERE host_name = ?`
)

// GetHostFenceRedfish reads host's live Redfish settings; ok is false when it
// has none.
func GetHostFenceRedfish(ctx context.Context, c *Client, host string) (cfg fence.RedfishConfig, ok bool, err error) {
	rows, err := c.Query(ctx, `SELECT endpoint, username, password, system_id, auth, ca_pem
		 FROM host_fence_redfish WHERE host_name = ? AND deleted_at IS NULL`, host)
	if err != nil || len(rows) == 0 {
		return fence.RedfishConfig{}, false, err
	}
	return redfishFromRow(rows[0], ""), true, nil
}

// redfishFromRow reads the Redfish columns of r, each under prefix.
func redfishFromRow(r Row, prefix string) fence.RedfishConfig {
	return fence.RedfishConfig{
		Endpoint: r.String(prefix + "endpoint"),
		User:     r.String(prefix + "username"),
		Pass:     r.String(prefix + "password"),
		SystemID: r.String(prefix + "system_id"),
		Auth:     r.String(prefix + "auth"),
		CACert:   r.String(prefix + "ca_pem"),
	}
}

// retireFenceRedfish retires host's Redfish row as retireFenceCredential
// retires its IPMI password: locally, stamped with the removal's or
// admission's own updatedAt, and only over a row older than that.
func retireFenceRedfish(ctx context.Context, tx *sql.Tx, host, updatedAt string) error {
	var cur string
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT updated_at, deleted_at FROM host_fence_redfish WHERE host_name = ?`, host).Scan(&cur, &deleted)
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
	// The clear's text, applied locally in the apply transaction and never
	// logged: every node derives the same tombstone from the same statement.
	_, err = tx.ExecContext(ctx, HostFenceRedfishClearSQL, updatedAt, updatedAt, host)
	return err
}
