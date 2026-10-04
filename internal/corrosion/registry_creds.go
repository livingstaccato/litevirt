package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/binary"

	"github.com/google/uuid"
)

// CANONICAL REGISTRY CREDENTIALS — planned, not implemented
// (docs/design/canonical-registry-credentials.md).
//
// The legacy writer below mints a random id per login, so two nodes writing the same
// (scope, owner, registry) inside one replication window mint two ids for one credential. The
// older entry's INSERT then collides on the partial UNIQUE index at the newer node and holds that
// peer stream until the sensitive anti-entropy lane carries the tombstone that lets it apply
// (docs/diagnostics.md, "Registry credentials: a concurrent-login collision"). The fix is a
// deterministic id per triple, written by one PK-keyed upsert.
//
// An earlier build shipped that model's receive side — an advertised canonical_registry_v1
// token whose latch made receivers ACCEPT the canonical upsert — with no production writer.
// It was retired on 2026-10-04 (capabilities.RetiredCanonicalRegistryV1). What remains here:
//
//   - RegistryCredentialID: the frozen id derivation, a contract the future writer keeps;
//   - registryCanonicalUpsertSQL: the canonical shape, registered as plain DispReject, so every
//     receiver on this build refuses it — the safe answer for a build that never latched the
//     contract that would make it acceptable;
//   - RegistryWriterReady / RegistryContractReady: latch-free local readiness reads.

// RegistryCredential is one stored OCI/Docker registry login (schema v23).
// A row is either per-user (Scope="user", Owner=<username>) or global
// (Scope="global", Owner=""). Secret is the raw password/token — List paths
// must redact it before it leaves the daemon (see grpcapi.toPbRegistryCredential).
type RegistryCredential struct {
	ID        string
	Scope     string // "user" | "global"
	Owner     string // username for user scope; "" for global
	Registry  string // normalized registry host
	Username  string
	Secret    string
	CreatedAt string
	UpdatedAt string
}

const (
	RegistryScopeUser   = "user"
	RegistryScopeGlobal = "global"
)

// RegistryCredentialID derives the DETERMINISTIC, cluster-stable primary-key id for one logical
// credential (scope, owner, registry) — the canonical model. Because every node computes the SAME
// id for a triple, two nodes creating/rotating the same credential target the SAME physical PK,
// so a replication conflict resolves by normal LWW on that PK instead of minting two random ids
// that collide on the partial UNIQUE index.
//
// The encoding is a FROZEN contract (a change ⇒ a new domain tag "credential/v2" + a migration):
// a domain tag followed by each field LENGTH-PREFIXED (big-endian uint32) so no two distinct
// triples can frame to the same bytes, hashed with SHA-256; the first 16 bytes become a v8
// (custom, RFC 9562) UUID. Inputs are the STORED canonical values — `registry` is already
// normalized by lxc.NormalizeRegistry at write time, and this function applies NO further
// normalization (notably NO lowercasing: NormalizeRegistry preserves case beyond folding the
// Docker Hub aliases, so re-casing here would split a credential from its own pulls).
//
// No writer uses it today. It is kept because it is pure, needs no latch, and is the one piece
// of the planned design that must not change between now and the writer shipping.
func RegistryCredentialID(scope, owner, registry string) string {
	b := make([]byte, 0, 64)
	b = append(b, "credential/v1"...)
	for _, f := range []string{scope, owner, registry} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		b = append(b, l[:]...)
		b = append(b, f...)
	}
	sum := sha256.Sum256(b)
	var id uuid.UUID
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x80 // version 8 (custom / hash-derived)
	id[8] = (id[8] & 0x3f) | 0x80 // RFC 4122 variant
	return id.String()
}

// registryTombstoneByTripleSQL soft-deletes the LIVE row for a triple (the legacy writer's first
// statement). Registered shape.
const registryTombstoneByTripleSQL = `UPDATE registry_credentials SET deleted_at = ?, updated_at = ?
			       WHERE scope = ? AND owner = ? AND registry = ? AND deleted_at IS NULL`

// registryLegacyInsertSQL mints a new random-id credential row (the legacy writer's second
// statement). It auto-derives to DispPlainInsert and is always accepted.
const registryLegacyInsertSQL = `INSERT INTO registry_credentials
			       (id, scope, owner, registry, username, secret, created_at, updated_at, deleted_at)
			       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`

// UpsertRegistryCredential replaces the live credential for (scope, owner,
// registry). It soft-deletes any existing live row for that triple then inserts
// a fresh id, both in one batch so the partial unique index never collides.
// The caller supplies a pre-generated ID.
func UpsertRegistryCredential(ctx context.Context, c *Client, rc RegistryCredential) error {
	now := c.NowTS()
	return c.ExecuteBatch(ctx, []Statement{
		{
			SQL:    registryTombstoneByTripleSQL,
			Params: []interface{}{nowRFC3339(), now, rc.Scope, rc.Owner, rc.Registry},
		},
		{
			SQL:    registryLegacyInsertSQL,
			Params: []interface{}{rc.ID, rc.Scope, rc.Owner, rc.Registry, rc.Username, rc.Secret, nowRFC3339(), now},
		},
	})
}

// registryCanonicalUpsertSQL is the canonical upsert of the retired design. NOTHING EMITS IT: it
// is kept so the shape stays registered — as plain DispReject (stmtledger_derive.go) — and listed
// in stmthistorical.go, because v1.4.0 through v1.9.0 carried a writer for it (never called).
// Every receiver on this build refuses it, whatever capability marker the node holds.
//
// The ON CONFLICT SET is a full image of the row's mutable content — including created_at =
// excluded.created_at — so a replicated write converges the whole row on the winning value.
// docs/design/canonical-registry-credentials.md records why, for the writer that replaces it.
const registryCanonicalUpsertSQL = `INSERT INTO registry_credentials
		   (id, scope, owner, registry, username, secret, created_at, updated_at, deleted_at)
		   VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(id) DO UPDATE SET
		   username = excluded.username,
		   secret = excluded.secret,
		   created_at = excluded.created_at,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`

// RegistryWriterReady reports whether NO legacy (non-canonical) LIVE row remains locally — the
// local precondition for switching the WRITER to canonical (a legacy live row would collide with a
// canonical write on the partial UNIQUE). It ignores tombstones (a soft-deleted legacy row is inert
// under the partial index). A pure local read with no caller yet; the planned activation
// re-evaluates it synchronously, never from a cached value.
func RegistryWriterReady(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT id, scope, owner, registry FROM registry_credentials WHERE deleted_at IS NULL`)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if row.String("id") != RegistryCredentialID(row.String("scope"), row.String("owner"), row.String("registry")) {
			return false, nil
		}
	}
	return true, nil
}

// RegistryContractReady reports whether NO non-canonical PHYSICAL row remains locally — live OR
// tombstoned. This is the precondition for the CONTRACT (replacing the partial UNIQUE with a
// non-partial UNIQUE(scope,owner,registry)): the non-partial index would reject the leftover legacy
// tombstones, so they must first be reclaimed by the watermark-safe GC. Strictly stronger than
// RegistryWriterReady. The cross-node component (peer barriers, no legacy shape in any mutation/relay
// log, AE convergence) belongs to the planned operator-run activation.
func RegistryContractReady(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx, `SELECT id, scope, owner, registry FROM registry_credentials`)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if row.String("id") != RegistryCredentialID(row.String("scope"), row.String("owner"), row.String("registry")) {
			return false, nil
		}
	}
	return true, nil
}

func scanRegistryCredentials(rows []Row) []RegistryCredential {
	out := make([]RegistryCredential, 0, len(rows))
	for _, r := range rows {
		out = append(out, RegistryCredential{
			ID: r.String("id"), Scope: r.String("scope"), Owner: r.String("owner"),
			Registry: r.String("registry"), Username: r.String("username"), Secret: r.String("secret"),
			CreatedAt: r.String("created_at"), UpdatedAt: r.String("updated_at"),
		})
	}
	return out
}

// ListRegistryCredentials returns the live rows owned by `owner` and,
// optionally, the global rows. Secret IS included (ResolveRegistryCredential
// needs it); redaction happens at the gRPC layer.
func ListRegistryCredentials(ctx context.Context, c *Client, owner string, includeGlobal bool) ([]RegistryCredential, error) {
	q := `SELECT id, scope, owner, registry, username, secret, created_at, updated_at
	       FROM registry_credentials
	       WHERE deleted_at IS NULL AND ((scope = 'user' AND owner = ?)`
	if includeGlobal {
		q += ` OR scope = 'global'`
	}
	q += `) ORDER BY scope, registry`
	rows, err := c.Query(ctx, q, owner)
	if err != nil {
		return nil, err
	}
	return scanRegistryCredentials(rows), nil
}

// ListAllRegistryCredentials returns every live row across all owners plus the
// global rows. Used by the operator `lv registry ls --all`.
func ListAllRegistryCredentials(ctx context.Context, c *Client) ([]RegistryCredential, error) {
	rows, err := c.Query(ctx,
		`SELECT id, scope, owner, registry, username, secret, created_at, updated_at
		 FROM registry_credentials WHERE deleted_at IS NULL ORDER BY scope, owner, registry`)
	if err != nil {
		return nil, err
	}
	return scanRegistryCredentials(rows), nil
}

// DeleteRegistryCredential soft-deletes the live row for (scope, owner,
// registry). The bool reports whether a live row existed (so the handler can
// return NotFound).
func DeleteRegistryCredential(ctx context.Context, c *Client, scope, owner, registry string) (bool, error) {
	existing, err := c.Query(ctx,
		`SELECT id FROM registry_credentials
		 WHERE scope = ? AND owner = ? AND registry = ? AND deleted_at IS NULL`,
		scope, owner, registry)
	if err != nil {
		return false, err
	}
	if len(existing) == 0 {
		return false, nil
	}
	now := c.NowTS()
	if err := c.Execute(ctx,
		`UPDATE registry_credentials SET deleted_at = ?, updated_at = ?
		 WHERE scope = ? AND owner = ? AND registry = ? AND deleted_at IS NULL`,
		nowRFC3339(), now, scope, owner, registry); err != nil {
		return false, err
	}
	return true, nil
}

// ResolveRegistryCredential implements the pull-time precedence rule: the
// caller's per-user row for `registry` wins, else the global row, else
// (nil, nil) for an anonymous pull.
func ResolveRegistryCredential(ctx context.Context, c *Client, username, registry string) (*RegistryCredential, error) {
	rows, err := c.Query(ctx,
		`SELECT id, scope, owner, registry, username, secret, created_at, updated_at
		 FROM registry_credentials
		 WHERE registry = ? AND deleted_at IS NULL
		   AND ((scope = 'user' AND owner = ?) OR scope = 'global')
		 ORDER BY CASE scope WHEN 'user' THEN 0 ELSE 1 END
		 LIMIT 1`,
		registry, username)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	rc := scanRegistryCredentials(rows)[0]
	return &rc, nil
}
