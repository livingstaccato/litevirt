package corrosion

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/hlc"
)

// CATALOG BIRTH INCARNATIONS (release feature catalog_incarnation, schema v92).
//
// An image name or a (host, pool) name can be deleted and created again, and
// before this nothing in either row told the two lifetimes apart: created_at
// is restamped by every copy, updated_at by every write, and the tombstone
// carries no generation. A consumer that binds to "the image" or "the pool"
// (the native VM create) could therefore attach to a later lifetime than the
// one it checked, or have a late write of an earlier lifetime resurrect it.
//
// Every birth of a name writes a fresh incarnation into the row, in ONE
// statement: a first birth (no row) or a rebirth (over a tombstone, or over a
// pool row born under an earlier lifetime of its host). Nothing else changes
// it. The value is "<birth HLC>~<f|r><32 hex>": the HLC prefix is fixed width
// and sorts lexically, and a birth is stamped after the row it replaces, so a
// greater incarnation is always a later lifetime.
//
// The rules every replica applies, on the WAL (catalogLifetimeDecision) and in
// anti-entropy (catalogDumpDecision), whatever the clocks:
//  1. A birth applies over a lesser incarnation (or ''), never a greater one.
//  2. A tombstone is final within its incarnation: a delete applies over the
//     same incarnation's live row, and a live row (a late write, a re-delivered
//     birth) never displaces its own incarnation's tombstone.
//  3. A write that names no incarnation (the previous release's shapes) never
//     applies to a row that carries one.
//  4. Otherwise, LWW as before.
// Writes to a born row (a copy, a content update, a capacity refresh) name its
// incarnation and change nothing of another lifetime.
//
// '' is a row born before the latch. It is not a lifetime, and the consume API
// (ImageBirthOf, StoragePoolBirthOf) refuses it. Nothing adopts such a row:
// recreating it is its birth.
//
// A node writes the incarnation-bearing forms once the release feature is
// available, and on a row that already carries an incarnation (only a latched
// writer makes one, so every replica decodes them). Births take the feature's
// grant.

const (
	catalogFirstBirth     = "f"
	catalogRebirth        = "r"
	catalogIncarnationSep = "~"
)

var (
	// ErrCatalogNoBirth: the row is missing, deleted, or was born before the
	// release latched (''): it records no lifetime to bind to.
	ErrCatalogNoBirth = errors.New("catalog: no durable birth recorded for this name")
	// ErrCatalogHostLifetime: the pool row was born under another lifetime of
	// its host (removed and re-admitted since), or its host is not admitted.
	ErrCatalogHostLifetime = errors.New("catalog: the pool was born under another lifetime of its host")
	// ErrCatalogBirthNeeded: this write is a birth, and the writer holds no
	// grant of the release feature. A writer that has one retries with it.
	ErrCatalogBirthNeeded = errors.New("catalog: this write is a birth and needs the catalog_incarnation grant")
	// ErrCatalogBirthNeedsLatch: the write would replace a lifetime, and the
	// release feature is not available on this node yet. Nothing was written.
	ErrCatalogBirthNeedsLatch = errors.New("catalog: the cluster upgrade must finish before this name can be created again here (catalog_incarnation)")
)

// newCatalogIncarnation is a birth's incarnation stamped at clock.
func newCatalogIncarnation(clock string, first bool) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("rand.Read: " + err.Error())
	}
	kind := catalogRebirth
	if first {
		kind = catalogFirstBirth
	}
	return clock + catalogIncarnationSep + kind + hex.EncodeToString(buf)
}

// ValidCatalogIncarnation reports whether s is a born incarnation.
func ValidCatalogIncarnation(s string) bool {
	i := strings.LastIndex(s, catalogIncarnationSep)
	if i < 0 {
		return false
	}
	if _, ok := hlc.Parse(s[:i]); !ok {
		if _, ok := tsInstant(s[:i]); !ok {
			return false
		}
	}
	tail := s[i+len(catalogIncarnationSep):]
	if len(tail) != 33 || (tail[:1] != catalogFirstBirth && tail[:1] != catalogRebirth) {
		return false
	}
	_, err := hex.DecodeString(tail[1:])
	return err == nil && strings.ToLower(tail[1:]) == tail[1:]
}

// CompareCatalogIncarnations orders two born incarnations by their birth
// clocks (lwwOrder: an HLC and an RFC3339 stamp compare by instant, since a
// node's clock form can change over a cluster's life), then by the whole
// value. ” sorts before every born incarnation.
func CompareCatalogIncarnations(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return -1
	case b == "":
		return 1
	}
	ia, ib := strings.LastIndex(a, catalogIncarnationSep), strings.LastIndex(b, catalogIncarnationSep)
	if ia >= 0 && ib >= 0 {
		if ord := lwwOrder(a[:ia], b[:ib]); ord != 0 {
			return ord
		}
	}
	return strings.Compare(a, b)
}

// ─────────────────────────────── images ───────────────────────────────

// imageBirthSQL is an image's birth: the whole row, its incarnation, live.
const imageBirthSQL = `INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at, incarnation)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   format = excluded.format,
		   source_url = excluded.source_url,
		   checksum = excluded.checksum,
		   size_bytes = excluded.size_bytes,
		   created_at = excluded.created_at,
		   updated_at = excluded.updated_at,
		   incarnation = excluded.incarnation,
		   deleted_at = NULL`

// imageContinueSQL is a write to a born image's content (a copy, a re-import
// over the live image): its own lifetime only, and never a revival.
const imageContinueSQL = `UPDATE images SET format = ?, source_url = ?, checksum = ?, size_bytes = ?, updated_at = ?
		 WHERE name = ? AND incarnation = ? AND deleted_at IS NULL`

// imageLifetimeDeleteSQL tombstones one lifetime of an image.
const imageLifetimeDeleteSQL = `UPDATE images SET deleted_at = ?, updated_at = ? WHERE name = ? AND incarnation = ?`

// catalogRow is one images / storage_pools row as a replica holds it.
type catalogRow struct {
	found, deleted       bool
	deletedAt, updatedAt string
	checksum             string
	incarnation          string
	hostIncarnation      int64
}

type catalogQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func readImageRow(ctx context.Context, q catalogQuerier, name string) (catalogRow, error) {
	var r catalogRow
	err := q.QueryRowContext(ctx, `SELECT COALESCE(deleted_at, ''), COALESCE(updated_at, ''), COALESCE(checksum, ''), incarnation
		FROM images WHERE name = ?`, name).Scan(&r.deletedAt, &r.updatedAt, &r.checksum, &r.incarnation)
	if errors.Is(err, sql.ErrNoRows) {
		return catalogRow{}, nil
	}
	if err != nil {
		return catalogRow{}, err
	}
	r.found, r.deleted = true, r.deletedAt != ""
	return r, nil
}

// ImageWriteMode says which forms an image or pool write may use.
type catalogWriteMode int

const (
	// catalogUnlatched: the release feature is not available here. The
	// previous release's forms on a row with no incarnation; a birth that
	// would replace a born lifetime is refused (ErrCatalogBirthNeedsLatch).
	catalogUnlatched catalogWriteMode = iota
	// catalogLatched: the feature is available; a birth is
	// ErrCatalogBirthNeeded (the caller retries with a grant).
	catalogLatched
	// catalogBirth: the writer holds the grant.
	catalogBirth
	// catalogMutate: a write to an existing pool (a capacity refresh, a
	// state, an export, a key fingerprint): never a birth. Over no row or a
	// tombstone it writes nothing, so it never brings a deleted pool back.
	catalogMutate
)

// RecordImageWithGrant is RecordImage on a node where the release feature is
// available. g nil: any birth is ErrCatalogBirthNeeded, and nothing is
// written; the caller takes the grant (WithFeature) and calls again with it.
func RecordImageWithGrant(ctx context.Context, c *Client, img ImageRecord, revive bool, startDeleted string, clk ImageClocks, g *capabilities.FeatureGrant) (ImageRecordResult, error) {
	if g == nil {
		return RecordImageLifetime(ctx, c, img, revive, startDeleted, clk, true, capabilities.FeatureGrant{})
	}
	return RecordImageLifetime(ctx, c, img, revive, startDeleted, clk, true, *g)
}

// ImageBirth is an image's durable birth as this replica holds it.
type ImageBirth struct {
	Name, Incarnation, Checksum, Format string
	SizeBytes                           int64
}

// ImageBirthOf returns name's live born row. ErrCatalogNoBirth when the row
// is missing, deleted or born before the release latched.
func ImageBirthOf(ctx context.Context, c *Client, name string) (ImageBirth, error) {
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ImageBirth{}, err
	}
	defer tx.Rollback()
	return ImageBirthTx(ctx, tx, name)
}

// ImageBirthTx is ImageBirthOf inside the caller's transaction (a consumer
// compares the birth it bound against the live one atomically with its write).
func ImageBirthTx(ctx context.Context, tx *sql.Tx, name string) (ImageBirth, error) {
	var b ImageBirth
	var deleted string
	err := tx.QueryRowContext(ctx, `SELECT name, incarnation, COALESCE(checksum, ''), COALESCE(format, ''), COALESCE(size_bytes, 0), COALESCE(deleted_at, '')
		FROM images WHERE name = ?`, name).Scan(&b.Name, &b.Incarnation, &b.Checksum, &b.Format, &b.SizeBytes, &deleted)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (deleted != "" || !ValidCatalogIncarnation(b.Incarnation))) {
		return ImageBirth{}, fmt.Errorf("image %q: %w", name, ErrCatalogNoBirth)
	}
	if err != nil {
		return ImageBirth{}, err
	}
	return b, nil
}

// ───────────────────────────── storage pools ─────────────────────────────

// storagePoolBirthSQL is a pool's birth on its host: the whole row, its
// incarnation and its host's incarnation, live.
const storagePoolBirthSQL = `INSERT INTO storage_pools
			(host_name, name, driver, source, target, options, project, total_bytes, used_bytes, state, updated_at, incarnation, host_incarnation)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(host_name, name) DO UPDATE SET
		   driver = excluded.driver,
		   source = excluded.source,
		   target = excluded.target,
		   options = excluded.options,
		   project = excluded.project,
		   total_bytes = excluded.total_bytes,
		   used_bytes = excluded.used_bytes,
		   state = excluded.state,
		   updated_at = excluded.updated_at,
		   incarnation = excluded.incarnation,
		   host_incarnation = excluded.host_incarnation,
		   deleted_at = NULL`

// storagePoolMutateSQL is every other write to a born pool (its config,
// capacity, state, export): its own lifetime only, and never a revival.
const storagePoolMutateSQL = `UPDATE storage_pools SET driver = ?, source = ?, target = ?, options = ?, project = ?,
			total_bytes = ?, used_bytes = ?, state = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND incarnation = ? AND deleted_at IS NULL`

// storagePoolLifetimeDeleteSQL tombstones one lifetime of a pool.
const storagePoolLifetimeDeleteSQL = `UPDATE storage_pools SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND incarnation = ? AND deleted_at IS NULL`

// storagePoolLegacySQL is the previous release's pool write.
const storagePoolLegacySQL = `INSERT OR REPLACE INTO storage_pools
			(host_name, name, driver, source, target, options, project, total_bytes, used_bytes, state, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`

// storagePoolLegacyDeleteSQL is the previous release's pool delete.
const storagePoolLegacyDeleteSQL = `UPDATE storage_pools SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`

func readPoolRow(ctx context.Context, q catalogQuerier, host, name string) (catalogRow, error) {
	var r catalogRow
	err := q.QueryRowContext(ctx, `SELECT COALESCE(deleted_at, ''), COALESCE(updated_at, ''), incarnation, host_incarnation
		FROM storage_pools WHERE host_name = ? AND name = ?`, host, name).Scan(&r.deletedAt, &r.updatedAt, &r.incarnation, &r.hostIncarnation)
	if errors.Is(err, sql.ErrNoRows) {
		return catalogRow{}, nil
	}
	if err != nil {
		return catalogRow{}, err
	}
	r.found, r.deleted = true, r.deletedAt != ""
	return r, nil
}

// hostIncarnationNow is host's admission counter as this replica holds it
// (0 with no row), and whether its row is live.
func hostIncarnationNow(ctx context.Context, q catalogQuerier, host string) (n int64, live bool, err error) {
	var deleted string
	err = q.QueryRowContext(ctx, `SELECT incarnation, COALESCE(deleted_at, '') FROM hosts WHERE name = ?`, host).Scan(&n, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return n, err == nil && deleted == "", err
}

// catalogWriteRetries bounds how often a write is chosen again when the row
// changed between its read and its guarded write.
const catalogWriteRetries = 4

// writeStoragePool writes p in the form its row calls for (see the file
// comment), re-choosing when the row changes under it.
func writeStoragePool(ctx context.Context, c *Client, p StoragePoolRecord, mode catalogWriteMode, g capabilities.FeatureGrant) error {
	optsJSON, err := poolOptionsJSON(p.Options)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < catalogWriteRetries; attempt++ {
		row, err := readPoolRow(ctx, c.db, p.HostName, p.Name)
		if err != nil {
			return err
		}
		hostN, _, err := hostIncarnationNow(ctx, c.db, p.HostName)
		if err != nil {
			return err
		}
		now := c.NowTS()
		live := row.found && !row.deleted
		var stmt Statement
		switch {
		case live && row.incarnation != "" && row.hostIncarnation == hostN:
			stmt = Statement{SQL: storagePoolMutateSQL, Params: []interface{}{p.Driver, p.Source, p.Target, optsJSON, p.Project,
				p.TotalBytes, p.UsedBytes, p.State, now, p.HostName, p.Name, row.incarnation}}
		case live && row.incarnation == "":
			stmt = Statement{SQL: storagePoolLegacySQL, Params: []interface{}{p.HostName, p.Name, p.Driver, p.Source, p.Target,
				optsJSON, p.Project, p.TotalBytes, p.UsedBytes, p.State, now}}
		default:
			// No row, a tombstone, or a row born under an earlier lifetime of
			// its host: a birth.
			switch mode {
			case catalogMutate:
				return nil
			case catalogLatched:
				return ErrCatalogBirthNeeded
			case catalogUnlatched:
				if row.incarnation != "" {
					return ErrCatalogBirthNeedsLatch
				}
				stmt = Statement{SQL: storagePoolLegacySQL, Params: []interface{}{p.HostName, p.Name, p.Driver, p.Source, p.Target,
					optsJSON, p.Project, p.TotalBytes, p.UsedBytes, p.State, now}}
			default:
				if err := g.Check(capabilities.FeatureCatalogIncarnation); err != nil {
					return err
				}
				if row.found && lwwOrder(row.updatedAt, now) >= 0 {
					// The row is stamped at or ahead of this clock (it came by
					// anti-entropy): take its stamp, and stamp after it.
					ObserveStamp(c, row.updatedAt)
					continue
				}
				stmt = Statement{SQL: storagePoolBirthSQL, Params: []interface{}{p.HostName, p.Name, p.Driver, p.Source, p.Target,
					optsJSON, p.Project, p.TotalBytes, p.UsedBytes, p.State, now, newCatalogIncarnation(now, !row.found), hostN}}
			}
		}
		ok, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
			again, err := readPoolRow(ctx, tx, p.HostName, p.Name)
			if err != nil {
				return false, err
			}
			n, _, err := hostIncarnationNow(ctx, tx, p.HostName)
			return err == nil && again == row && n == hostN, err
		}, []Statement{stmt})
		if err != nil || ok {
			return err
		}
	}
	return fmt.Errorf("storage pool %s on %s kept changing while it was written; nothing was written", p.Name, p.HostName)
}

func poolOptionsJSON(opts map[string]string) (string, error) {
	if len(opts) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(opts)
	if err != nil {
		return "", fmt.Errorf("marshal options: %w", err)
	}
	return string(b), nil
}

// UpsertStoragePoolWithGrant is UpsertStoragePool on a node where the release
// feature is available. g nil: a birth is ErrCatalogBirthNeeded, and nothing
// is written; the caller takes the grant (WithFeature) and calls again.
func UpsertStoragePoolWithGrant(ctx context.Context, c *Client, p StoragePoolRecord, g *capabilities.FeatureGrant) error {
	if g == nil {
		return writeStoragePool(ctx, c, p, catalogLatched, capabilities.FeatureGrant{})
	}
	return writeStoragePool(ctx, c, p, catalogBirth, *g)
}

// CatalogFeatureGate is the release-feature gate a pool or image writer goes
// through (health.Checker; grpcapi's releaseFeatureGate).
type CatalogFeatureGate interface {
	FeatureAvailable(feature capabilities.Feature) bool
	WithFeature(ctx context.Context, feature capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error
}

// UpdateStoragePool writes p over its existing live row only: a capacity
// refresh, a state, an NFS export, a ceph key fingerprint. It never gives
// birth: over no row or a tombstone it writes nothing, so a refresh that
// raced lv pool rm never brings the pool back. A born row keeps its lifetime
// (storagePoolMutateSQL); one born before the latch takes the previous
// release's statement. It needs no grant.
func UpdateStoragePool(ctx context.Context, c *Client, p StoragePoolRecord) error {
	return writeStoragePool(ctx, c, p, catalogMutate, capabilities.FeatureGrant{})
}

// WriteStoragePool creates or writes p (lv pool create, a configured pool, the
// built-in ISO library) through gate: the previous release's forms while
// the release feature is not available here, and once it is, a birth under
// its grant only when the row calls for one, so a write to a born pool does
// not record the feature's use. A nil gate is an unlatched node.
func WriteStoragePool(ctx context.Context, c *Client, gate CatalogFeatureGate, p StoragePoolRecord) error {
	if gate == nil || !gate.FeatureAvailable(capabilities.FeatureCatalogIncarnation) {
		return UpsertStoragePool(ctx, c, p)
	}
	err := UpsertStoragePoolWithGrant(ctx, c, p, nil)
	if !errors.Is(err, ErrCatalogBirthNeeded) {
		return err
	}
	return gate.WithFeature(ctx, capabilities.FeatureCatalogIncarnation, func(ctx context.Context, g capabilities.FeatureGrant) error {
		return UpsertStoragePoolWithGrant(ctx, c, p, &g)
	})
}

// StoragePoolBirth is a pool's durable birth as this replica holds it.
type StoragePoolBirth struct {
	HostName, Name, Incarnation string
	// HostIncarnation is the host's admission counter the pool was born
	// under, equal to the host's live one (StoragePoolBirthOf checks it).
	HostIncarnation                          int64
	Driver, Source, Target, Options, Project string
}

// StoragePoolBirthOf returns (host, name)'s live born row, born under the
// host's current admission. ErrCatalogNoBirth when the row is missing,
// deleted or born before the release latched; ErrCatalogHostLifetime when
// it was born under another admission of the host, or the host has no live
// row.
func StoragePoolBirthOf(ctx context.Context, c *Client, host, name string) (StoragePoolBirth, error) {
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return StoragePoolBirth{}, err
	}
	defer tx.Rollback()
	return StoragePoolBirthTx(ctx, tx, host, name)
}

// StoragePoolBirthTx is StoragePoolBirthOf inside the caller's transaction.
func StoragePoolBirthTx(ctx context.Context, tx *sql.Tx, host, name string) (StoragePoolBirth, error) {
	var b StoragePoolBirth
	var deleted string
	err := tx.QueryRowContext(ctx, `SELECT host_name, name, incarnation, host_incarnation, COALESCE(driver, ''), COALESCE(source, ''),
			COALESCE(target, ''), COALESCE(options, ''), COALESCE(project, ''), COALESCE(deleted_at, '')
		FROM storage_pools WHERE host_name = ? AND name = ?`, host, name).
		Scan(&b.HostName, &b.Name, &b.Incarnation, &b.HostIncarnation, &b.Driver, &b.Source, &b.Target, &b.Options, &b.Project, &deleted)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (deleted != "" || !ValidCatalogIncarnation(b.Incarnation))) {
		return StoragePoolBirth{}, fmt.Errorf("storage pool %q on %s: %w", name, host, ErrCatalogNoBirth)
	}
	if err != nil {
		return StoragePoolBirth{}, err
	}
	n, live, err := hostIncarnationNow(ctx, tx, host)
	if err != nil {
		return StoragePoolBirth{}, err
	}
	if !live || n != b.HostIncarnation {
		return StoragePoolBirth{}, fmt.Errorf("storage pool %q on %s (born under host incarnation %d, host now %d, live %v): %w",
			name, host, b.HostIncarnation, n, live, ErrCatalogHostLifetime)
	}
	return b, nil
}

// ─────────────────────────── receiver rules ───────────────────────────

type catalogVerdict int

const (
	catalogNormal catalogVerdict = iota // the clock decides, as for any row
	catalogApply                        // applies whatever the clocks say
	catalogSkip                         // changes nothing here
)

// catalogLifetimeDecision decides a replicated write to images or
// storage_pools by the lifetimes it and the local row name (the file
// comment's rules 1-3), before the clock is compared.
func catalogLifetimeDecision(ctx context.Context, tx *sql.Tx, s Statement, table string) (catalogVerdict, error) {
	sqlText := strings.TrimSpace(s.SQL)
	param := func(i int) string {
		if i < len(s.Params) {
			return coerceString(s.Params[i])
		}
		return ""
	}
	var row catalogRow
	var err error
	var incoming string
	birth, scoped := false, false
	switch table {
	case "images":
		switch sqlText {
		case strings.TrimSpace(imageBirthSQL):
			birth, incoming = true, param(7)
			row, err = readImageRow(ctx, tx, param(0))
		case strings.TrimSpace(imageLifetimeDeleteSQL):
			scoped, incoming = true, param(3)
			row, err = readImageRow(ctx, tx, param(2))
		case strings.TrimSpace(imageContinueSQL):
			return catalogNormal, nil
		default:
			row, err = legacyImageRow(ctx, tx, s)
		}
	case "storage_pools":
		switch sqlText {
		case strings.TrimSpace(storagePoolBirthSQL):
			birth, incoming = true, param(11)
			row, err = readPoolRow(ctx, tx, param(0), param(1))
		case strings.TrimSpace(storagePoolLifetimeDeleteSQL):
			scoped, incoming = true, param(4)
			row, err = readPoolRow(ctx, tx, param(2), param(3))
		case strings.TrimSpace(storagePoolMutateSQL):
			return catalogNormal, nil
		default:
			row, err = legacyPoolRow(ctx, tx, s)
		}
	default:
		return catalogNormal, nil
	}
	if err != nil || !row.found {
		return catalogNormal, err
	}
	switch {
	case birth:
		switch c := CompareCatalogIncarnations(incoming, row.incarnation); {
		case row.incarnation == "" || c > 0:
			return catalogApply, nil
		case c < 0 || row.deleted:
			return catalogSkip, nil
		}
		return catalogNormal, nil
	case scoped:
		if row.incarnation == incoming && !row.deleted {
			return catalogApply, nil
		}
		return catalogNormal, nil
	}
	// A write that names no incarnation.
	if row.incarnation != "" {
		return catalogSkip, nil
	}
	return catalogNormal, nil
}

// legacyImageRow is the row a previous-release images write names: name is
// the INSERT's first value or the UPDATE's last parameter.
func legacyImageRow(ctx context.Context, tx *sql.Tx, s Statement) (catalogRow, error) {
	if len(s.Params) == 0 {
		return catalogRow{}, nil
	}
	sqlText := strings.ToUpper(strings.TrimSpace(s.SQL))
	name := coerceString(s.Params[len(s.Params)-1])
	if strings.HasPrefix(sqlText, "INSERT") {
		name = coerceString(s.Params[0])
	}
	return readImageRow(ctx, tx, name)
}

// legacyPoolRow is the row a previous-release storage_pools write names.
func legacyPoolRow(ctx context.Context, tx *sql.Tx, s Statement) (catalogRow, error) {
	sqlText := strings.ToUpper(strings.TrimSpace(s.SQL))
	switch {
	case strings.HasPrefix(sqlText, "INSERT") && len(s.Params) >= 2:
		return readPoolRow(ctx, tx, coerceString(s.Params[0]), coerceString(s.Params[1]))
	case strings.HasPrefix(sqlText, "UPDATE") && len(s.Params) >= 2:
		return readPoolRow(ctx, tx, coerceString(s.Params[len(s.Params)-2]), coerceString(s.Params[len(s.Params)-1]))
	}
	return catalogRow{}, nil
}

// catalogDumpDecision is the same rules for an anti-entropy row. A dump
// without the incarnation column comes from a node whose every row has none
// (withoutUnsetIncarnation): its rows read as ”.
func catalogDumpDecision(tx *sql.Tx, table syncTable, row []interface{}) (mergeAuthorityDecision, error) {
	idx := columnIndexMap(table.Columns)
	var local catalogRow
	var err error
	switch table.Name {
	case "images":
		local, err = readImageRow(context.Background(), tx, cellStr(row, idx, "name"))
	case "storage_pools":
		local, err = readPoolRow(context.Background(), tx, cellStr(row, idx, "host_name"), cellStr(row, idx, "name"))
	default:
		return mergeAuthorityNormal, nil
	}
	if err != nil {
		return mergeAuthorityKeepLocal, err
	}
	if !local.found {
		return mergeAuthorityNormal, nil
	}
	incoming := cellStr(row, idx, "incarnation")
	incomingDeleted := cellStr(row, idx, "deleted_at") != ""
	switch {
	case local.incarnation == "" && incoming == "":
		return mergeAuthorityNormal, nil
	case incoming == "":
		return mergeAuthorityKeepLocal, nil
	case local.incarnation == "":
		return mergeAuthorityApplyIncoming, nil
	case CompareCatalogIncarnations(incoming, local.incarnation) > 0:
		return mergeAuthorityApplyIncoming, nil
	case CompareCatalogIncarnations(incoming, local.incarnation) < 0:
		return mergeAuthorityKeepLocal, nil
	case local.deleted && !incomingDeleted:
		return mergeAuthorityKeepLocal, nil
	case !local.deleted && incomingDeleted:
		return mergeAuthorityApplyIncoming, nil
	}
	return mergeAuthorityNormal, nil
}
