package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// StoragePoolRecord represents a storage pool on a host.
type StoragePoolRecord struct {
	HostName string
	Name     string
	Driver   string
	Source   string
	Target   string
	Options  map[string]string
	// Project is the owning tenant. EMPTY means GLOBAL/shared — usable by every
	// project; a non-empty value means owned + isolated (only that project's
	// workloads may place disks on it).
	Project    string
	TotalBytes int64
	UsedBytes  int64
	State      string
	// Incarnation and HostIncarnation are the row's birth incarnation and
	// the host incarnation it was born under (catalog_incarnation.go), as a
	// pool listing read them: UpdateStoragePool writes only into that
	// lifetime. Both are ignored by WriteStoragePool, which reads its own.
	Incarnation     string
	HostIncarnation int64
}

// UpsertStoragePool inserts or updates a storage pool record. Options are
// serialised as JSON; nil/empty maps round-trip as a JSON "{}" (sqlite
// treats NULL and "{}" the same after scanStoragePool decodes them).
//
// It is the write of a node where the release feature catalog_incarnation is
// not available: the previous release's statement, except on a born row,
// whose lifetime it keeps (catalog_incarnation.go). A write that would give
// birth over a born lifetime is refused (ErrCatalogBirthNeedsLatch).
// WriteStoragePool is every production caller's.
func UpsertStoragePool(ctx context.Context, c *Client, p StoragePoolRecord) error {
	return writeStoragePool(ctx, c, p, catalogUnlatched, capabilities.FeatureGrant{})
}

// storagePoolColumns is what scanStoragePool reads.
const storagePoolColumns = `host_name, name, driver, source, target, options, COALESCE(project, '') AS project, total_bytes, used_bytes, state, incarnation, host_incarnation`

// storagePoolUsable is the predicate of a live pool that may be used: not a
// pool born under an earlier lifetime of its host (catalog_incarnation.go,
// logStaleHostPool). Such a row is left out of every listing, so nothing
// places on, refreshes or resolves it; lv pool create gives it a new birth.
const storagePoolUsable = `deleted_at IS NULL AND (incarnation = '' OR host_incarnation = COALESCE((SELECT h.incarnation FROM hosts h WHERE h.name = storage_pools.host_name), 0))`

// GetStoragePoolAnyLifetime is GetStoragePool that also finds a pool born
// under an earlier lifetime of its host (stale), which every listing leaves
// out: what an ownership check (lv pool create) and lv pool rm must see.
func GetStoragePoolAnyLifetime(ctx context.Context, c *Client, hostName, name string) (rec StoragePoolRecord, ok, stale bool, err error) {
	rows, err := c.Query(ctx,
		`SELECT `+storagePoolColumns+`, CASE WHEN `+storagePoolUsable+` THEN 0 ELSE 1 END AS stale
		 FROM storage_pools WHERE host_name = ? AND name = ? AND deleted_at IS NULL`, hostName, name)
	if err != nil || len(rows) == 0 {
		return StoragePoolRecord{}, false, false, err
	}
	return scanStoragePool(rows[0]), true, rows[0].Int("stale") == 1, nil
}

// ListStaleHostStoragePools returns every live pool born under an earlier
// lifetime of its host: left out of every other listing, shown by lv pool ls
// so an operator can create it again or remove it.
func ListStaleHostStoragePools(ctx context.Context, c *Client) ([]StoragePoolRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+storagePoolColumns+` FROM storage_pools WHERE deleted_at IS NULL AND NOT (`+storagePoolUsable+`)`)
	if err != nil {
		return nil, err
	}
	out := make([]StoragePoolRecord, len(rows))
	for i, r := range rows {
		out[i] = scanStoragePool(r)
	}
	return out, nil
}

// ListAllStoragePools returns all active storage pools across the cluster.
func ListAllStoragePools(ctx context.Context, c *Client) ([]StoragePoolRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+storagePoolColumns+`
		 FROM storage_pools WHERE `+storagePoolUsable)
	if err != nil {
		return nil, err
	}
	pools := make([]StoragePoolRecord, len(rows))
	for i, r := range rows {
		pools[i] = scanStoragePool(r)
	}
	return pools, nil
}

// ListStoragePoolsForHost returns all active storage pools for a specific host.
func ListStoragePoolsForHost(ctx context.Context, c *Client, hostName string) ([]StoragePoolRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+storagePoolColumns+`
		 FROM storage_pools WHERE `+storagePoolUsable+` AND host_name = ? AND deleted_at IS NULL`, hostName)
	if err != nil {
		return nil, err
	}
	pools := make([]StoragePoolRecord, len(rows))
	for i, r := range rows {
		pools[i] = scanStoragePool(r)
	}
	return pools, nil
}

// GetStoragePool fetches a single pool by (host, name). Returns ok=false
// when the row is absent or soft-deleted so callers don't need to
// distinguish "missing" from "error" — a NotFound RPC code is enough.
func GetStoragePool(ctx context.Context, c *Client, hostName, name string) (StoragePoolRecord, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT `+storagePoolColumns+`
		 FROM storage_pools WHERE `+storagePoolUsable+` AND host_name = ? AND name = ? AND deleted_at IS NULL`,
		hostName, name)
	if err != nil {
		return StoragePoolRecord{}, false, err
	}
	if len(rows) == 0 {
		return StoragePoolRecord{}, false, nil
	}
	return scanStoragePool(rows[0]), true, nil
}

// HostsWithPool returns the names of ACTIVE hosts (other than excludeHost) that
// have a non-deleted pool of the given name — used to pick a healthy peer for
// cross-host replication when no target host was set explicitly.
func HostsWithPool(ctx context.Context, c *Client, poolName, excludeHost string) ([]string, error) {
	// The state filter is applied to the RESOLVED state (host_membership.go),
	// not to hosts.state in SQL: after the membership split that column is a
	// copy on the shared hosts clock, and can still lose a concurrent write.
	states, err := resolvedHostStates(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("hosts_with_pool: %w", err)
	}
	rows, err := c.Query(ctx,
		`SELECT sp.host_name
		 FROM storage_pools sp
		 JOIN hosts h ON h.name = sp.host_name
		 WHERE sp.name = ? AND sp.deleted_at IS NULL
		   AND (sp.incarnation = '' OR sp.host_incarnation = h.incarnation)
		   AND h.deleted_at IS NULL AND h.name != ?
		 ORDER BY sp.host_name`, poolName, excludeHost)
	if err != nil {
		return nil, fmt.Errorf("hosts_with_pool: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if states[r.String("host_name")] == "active" {
			out = append(out, r.String("host_name"))
		}
	}
	return out, nil
}

// CountDisksUsingPool counts live VM disks placed on (host, poolName). Pools are
// HOST-scoped, so the guard must scope by host too — a cluster-wide
// `storage_volume = ?` count would be both too broad (a same-named pool's disks on
// another host) and wrong. The pool delete refuses (without --force) when this is
// non-zero.
func CountDisksUsingPool(ctx context.Context, c *Client, host, poolName string) (int, error) {
	rows, err := c.Query(ctx,
		`SELECT COUNT(*) AS n FROM vm_disks
		 WHERE storage_volume = ? AND host_name = ? AND deleted_at IS NULL`,
		poolName, host)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int("n"), nil
}

// CountPoolsSharingResource counts OTHER live pool rows on rec's host that would
// share the SAME host-level resource rec's teardown releases — the refcount that
// stops us tearing down a mount/session another pool still needs. The shared
// resource is DRIVER-SPECIFIC, not just "same source":
//
//   - nfs: the litevirt-DERIVED mountpoint, keyed by source. Only OTHER
//     litevirt-owned NFS pools (those with an empty target) with the same source mount it at the
//     same path; an operator-managed (targetOverride) pool mounts elsewhere and
//     is excluded — counting it would falsely block a derived-mount unmount.
//   - iscsi: the (target IQN, portal) session. Same source (IQN) AND same portal
//     (empty/absent normalizes to 127.0.0.1, matching the driver default) — two
//     pools on the same IQN via DIFFERENT portals are distinct sessions and must
//     not block each other.
//   - every other driver: no host-level resource to refcount → 0 (teardown is a
//     no-op for them anyway).
func CountPoolsSharingResource(ctx context.Context, c *Client, rec StoragePoolRecord) (int, error) {
	if rec.Source == "" {
		return 0, nil
	}
	switch strings.ToLower(rec.Driver) {
	case "nfs", "netfs":
		rows, err := c.Query(ctx,
			`SELECT COUNT(*) AS n FROM storage_pools
			 WHERE host_name = ? AND name != ? AND driver = ? AND source = ?
			   AND COALESCE(target, '') = '' AND deleted_at IS NULL`,
			rec.HostName, rec.Name, rec.Driver, rec.Source)
		return countN(rows, err)
	case "iscsi":
		portal := rec.Options["portal"]
		if portal == "" {
			portal = "127.0.0.1"
		}
		rows, err := c.Query(ctx,
			`SELECT COUNT(*) AS n FROM storage_pools
			 WHERE host_name = ? AND name != ? AND driver = 'iscsi' AND source = ? AND deleted_at IS NULL
			   AND CASE WHEN COALESCE(json_extract(options, '$.portal'), '') = ''
			            THEN '127.0.0.1' ELSE json_extract(options, '$.portal') END = ?`,
			rec.HostName, rec.Name, rec.Source, portal)
		return countN(rows, err)
	default:
		return 0, nil
	}
}

// countN reads a single COUNT(*) AS n result.
func countN(rows []Row, err error) (int, error) {
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int("n"), nil
}

// MarkStoragePoolDeleted soft-deletes a pool row by stamping deleted_at.
// The corresponding driver teardown (unmount NFS, log out of iSCSI) is
// the caller's responsibility — we don't tear down here because the
// caller may want to keep the underlying mount around for a manual
// recovery. Schedule a real driver cleanup in the gRPC handler instead.
func MarkStoragePoolDeleted(ctx context.Context, c *Client, hostName, name string) error {
	// A born pool's delete names its incarnation: it ends that lifetime and
	// no later one (catalog_incarnation.go).
	for attempt := 0; attempt < catalogWriteRetries; attempt++ {
		row, err := readPoolRow(ctx, c.db, hostName, name)
		if err != nil {
			return err
		}
		// Stamped after the row and its lifetime's birth (catalogRowFloor).
		now, err := c.nowTSAfter(row.updatedAt, catalogBirthClock(row.incarnation))
		if err != nil {
			return err
		}
		del := Statement{SQL: storagePoolLegacyDeleteSQL, Params: []interface{}{nowRFC3339(), now, hostName, name}}
		if row.incarnation != "" {
			del = Statement{SQL: storagePoolLifetimeDeleteSQL, Params: []interface{}{nowRFC3339(), now, hostName, name, row.incarnation}}
		}
		ok, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
			again, err := readPoolRow(ctx, tx, hostName, name)
			return err == nil && again.incarnation == row.incarnation, err
		}, []Statement{del})
		if err != nil || ok {
			return err
		}
	}
	return fmt.Errorf("storage pool %s on %s kept changing while it was deleted; nothing was written", name, hostName)
}

func scanStoragePool(r Row) StoragePoolRecord {
	rec := StoragePoolRecord{
		HostName:   r.String("host_name"),
		Name:       r.String("name"),
		Driver:     r.String("driver"),
		Source:     r.String("source"),
		Target:     r.String("target"),
		Project:    r.String("project"),
		TotalBytes: r.Int64("total_bytes"),
		UsedBytes:  r.Int64("used_bytes"),
		State:      r.String("state"),

		Incarnation:     r.String("incarnation"),
		HostIncarnation: r.Int64("host_incarnation"),
	}
	if blob := r.String("options"); blob != "" && blob != "{}" {
		_ = json.Unmarshal([]byte(blob), &rec.Options)
	}
	return rec
}

// ListRBDDiskPathsForHost returns the paths of the live rbd ("rbd:…") VM disks
// recorded on host — what decides which ceph secrets the host must keep.
func ListRBDDiskPathsForHost(ctx context.Context, c *Client, host string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT path FROM vm_disks
		 WHERE host_name = ? AND deleted_at IS NULL AND path LIKE 'rbd:%'`, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("path"))
	}
	return out, nil
}

// ListStoragePoolsNamed returns every host's live row of the pool name — what
// the ceph key fingerprints of one pool are compared across.
func ListStoragePoolsNamed(ctx context.Context, c *Client, name string) ([]StoragePoolRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+storagePoolColumns+`
		 FROM storage_pools WHERE `+storagePoolUsable+` AND name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	out := make([]StoragePoolRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, scanStoragePool(r))
	}
	return out, nil
}

// DisksNamingRBDImage returns the live vm_disks rows whose path names the rbd
// image spec ("<pool>[/<ns>]/<image>"), whatever options their locators carry:
// "rbd:<spec>" or "rbd:<spec>:…". Two rows can name one image with different
// option suffixes, so an exact path match is not a reference check for rbd.
func DisksNamingRBDImage(ctx context.Context, c *Client, spec string) ([]DiskRecord, error) {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace("rbd:" + spec + ":")
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path FROM vm_disks
		 WHERE (path = ? OR path LIKE ? ESCAPE '\') AND deleted_at IS NULL`,
		"rbd:"+spec, esc+"%")
	if err != nil {
		return nil, err
	}
	out := make([]DiskRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, DiskRecord{VMName: r.String("vm_name"), DiskName: r.String("disk_name"),
			HostName: r.String("host_name"), Path: r.String("path")})
	}
	return out, nil
}
