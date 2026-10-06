package corrosion

// The cluster-global ISO library's replicated state (docs/storage.md,
// "Installer ISOs"). It lives in cluster_policies, written through its one
// upsert (clusterPolicyUpsertSQL) and so behind the same failover_scope_v1
// gate — no new table and no new statement shape. The rows:
//
//   - iso_library_mode: where the global library ("isos") lives. "sync" keeps
//     a local copy on every host, copied between hosts by the daemon and
//     verified by sha256; "shared" means the isos pool is on storage every host
//     mounts. With no row the mode is "shared" when some host already has an
//     isos pool the daemon did not make (its files stay usable as they are),
//     and "sync" otherwise.
//   - iso_library/<file>: one per file of a sync-mode library — its sha256 and
//     size, or a removal (a tombstone, so a host that was down when the file
//     was removed deletes its copy). Each is stamped with the generation it
//     was written in — the mode row's updated_at — and a record of another
//     generation means nothing: setting the mode starts a new generation, and
//     every host then records what it holds (ReconcileGeneration). A record
//     with no content ("{}") is a collected one.
//   - iso_library_host/<host>: what a host has applied — the generation and,
//     per record, the version it applied. A tombstone every host has applied
//     (that exact version) is collected.
//
// cluster_policies has no statement that deletes a row, and adding one is a
// new replicated shape, so a collected record stays as an empty row.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// ISOLibrarySync keeps a verified local copy of every library file on
	// every host.
	ISOLibrarySync = "sync"
	// ISOLibraryShared means the isos pool is on storage every host mounts.
	ISOLibraryShared = "shared"

	// ISOLibraryPool is the name of the global library pool.
	ISOLibraryPool = "isos"

	clusterPolicyISOLibraryMode = "iso_library_mode"
	isoCatalogKeyPrefix         = "iso_library/"
	isoHostKeyPrefix            = "iso_library_host/"
)

// ErrUnknownISOLibraryMode is a stored mode this build does not implement (a
// later release's, arriving by replication). Callers fail closed on it.
var ErrUnknownISOLibraryMode = errors.New("unknown ISO library mode")

// ValidISOLibraryMode reports whether m is a mode this build implements.
func ValidISOLibraryMode(m string) bool { return m == ISOLibrarySync || m == ISOLibraryShared }

// IsBuiltinISOLibraryRow reports whether a pool row has the shape of the
// library the daemon makes: the global "isos" dir pool at <data_dir>/pools/isos.
func IsBuiltinISOLibraryRow(p StoragePoolRecord) bool {
	return p.Name == ISOLibraryPool && p.Project == "" && p.Driver == "dir" &&
		filepath.Base(p.Target) == "isos" && filepath.Base(filepath.Dir(p.Target)) == "pools"
}

// ISOLibraryModePolicy is the effective mode. UpdatedAt is the generation
// library records are stamped with; Implicit is true when no row was ever
// written.
type ISOLibraryModePolicy struct {
	Value     string
	SetBy     string
	UpdatedAt string
	Implicit  bool
}

// GetISOLibraryMode reads the effective mode (see the file comment for the
// default). A stored value this build does not implement returns it with
// ErrUnknownISOLibraryMode.
func GetISOLibraryMode(ctx context.Context, c *Client) (ISOLibraryModePolicy, error) {
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		clusterPolicyISOLibraryMode)
	if err != nil {
		return ISOLibraryModePolicy{}, err
	}
	if len(rows) == 0 {
		p := ISOLibraryModePolicy{Value: ISOLibrarySync, Implicit: true}
		pools, err := ListAllStoragePools(ctx, c)
		if err != nil {
			return ISOLibraryModePolicy{}, err
		}
		for _, r := range pools {
			if r.Name == ISOLibraryPool && r.Project == "" && !IsBuiltinISOLibraryRow(r) {
				p.Value = ISOLibraryShared
				break
			}
		}
		return p, nil
	}
	p := ISOLibraryModePolicy{Value: rows[0].String("value"), SetBy: rows[0].String("set_by"), UpdatedAt: rows[0].String("updated_at")}
	if !ValidISOLibraryMode(p.Value) {
		return p, fmt.Errorf("%w %q", ErrUnknownISOLibraryMode, p.Value)
	}
	return p, nil
}

// SetISOLibraryMode writes the mode, which starts a new record generation. It
// refuses with ErrClusterPolicyGateClosed until failover_scope_v1 has latched.
func SetISOLibraryMode(ctx context.Context, c *Client, mode, setBy string) error {
	if !ValidISOLibraryMode(mode) {
		return fmt.Errorf("%w %q (valid: %s, %s)", ErrUnknownISOLibraryMode, mode, ISOLibrarySync, ISOLibraryShared)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyISOLibraryMode, mode, setBy, c.NowTS())
}

// ISOCatalogEntry is one file record of a sync-mode global library.
type ISOCatalogEntry struct {
	Name      string `json:"-"`
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Origin    string `json:"origin,omitempty"` // the host that wrote it
	Deleted   bool   `json:"deleted,omitempty"`
	Gen       string `json:"gen,omitempty"`
	SetBy     string `json:"-"`
	UpdatedAt string `json:"-"`
}

// Collected reports whether the record carries nothing (it was collected).
func (e ISOCatalogEntry) Collected() bool { return !e.Deleted && e.SHA256 == "" }

// keyRange is the half-open key range of a prefix ending in '/': '0' is the
// byte after '/', and no LIKE wildcard can widen it.
func keyRange(prefix string) (string, string) {
	return prefix, strings.TrimSuffix(prefix, "/") + "0"
}

// ListISOCatalog returns every record row of every generation, collected ones
// included. A value that does not decode is skipped: it can only be a later
// release's.
func ListISOCatalog(ctx context.Context, c *Client) ([]ISOCatalogEntry, error) {
	lo, hi := keyRange(isoCatalogKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at FROM cluster_policies
		 WHERE key >= ? AND key < ? AND deleted_at IS NULL ORDER BY key`, lo, hi)
	if err != nil {
		return nil, err
	}
	out := make([]ISOCatalogEntry, 0, len(rows))
	for _, r := range rows {
		var e ISOCatalogEntry
		if json.Unmarshal([]byte(r.String("value")), &e) != nil {
			continue
		}
		e.Name = strings.TrimPrefix(r.String("key"), isoCatalogKeyPrefix)
		e.SetBy, e.UpdatedAt = r.String("set_by"), r.String("updated_at")
		if e.Name == "" {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// CurrentISOCatalog returns the effective mode and the records of its
// generation that carry something, by file name.
func CurrentISOCatalog(ctx context.Context, c *Client) (ISOLibraryModePolicy, map[string]ISOCatalogEntry, error) {
	mode, err := GetISOLibraryMode(ctx, c)
	if err != nil {
		return mode, nil, err
	}
	all, err := ListISOCatalog(ctx, c)
	if err != nil {
		return mode, nil, err
	}
	out := map[string]ISOCatalogEntry{}
	for _, e := range all {
		if e.Gen == mode.UpdatedAt && !e.Collected() {
			out[e.Name] = e
		}
	}
	return mode, out, nil
}

// GetISOCatalogEntry returns the current-generation record for name, if any
// (a tombstone included).
func GetISOCatalogEntry(ctx context.Context, c *Client, name string) (ISOCatalogEntry, bool, error) {
	_, cur, err := CurrentISOCatalog(ctx, c)
	if err != nil {
		return ISOCatalogEntry{}, false, err
	}
	e, ok := cur[name]
	return e, ok, nil
}

// PutISOCatalogEntry records (or, with e.Deleted, retires) a library file in
// the current generation. A positive record over a tombstone clears it.
func PutISOCatalogEntry(ctx context.Context, c *Client, e ISOCatalogEntry, setBy string) error {
	if e.Name == "" || strings.ContainsAny(e.Name, "/%") {
		return fmt.Errorf("invalid ISO library file name %q", e.Name)
	}
	if !e.Deleted && len(e.SHA256) != 64 {
		return fmt.Errorf("ISO library entry %q needs a sha256", e.Name)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	mode, err := GetISOLibraryMode(ctx, c)
	if err != nil {
		return err
	}
	e.Gen = mode.UpdatedAt
	if e.Deleted {
		e.SHA256, e.Size = "", 0
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, isoCatalogKeyPrefix+e.Name, string(b), setBy, c.NowTS())
}

// CollectISOCatalogEntry empties a record (see the file comment).
func CollectISOCatalogEntry(ctx context.Context, c *Client, name, setBy string) error {
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, isoCatalogKeyPrefix+name, "{}", setBy, c.NowTS())
}

// ISOLibraryHostAck is what one host has applied of the library records: per
// record (file name → the UpdatedAt of the version it applied), because
// records from different origins can replicate out of order, so a high-water
// mark could claim a tombstone that never arrived.
type ISOLibraryHostAck struct {
	Host    string            `json:"-"`
	Gen     string            `json:"gen"`
	Applied map[string]string `json:"applied,omitempty"`
}

// ListISOLibraryHostAcks returns every host's ack, by host.
func ListISOLibraryHostAcks(ctx context.Context, c *Client) (map[string]ISOLibraryHostAck, error) {
	lo, hi := keyRange(isoHostKeyPrefix)
	rows, err := c.Query(ctx,
		`SELECT key, value FROM cluster_policies WHERE key >= ? AND key < ? AND deleted_at IS NULL`, lo, hi)
	if err != nil {
		return nil, err
	}
	out := map[string]ISOLibraryHostAck{}
	for _, r := range rows {
		var a ISOLibraryHostAck
		if json.Unmarshal([]byte(r.String("value")), &a) != nil {
			continue
		}
		a.Host = strings.TrimPrefix(r.String("key"), isoHostKeyPrefix)
		out[a.Host] = a
	}
	return out, nil
}

// PutISOLibraryHostAck records what host has applied.
func PutISOLibraryHostAck(ctx context.Context, c *Client, a ISOLibraryHostAck) error {
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, isoHostKeyPrefix+a.Host, string(b), a.Host, c.NowTS())
}

// ISOTimestampAtOrAfter reports whether ts is at or after ref in replication
// order (RFC3339 and HLC timestamps compare correctly with each other).
func ISOTimestampAtOrAfter(ts, ref string) bool { return lwwOrder(ref, ts) <= 0 }
