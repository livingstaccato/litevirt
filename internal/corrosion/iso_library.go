package corrosion

// The cluster-global ISO library's replicated state (docs/storage.md,
// "Installer ISOs"). Two things live in cluster_policies, written through its
// one upsert (clusterPolicyUpsertSQL) and so behind the same failover_scope_v1
// gate — no new table and no new statement shape:
//
//   - iso_library_mode: where the global library ("isos") lives. "sync" (the
//     answer when no row exists) keeps a local copy on every host, which the
//     daemon copies between hosts and verifies by sha256; "shared" means the
//     operator put the isos pool on shared storage, so every host already sees
//     the same files.
//   - iso_library/<file>: one row per file in a sync-mode library, carrying the
//     sha256 and size every host's copy must match before a VM may start from
//     it. A removed file keeps its row, marked deleted, so a host that was down
//     when it was removed deletes its copy instead of offering it back.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// ISOLibrarySync keeps a verified local copy of every library file on
	// every host. The default.
	ISOLibrarySync = "sync"
	// ISOLibraryShared means the isos pool is on storage every host mounts.
	ISOLibraryShared = "shared"

	clusterPolicyISOLibraryMode = "iso_library_mode"
	isoCatalogKeyPrefix         = "iso_library/"
)

// ErrUnknownISOLibraryMode is a stored mode this build does not implement (a
// later release's, arriving by replication). Callers fail closed on it.
var ErrUnknownISOLibraryMode = errors.New("unknown ISO library mode")

// ValidISOLibraryMode reports whether m is a mode this build implements.
func ValidISOLibraryMode(m string) bool { return m == ISOLibrarySync || m == ISOLibraryShared }

// ISOLibraryModePolicy is the iso_library_mode row as this replica holds it.
type ISOLibraryModePolicy struct {
	Value     string
	SetBy     string
	UpdatedAt string
}

// GetISOLibraryMode reads the mode. No row is ISOLibrarySync. A value this
// build does not implement returns it with ErrUnknownISOLibraryMode.
func GetISOLibraryMode(ctx context.Context, c *Client) (ISOLibraryModePolicy, error) {
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		clusterPolicyISOLibraryMode)
	if err != nil {
		return ISOLibraryModePolicy{}, err
	}
	if len(rows) == 0 {
		return ISOLibraryModePolicy{Value: ISOLibrarySync}, nil
	}
	p := ISOLibraryModePolicy{Value: rows[0].String("value"), SetBy: rows[0].String("set_by"), UpdatedAt: rows[0].String("updated_at")}
	if !ValidISOLibraryMode(p.Value) {
		return p, fmt.Errorf("%w %q", ErrUnknownISOLibraryMode, p.Value)
	}
	return p, nil
}

// SetISOLibraryMode writes the mode, refusing with ErrClusterPolicyGateClosed
// until failover_scope_v1 has latched.
func SetISOLibraryMode(ctx context.Context, c *Client, mode, setBy string) error {
	if !ValidISOLibraryMode(mode) {
		return fmt.Errorf("%w %q (valid: %s, %s)", ErrUnknownISOLibraryMode, mode, ISOLibrarySync, ISOLibraryShared)
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyISOLibraryMode, mode, setBy, c.NowTS())
}

// ISOCatalogEntry is one file of a sync-mode global library.
type ISOCatalogEntry struct {
	Name      string `json:"-"`
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Origin    string `json:"origin,omitempty"` // the host that wrote it
	Deleted   bool   `json:"deleted,omitempty"`
	SetBy     string `json:"-"`
	UpdatedAt string `json:"-"`
}

// ListISOCatalog returns every catalog row, deleted ones included. A row whose
// value does not decode is skipped: it can only be a later release's.
func ListISOCatalog(ctx context.Context, c *Client) ([]ISOCatalogEntry, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value, set_by, updated_at FROM cluster_policies
		 WHERE key LIKE 'iso_library/%' AND deleted_at IS NULL ORDER BY key`)
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
		if e.Name == "" || (!e.Deleted && e.SHA256 == "") {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// GetISOCatalogEntry returns the catalog row for name, if any.
func GetISOCatalogEntry(ctx context.Context, c *Client, name string) (ISOCatalogEntry, bool, error) {
	all, err := ListISOCatalog(ctx, c)
	if err != nil {
		return ISOCatalogEntry{}, false, err
	}
	for _, e := range all {
		if e.Name == name {
			return e, true, nil
		}
	}
	return ISOCatalogEntry{}, false, nil
}

// PutISOCatalogEntry records (or, with e.Deleted, retires) a library file.
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
	if e.Deleted {
		e.SHA256, e.Size = "", 0
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, isoCatalogKeyPrefix+e.Name, string(b), setBy, c.NowTS())
}
