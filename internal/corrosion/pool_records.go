package corrosion

// Replicated pool-file records (docs/storage.md, "Pools on <data_dir>/disks
// or a shared directory"). A file in a pool on shared storage — an export
// several hosts mount (NFS, CephFS, GlusterFS, CIFS/SMB) — is the same file on
// every host, so the record of whose it is must be too: each host keeps its
// own records in <data_dir>/pool-uploads.json, and a file on shared storage is
// additionally recorded here, in cluster_policies, so every host matches it
// the same way. Written through clusterPolicyUpsertSQL behind the
// failover_scope_v1 gate: no new table and no new statement shape.
//
// Every row is written by one host only (the last key segment, or the one
// after the store), read-modify-written under that host's lock, so no write
// is lost to another host's; readers take the union of every host's rows.
// <store> is the storage's identity (storage.SharedStore.ID), path-escaped
// into one key segment. The rows:
//
//   - pool_upload/<store>/<host>: the users' (and older nodes') uploads that
//     host recorded there, by file name. A forgotten upload leaves the row,
//     and a file gone from the store is dropped the next time the host
//     writes it, so the row holds only files that exist.
//   - pool_replicas/<store>/<host>/<project>/<vm uuid>/<disk>: the replicas
//     (and replicate-volume copies) of one VM's disk that host placed there.
//   - pool_records_host/<host>: when this host began recording, written at
//     start (and retried until the gate opens).
//   - pool_records_hoststores/<host>: which stores this host's pools are on
//     now, and since when, per pool: rewritten whenever that changes (a
//     remount elsewhere, a re-IP, a pool added), so a host is counted for a
//     store only while it is on it, from when it last moved onto it.
//   - pool_records_epoch: when every host of the cluster had begun recording.
//
// A store's records are complete from the later of the epoch and the moment
// every host holding a pool on it moved onto it (and while each still is). A file made after that with no record
// was made by no recording host's daemon and is never taken for a replica by
// its name. Where that moment is not known — a host has not marked, or this
// host cannot identify the store — files are matched by name, as before
// records.
//
// cluster_policies has no statement that deletes a row; the rows above are
// bounded by hosts, stores and VM disks, never by history.

import (
	"context"
	"strings"
	"time"
)

const (
	PoolUploadKeyPrefix         = "pool_upload/"
	PoolReplicasKeyPrefix       = "pool_replicas/"
	PoolRecordsHostStoresPrefix = "pool_records_hoststores/"
	poolRecordsHostKeyPrefix    = "pool_records_host/"
	poolRecordsEpochKey         = "pool_records_epoch"
)

// SetPoolRecord writes one pool-file record row. It refuses with
// ErrClusterPolicyGateClosed until failover_scope_v1 has latched.
func SetPoolRecord(ctx context.Context, c *Client, key, value, setBy string) error {
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	return c.Execute(ctx, clusterPolicyUpsertSQL, key, value, setBy, c.NowTS())
}

// GetPoolRecord reads one pool-file record row.
func GetPoolRecord(ctx context.Context, c *Client, key string) (string, bool, error) {
	rows, err := c.Query(ctx, `SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, key)
	if err != nil || len(rows) == 0 {
		return "", false, err
	}
	return rows[0].String("value"), true, nil
}

// ListPoolRecords returns every row whose key starts with prefix, by key.
func ListPoolRecords(ctx context.Context, c *Client, prefix string) (map[string]string, error) {
	rows, err := c.Query(ctx,
		`SELECT key, value FROM cluster_policies WHERE key >= ? AND key < ? AND deleted_at IS NULL`,
		prefix, prefix+"\xff")
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		if k := r.String("key"); strings.HasPrefix(k, prefix) {
			out[k] = r.String("value")
		}
	}
	return out, nil
}

// MarkPoolRecordsHost records that host has begun recording pool files, once:
// the first start of a recording build on it. Gate closed: nothing is written.
func MarkPoolRecordsHost(ctx context.Context, c *Client, host string, at time.Time) error {
	return markOnce(ctx, c, poolRecordsHostKeyPrefix+host, host, at)
}

// HostsWithPools returns, by host (not deleted, in any state), which of the
// pools named in names it holds.
func HostsWithPools(ctx context.Context, c *Client, names []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, n := range names {
		rows, err := c.Query(ctx,
			`SELECT sp.host_name FROM storage_pools sp JOIN hosts h ON h.name = sp.host_name
			 WHERE sp.name = ? AND sp.deleted_at IS NULL AND h.deleted_at IS NULL`, n)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			h := r.String("host_name")
			out[h] = append(out[h], n)
		}
	}
	return out, nil
}

// PoolRecordsEpoch is when every host of the cluster had begun recording pool
// files, or false while some host has not (an older build, or the gate is not
// open yet). Once every live host has, the epoch is the latest of their starts
// and is written down, so a host joining or leaving later does not move it.
// Two hosts may write it at once from different views; the value returned is
// the row's, re-read, so every host converges on the one that won.
func PoolRecordsEpoch(ctx context.Context, c *Client) (time.Time, bool, error) {
	if t, ok, err := readPoolRecordsEpoch(ctx, c); err != nil || ok {
		return t, ok, err
	}
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		return time.Time{}, false, err
	}
	marks, err := ListPoolRecords(ctx, c, poolRecordsHostKeyPrefix)
	if err != nil {
		return time.Time{}, false, err
	}
	var epoch time.Time
	for _, h := range hosts {
		v, ok := marks[poolRecordsHostKeyPrefix+h.Name]
		if !ok {
			return time.Time{}, false, nil
		}
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return time.Time{}, false, nil
		}
		if t.After(epoch) {
			epoch = t
		}
	}
	if epoch.IsZero() || !c.MayWriteClusterPolicy() {
		return time.Time{}, false, nil
	}
	if err := SetPoolRecord(ctx, c, poolRecordsEpochKey, epoch.Format(time.RFC3339Nano), "pool-records"); err != nil {
		return time.Time{}, false, err
	}
	return readPoolRecordsEpoch(ctx, c)
}

func readPoolRecordsEpoch(ctx context.Context, c *Client) (time.Time, bool, error) {
	v, ok, err := GetPoolRecord(ctx, c, poolRecordsEpochKey)
	if err != nil || !ok {
		return time.Time{}, false, err
	}
	t, perr := time.Parse(time.RFC3339Nano, v)
	return t, perr == nil, nil
}

func markOnce(ctx context.Context, c *Client, key, host string, at time.Time) error {
	if _, ok, err := GetPoolRecord(ctx, c, key); err != nil || ok {
		return err
	}
	return SetPoolRecord(ctx, c, key, at.UTC().Format(time.RFC3339Nano), host)
}

// HostLastSeen is the latest moment any observer saw host answer
// (host_health.last_seen), and whether any observer reports it healthy now.
func HostLastSeen(ctx context.Context, c *Client, host string) (last time.Time, healthy bool, err error) {
	rows, err := c.Query(ctx, `SELECT status, last_seen FROM host_health WHERE target = ? AND deleted_at IS NULL`, host)
	if err != nil {
		return time.Time{}, false, err
	}
	for _, r := range rows {
		if r.String("status") == "healthy" {
			healthy = true
		}
		if t, ok := ParseUpdatedAt(r.String("last_seen")); ok && t.After(last) {
			last = t
		}
	}
	return last, healthy, nil
}

// DisksReferencingName returns the live disk rows, on any host, whose file,
// backing image or backing disk has the base name name: on storage several
// hosts mount at different paths, the same file is a different path on each.
func DisksReferencingName(ctx context.Context, c *Client, name string) ([]DiskRecord, error) {
	pat := "%/" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(name)
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path, backing_image, backing_disk
		 FROM vm_disks
		 WHERE (path LIKE ? ESCAPE '\' OR backing_image LIKE ? ESCAPE '\' OR backing_disk LIKE ? ESCAPE '\') AND deleted_at IS NULL`,
		pat, pat, pat)
	if err != nil {
		return nil, err
	}
	out := make([]DiskRecord, len(rows))
	for i, r := range rows {
		out[i] = DiskRecord{VMName: r.String("vm_name"), DiskName: r.String("disk_name"), HostName: r.String("host_name"),
			Path: r.String("path"), BackingImage: r.String("backing_image"), BackingDisk: r.String("backing_disk")}
	}
	return out, nil
}
