package corrosion

// Replicated pool-file records (docs/storage.md, "Pools on <data_dir>/disks
// or a shared directory"). A file in a pool on shared storage — an NFS export
// several hosts mount — is the same file on every host, so the record of whose
// it is must be too: each host keeps its own records in
// <data_dir>/pool-uploads.json, and a file on shared storage is additionally
// recorded here, in cluster_policies, so every host matches it the same way.
// Written through clusterPolicyUpsertSQL behind the failover_scope_v1 gate:
// no new table and no new statement shape. The rows:
//
//   - pool_upload/<export>/<file>: a user's (or an older node's) upload.
//   - pool_replicas/<export>/<vm>/<disk>: the replicas of one VM's disk held
//     in that directory, with the size and modification time of each.
//   - pool_records_host/<host>: when this host began recording, written at
//     start.
//   - pool_records_epoch: when every host of the cluster had begun
//     recording. A file made after it with no record was made by no recording
//     host's daemon and is never taken for a replica by its name.
//
// cluster_policies has no statement that deletes a row; a forgotten record is
// written as "{}".

import (
	"context"
	"strings"
	"time"
)

const (
	PoolUploadKeyPrefix      = "pool_upload/"
	PoolReplicasKeyPrefix    = "pool_replicas/"
	poolRecordsHostKeyPrefix = "pool_records_host/"
	poolRecordsEpochKey      = "pool_records_epoch"
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
	key := poolRecordsHostKeyPrefix + host
	if _, ok, err := GetPoolRecord(ctx, c, key); err != nil || ok {
		return err
	}
	return SetPoolRecord(ctx, c, key, at.UTC().Format(time.RFC3339Nano), host)
}

// PoolRecordsEpoch is when every host of the cluster had begun recording pool
// files, or false while some host has not (an older build, or the gate is not
// open yet). Once every live host has, the epoch is the latest of their starts
// and is written down, so a host joining or leaving later does not move it.
func PoolRecordsEpoch(ctx context.Context, c *Client) (time.Time, bool, error) {
	if v, ok, err := GetPoolRecord(ctx, c, poolRecordsEpochKey); err != nil {
		return time.Time{}, false, err
	} else if ok {
		t, perr := time.Parse(time.RFC3339Nano, v)
		return t, perr == nil, nil
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
	if epoch.IsZero() {
		return time.Time{}, false, nil
	}
	if c.MayWriteClusterPolicy() {
		if err := SetPoolRecord(ctx, c, poolRecordsEpochKey, epoch.Format(time.RFC3339Nano), "pool-records"); err != nil {
			return time.Time{}, false, err
		}
	}
	return epoch, true, nil
}
