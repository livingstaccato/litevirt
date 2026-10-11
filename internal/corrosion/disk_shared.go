package corrosion

import (
	"context"
	"sort"
	"strings"
)

// sharedStorageTypes is the set of disk storage drivers that place a disk on
// cluster-shared storage — a second host can open and WRITE the same bytes. A
// shared writable disk is the split-brain hazard a cross-host ownership transfer
// (auto-promote / reschedule) must fence against: unlike a local-disk replica
// (a different image on the target), starting a VM on a shared disk while the
// old owner may still be writing it corrupts the disk.
func sharedStorageType(storageType string) bool {
	switch strings.ToLower(storageType) {
	case "nfs", "ceph", "rbd", "iscsi":
		return true
	default:
		return false
	}
}

// DiskIsShared reports whether a disk lives on cluster-shared storage
// (nfs/ceph/rbd/iscsi). Local/dir/btrfs/lvm are host-local. Exported so the
// failover coordinator, health reconciler, and grpcapi promote path share one
// definition of "shared" rather than each carrying a copy.
func DiskIsShared(d DiskRecord) bool { return sharedStorageType(d.StorageType) }

// VMHasWritableSharedDisk reports whether ANY of the VM's disks is on shared
// storage. There is no read-only bit on DiskRecord, so every disk is treated as
// writable (weakest-writable-disk controls: one shared disk ⇒ the whole VM needs
// the proof-grade fence before a cross-host transfer start).
func VMHasWritableSharedDisk(disks []DiskRecord) bool {
	for _, d := range disks {
		if DiskIsShared(d) {
			return true
		}
	}
	return false
}

// VMNamesWithWritableSharedDisk returns every VM with at least one disk on
// shared storage, sorted. These are exactly the workloads a cross-host transfer
// must fence before starting, so a diagnostic can weigh how much is exposed when
// the fence is not switched on.
//
// It reads the disk rows and classifies them through DiskIsShared rather than
// filtering by storage_type in SQL. Encoding the shared set into a query would
// be the second copy of a definition this file exists to keep single — a new
// shared driver added to sharedStorageType would then silently not count here.
func VMNamesWithWritableSharedDisk(ctx context.Context, c *Client) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, storage_type FROM vm_disks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, r := range rows {
		if DiskIsShared(DiskRecord{StorageType: r.String("storage_type")}) {
			seen[r.String("vm_name")] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// DiskOnSharedStorage is the one definition of "shared" for a disk that a
// promotion and the shared-disk fence gates agree on (colonelpanik/litevirt#258
// re-review R2-m1): its storage type is shared (DiskIsShared), or the pool it
// names has a shared driver in the pool row of any of hosts — the disk's own
// host is always consulted. A read error counts as not shared by pool; the
// storage type still decides.
func DiskOnSharedStorage(ctx context.Context, c *Client, d DiskRecord, hosts ...string) bool {
	if DiskIsShared(d) {
		return true
	}
	if d.StorageVolume == "" || c == nil {
		return false
	}
	seen := map[string]bool{}
	for _, h := range append([]string{d.HostName}, hosts...) {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if p, ok, err := GetStoragePool(ctx, c, h, d.StorageVolume); err == nil && ok && sharedStorageType(p.Driver) {
			return true
		}
	}
	return false
}

// VMHasSharedDisk reports whether any of disks is on shared storage by
// DiskOnSharedStorage. Every disk is treated as writable, as in
// VMHasWritableSharedDisk.
func VMHasSharedDisk(ctx context.Context, c *Client, disks []DiskRecord, hosts ...string) bool {
	for _, d := range disks {
		if DiskOnSharedStorage(ctx, c, d, hosts...) {
			return true
		}
	}
	return false
}
