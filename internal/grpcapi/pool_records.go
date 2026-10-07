package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Pool-file records on shared storage, and when they are complete.
//
// A record in <data_dir>/pool-uploads.json is this host's. A file on storage
// several hosts mount — NFS, CephFS, GlusterFS, CIFS/SMB — is the same file
// on all of them, so its record is also written to the replicated rows
// (corrosion/pool_records.go), keyed by the storage's identity
// (storage.SharedStore.ID), and read from there on every host. Such a record
// is bound to the file by size and modification time: the server's, the same
// on every client. Inode numbers are not on every network filesystem, and
// device numbers are not even across a remount of one host's.
//
// Records only ever add proof. A file with no record, or whose records no
// longer describe it, is matched by its name, as before records — except in a
// directory whose store's shared records this host can see, once every host
// with a pool there had begun sharing them (storeRecordsEpoch): an unrecorded
// file made after that was made by no host's daemon, and is never taken for a
// replica by its name.

// replicaRow is one host's replicated record of one VM disk's replicas (and
// replicate-volume copies) on one store.
type replicaRow struct {
	Pool    string              `json:"pool"`
	Project string              `json:"project"`
	VM      string              `json:"vm"`
	VMUUID  string              `json:"vm_uuid,omitempty"`
	Disk    string              `json:"disk"`
	Files   map[string]slotFile `json:"files"`
}

type slotFile struct {
	Size    int64 `json:"size"`
	MtimeNs int64 `json:"mtime_ns"`
	Copy    bool  `json:"copy,omitempty"`
}

// uploadRow is one host's replicated record of the uploads it recorded on
// one store, by file name.
type uploadRow struct {
	Files map[string]poolUpload `json:"files"`
}

// sharedStoreOf is the storage dir is on (storage.SharedStoreOf).
func sharedStoreOf(dir string) storage.SharedStore {
	return storage.SharedStoreOf(dir)
}

// storeSeg is a store's identity as one key segment.
func storeSeg(id string) string { return url.PathEscape(id) }

func uploadRowKey(id, host string) string {
	return corrosion.PoolUploadKeyPrefix + storeSeg(id) + "/" + host
}

func replicaRowPrefix(id, host string) string {
	return corrosion.PoolReplicasKeyPrefix + storeSeg(id) + "/" + host + "/"
}

// replicaRowKey is keyed by the VM's project and uuid, never its name: a VM
// of the same name in another project writes another row.
func replicaRowKey(id, host string, u poolUpload) string {
	uuid := u.VMUUID
	if uuid == "" {
		uuid = "-"
	}
	return replicaRowPrefix(id, host) + url.PathEscape(u.Project) + "/" + url.PathEscape(uuid) + "/" + url.PathEscape(u.Disk)
}

// shareRecord writes path's record to this host's replicated rows when path
// is on shared storage with an identity. A record that cannot be written
// fails the caller, which removes the file: on other hosts it would be an
// unrecorded file made after the records epoch, never matched.
func (s *Server) shareRecord(ctx context.Context, path string, u poolUpload) error {
	dir, name := filepath.Dir(path), filepath.Base(path)
	st := sharedStoreOf(dir)
	if st.ID == "" || !s.db.MayWriteClusterPolicy() {
		return nil
	}
	if err := s.refreshHostStores(ctx); err != nil {
		return err
	}
	if u.VM != "" {
		key := replicaRowKey(st.ID, s.hostName, u)
		return s.updateRow(ctx, key, func(v string) (string, error) {
			row := replicaRow{}
			_ = json.Unmarshal([]byte(v), &row)
			row.Pool, row.Project, row.VM, row.VMUUID, row.Disk = u.Pool, u.Project, u.VM, u.VMUUID, u.Disk
			if row.Files == nil {
				row.Files = map[string]slotFile{}
			}
			row.Files[name] = slotFile{Size: u.Size, MtimeNs: u.MtimeNs, Copy: u.Copy}
			dropGone(dir, row.Files)
			b, err := json.Marshal(row)
			return string(b), err
		})
	}
	return s.updateRow(ctx, uploadRowKey(st.ID, s.hostName), func(v string) (string, error) {
		row := uploadRow{}
		_ = json.Unmarshal([]byte(v), &row)
		if row.Files == nil {
			row.Files = map[string]poolUpload{}
		}
		row.Files[name] = u
		dropGone(dir, row.Files)
		b, err := json.Marshal(row)
		return string(b), err
	})
}

// forgetShared drops path from this host's replicated rows. Another host's
// row may still name it; with the file gone that entry matches nothing, and
// that host drops it the next time it writes the row.
func (s *Server) forgetShared(ctx context.Context, path string) error {
	dir, name := filepath.Dir(path), filepath.Base(path)
	st := sharedStoreOf(dir)
	if st.ID == "" || !s.db.MayWriteClusterPolicy() {
		return nil
	}
	var errs []error
	errs = append(errs, s.updateRowIf(ctx, uploadRowKey(st.ID, s.hostName), func(v string) (string, bool, error) {
		row := uploadRow{}
		if json.Unmarshal([]byte(v), &row) != nil || row.Files == nil {
			return "", false, nil
		}
		if _, ok := row.Files[name]; !ok {
			return "", false, nil
		}
		delete(row.Files, name)
		b, err := json.Marshal(row)
		return string(b), true, err
	}))
	rows, err := corrosion.ListPoolRecords(ctx, s.db, replicaRowPrefix(st.ID, s.hostName))
	if err != nil {
		return err
	}
	for key := range rows {
		errs = append(errs, s.updateRowIf(ctx, key, func(v string) (string, bool, error) {
			row := replicaRow{}
			if json.Unmarshal([]byte(v), &row) != nil {
				return "", false, nil
			}
			if _, ok := row.Files[name]; !ok {
				return "", false, nil
			}
			delete(row.Files, name)
			b, err := json.Marshal(row)
			return string(b), true, err
		}))
	}
	return errors.Join(errs...)
}

// dropGone removes from files every name whose file is gone from dir (dir
// itself readable), so a row holds only files that exist.
func dropGone[T any](dir string, files map[string]T) {
	if _, err := os.Lstat(dir); err != nil {
		return
	}
	for n := range files {
		if _, err := os.Lstat(filepath.Join(dir, n)); errors.Is(err, fs.ErrNotExist) {
			delete(files, n)
		}
	}
}

// sharedWriteAttempts bounds the retries of one replicated record write.
var sharedWriteAttempts = 3

func (s *Server) updateRow(ctx context.Context, key string, mutate func(string) (string, error)) error {
	return s.updateRowIf(ctx, key, func(v string) (string, bool, error) {
		nv, err := mutate(v)
		return nv, true, err
	})
}

// updateRowIf read-modify-writes this host's row key (only this host writes
// it, under poolUploadsMu, which the caller holds), retrying a failed write.
func (s *Server) updateRowIf(ctx context.Context, key string, mutate func(string) (string, bool, error)) error {
	var err error
	for attempt := range sharedWriteAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(err, ctx.Err())
			case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
			}
		}
		var cur, next string
		var write bool
		cur, _, err = corrosion.GetPoolRecord(ctx, s.db, key)
		if err != nil {
			continue
		}
		if next, write, err = mutate(cur); err != nil || !write {
			return err
		}
		err = corrosion.SetPoolRecord(ctx, s.db, key, next, s.hostName)
		if err == nil || errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil
		}
	}
	return fmt.Errorf("record %s for the cluster: %w", key, err)
}

// addSharedRecords adds to m the replicated records of the files in dir, when
// dir is on shared storage with an identity: every host's rows, after this
// host's own record.
func (s *Server) addSharedRecords(ctx context.Context, m poolRecords, dir string) error {
	st := sharedStoreOf(dir)
	if st.ID == "" {
		return nil
	}
	prefix := corrosion.PoolUploadKeyPrefix + storeSeg(st.ID) + "/"
	ups, err := corrosion.ListPoolRecords(ctx, s.db, prefix)
	if err != nil {
		return err
	}
	for _, key := range sortedKeys(ups) {
		row := uploadRow{}
		if strings.Contains(strings.TrimPrefix(key, prefix), "/") || json.Unmarshal([]byte(ups[key]), &row) != nil {
			continue
		}
		for _, name := range sortedKeys(row.Files) {
			u := row.Files[name]
			if strings.Contains(name, "/") || u.VM != "" {
				continue
			}
			u.shared = true
			p := filepath.Join(dir, name)
			m[p] = append(m[p], u)
		}
	}
	prefix = corrosion.PoolReplicasKeyPrefix + storeSeg(st.ID) + "/"
	reps, err := corrosion.ListPoolRecords(ctx, s.db, prefix)
	if err != nil {
		return err
	}
	for _, key := range sortedKeys(reps) {
		row := replicaRow{}
		if json.Unmarshal([]byte(reps[key]), &row) != nil || row.VM == "" || row.Disk == "" {
			continue
		}
		for _, name := range sortedKeys(row.Files) {
			f := row.Files[name]
			if strings.Contains(name, "/") {
				continue
			}
			p := filepath.Join(dir, name)
			m[p] = append(m[p], poolUpload{Pool: row.Pool, Project: row.Project, VM: row.VM, VMUUID: row.VMUUID, Disk: row.Disk,
				Copy: f.Copy, Size: f.Size, MtimeNs: f.MtimeNs, shared: true})
		}
	}
	return nil
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// MarkPoolRecords records that this host has begun recording pool files, and
// which shared stores its pools are on now (refreshHostStores). It runs at
// start and then periodically (RunPoolRecordsMarker): on a new cluster the
// replicated rows are not writable at first start (failover_scope_v1 has not
// latched yet), and a remount may move a pool to another store identity.
func (s *Server) MarkPoolRecords(ctx context.Context) {
	if !s.db.MayWriteClusterPolicy() {
		return
	}
	if err := corrosion.MarkPoolRecordsHost(ctx, s.db, s.hostName, time.Now()); err != nil {
		slog.Warn("pool file records: start not recorded", "error", err)
	}
	if err := s.refreshHostStores(ctx); err != nil {
		slog.Warn("pool file records: this host's stores not recorded", "error", err)
	}
}

// hostStoreEntry is, for one of a host's pools, the identities of the
// stores its content directories are on now, and since when.
type hostStoreEntry struct {
	IDs   []string  `json:"ids"`
	Since time.Time `json:"since"`
}

func hostStoresKey(host string) string { return corrosion.PoolRecordsHostStoresPrefix + host }

// refreshHostStores rewrites this host's row of which stores its pools are on
// when that changed. A pool whose stores changed gets a new Since: the host
// shares its records of a store only from when it moved onto it, and
// whatever it wrote elsewhere meanwhile is recorded under the other identity.
func (s *Server) refreshHostStores(ctx context.Context) error {
	cur := s.localPoolStoreIDs(ctx)
	s.hostStoresMu.Lock()
	defer s.hostStoresMu.Unlock()
	v, _, err := corrosion.GetPoolRecord(ctx, s.db, hostStoresKey(s.hostName))
	if err != nil {
		return err
	}
	old := map[string]hostStoreEntry{}
	_ = json.Unmarshal([]byte(v), &old)
	next := make(map[string]hostStoreEntry, len(cur))
	changed := len(old) != len(cur)
	now := time.Now().UTC()
	for pool, ids := range cur {
		if e, ok := old[pool]; ok && slices.Equal(e.IDs, ids) {
			next[pool] = e
			continue
		}
		next[pool] = hostStoreEntry{IDs: ids, Since: now}
		changed = true
	}
	if !changed {
		return nil
	}
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	s.epochCache.Clear()
	if err := corrosion.SetPoolRecord(ctx, s.db, hostStoresKey(s.hostName), string(b), s.hostName); err != nil && !errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
		return err
	}
	return nil
}

// poolRecordsMarkInterval is how often a running daemon retries its marks.
var poolRecordsMarkInterval = 5 * time.Minute

// RunPoolRecordsMarker marks now and then every poolRecordsMarkInterval
// until ctx ends (MarkPoolRecords).
func (s *Server) RunPoolRecordsMarker(ctx context.Context) {
	t := time.NewTicker(poolRecordsMarkInterval)
	defer t.Stop()
	for {
		s.MarkPoolRecords(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// localPoolStoreIDs maps each of this host's file pools to the identities of
// the shared stores its content directories are on now (sorted; none for a
// pool on local or unidentified storage).
func (s *Server) localPoolStoreIDs(ctx context.Context) map[string][]string {
	out := map[string][]string{}
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return out
	}
	for _, p := range pools {
		if !isFileBasedDriver(p.Driver) {
			continue
		}
		dir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target})
		if err != nil {
			continue
		}
		ids := []string{}
		for _, d := range s.poolContentDirs(dir) {
			if id := sharedStoreOf(d).ID; id != "" && !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		out[p.Name] = ids
	}
	return out
}

// epochEntry is a cached answer of storeRecordsEpoch.
type epochEntry struct {
	at    time.Time
	epoch time.Time
	ok    bool
}

// How long a store's records epoch is reused: a known one for a while (every
// host converges on the replicated epoch row within it), an unknown one only
// briefly (a host's mark may arrive any moment). Vars for tests.
var (
	poolRecordsEpochTTL    = 30 * time.Second
	poolRecordsEpochNegTTL = 3 * time.Second
)

// storeRecordsEpoch is when the shared records of store id became complete:
// the later of the cluster's records epoch (every host records) and the
// moment every host holding a pool on that store last moved onto it, as
// each host's current row says (refreshHostStores). False while that is not
// known: the rows are not writable, or some such host is not on this
// identity now (it identifies the store differently, or is mid-move), or has
// not said yet. The epoch is recomputed, never kept: a host adding a pool
// there moves it later, which only lets more files be matched by name.
func (s *Server) storeRecordsEpoch(ctx context.Context, id string) (time.Time, bool) {
	now := time.Now()
	if v, ok := s.epochCache.Load(id); ok {
		e := v.(epochEntry)
		ttl := poolRecordsEpochNegTTL
		if e.ok {
			ttl = poolRecordsEpochTTL
		}
		if now.Sub(e.at) < ttl {
			return e.epoch, e.ok
		}
	}
	epoch, ok := s.computeStoreRecordsEpoch(ctx, id)
	s.epochCache.Store(id, epochEntry{at: now, epoch: epoch, ok: ok})
	return epoch, ok
}

func (s *Server) computeStoreRecordsEpoch(ctx context.Context, id string) (time.Time, bool) {
	if !s.db.MayWriteClusterPolicy() {
		return time.Time{}, false
	}
	epoch, ok, err := corrosion.PoolRecordsEpoch(ctx, s.db)
	if err != nil || !ok {
		return time.Time{}, false
	}
	var pools []string
	for pool, ids := range s.localPoolStoreIDs(ctx) {
		if slices.Contains(ids, id) {
			pools = append(pools, pool)
		}
	}
	if len(pools) == 0 {
		return time.Time{}, false
	}
	holders, err := corrosion.HostsWithPools(ctx, s.db, pools)
	if err != nil || len(holders) == 0 {
		return time.Time{}, false
	}
	rows, err := corrosion.ListPoolRecords(ctx, s.db, corrosion.PoolRecordsHostStoresPrefix)
	if err != nil {
		return time.Time{}, false
	}
	for host, held := range holders {
		cur := map[string]hostStoreEntry{}
		if json.Unmarshal([]byte(rows[hostStoresKey(host)]), &cur) != nil {
			return time.Time{}, false
		}
		for _, pool := range held {
			e, ok := cur[pool]
			if !ok || !slices.Contains(e.IDs, id) {
				return time.Time{}, false
			}
			if e.Since.After(epoch) {
				epoch = e.Since
			}
		}
	}
	return epoch, true
}

// isLegacyUnrecorded reports whether a file with no record (or none that
// still describes it) may be matched by its name, as a replica made before
// records: always, unless its directory's store has shared records this host
// can see, complete since storeRecordsEpoch; then only a file modified
// before that.
func (s *Server) isLegacyUnrecorded(ctx context.Context, path string) bool {
	st := sharedStoreOf(filepath.Dir(path))
	if st.ID == "" {
		return true
	}
	epoch, ok := s.storeRecordsEpoch(ctx, st.ID)
	if !ok {
		return true
	}
	fi, err := os.Lstat(path)
	return err == nil && !fi.ModTime().After(epoch)
}

// uploadMarkerDir holds, beside the files of a directory on a shared store
// with an identity, one empty marker per file the upload API placed there. It
// is written on the store itself before the upload is published, so every
// host that can see the file can see the marker — across a partition too,
// where the upload's record may not arrive. A marker only ever withdraws a
// file from being taken as a late replica (lateReplicaOK); it gives no one
// anything. Listings skip it (a directory), and no content name reaches into
// it.
const uploadMarkerDir = ".litevirt-uploads"

func uploadMarkerPath(path string) string {
	return filepath.Join(filepath.Dir(path), uploadMarkerDir, filepath.Base(path))
}

// markUpload writes path's upload marker, durably, when path is on a shared
// store with an identity. A marker directory that is not a real directory
// (someone with access to the store put something else there) is not written
// through: the upload goes ahead unmarked, as before markers.
func markUpload(path string) error {
	dir := filepath.Dir(path)
	if sharedStoreOf(dir).ID == "" {
		return nil
	}
	mdir := filepath.Join(dir, uploadMarkerDir)
	if err := os.Mkdir(mdir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if fi, err := os.Lstat(mdir); err != nil || !fi.IsDir() {
		slog.Warn("upload marker directory is not a directory; upload not marked", "dir", mdir)
		return nil
	}
	f, err := storage.OpenPoolFile(uploadMarkerPath(path), os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncPath(mdir)
}

// unmarkUpload removes path's upload marker, if any.
func unmarkUpload(path string) {
	_ = os.Remove(uploadMarkerPath(path))
}

// hasUploadMarker reports whether the upload API placed path (or that cannot
// be ruled out: any error but its absence counts as marked).
func hasUploadMarker(path string) bool {
	_, err := os.Lstat(uploadMarkerPath(path))
	return !errors.Is(err, fs.ErrNotExist)
}
