package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Pool-file records on shared storage, and the records epoch.
//
// A record in <data_dir>/pool-uploads.json is this host's. A file on an NFS
// export several hosts mount is the same file on all of them, so its record
// is also written to the replicated rows (corrosion/pool_records.go), keyed by
// the export of its directory, and read from there on every host. Such a
// record is bound to the file by size and modification time: the server's,
// the same on every client. Device and inode numbers are not.

// replicaSlot is the replicated record of one VM disk's replicas in one
// directory on shared storage.
type replicaSlot struct {
	Pool    string              `json:"pool"`
	Project string              `json:"project"`
	Files   map[string]slotFile `json:"files"`
}

type slotFile struct {
	Size    int64 `json:"size"`
	MtimeNs int64 `json:"mtime_ns"`
}

// sharedStorageID is the NFS export dir is on (with the path below the
// mount), the identity it has on every host; false when it is not on NFS.
func sharedStorageID(dir string) (string, bool) {
	mt, err := storage.ReadMountTable()
	if err != nil {
		return "", false
	}
	b, err := mt.NFSBackingOf(dir)
	if err != nil || b == nil {
		return "", false
	}
	return b.Export.String(), true
}

func replicaSlotKey(id, vm, disk string) string {
	return corrosion.PoolReplicasKeyPrefix + id + "/" + vm + "/" + disk
}

// shareRecord writes path's record to the replicated rows when path is on
// shared storage. A record not shared leaves the file unrecorded on other
// hosts, where it is never taken for anyone's by its name (see
// isLegacyUnrecorded), so a failure only warns.
func (s *Server) shareRecord(ctx context.Context, path string, u poolUpload, forget bool) {
	id, ok := sharedStorageID(filepath.Dir(path))
	if !ok {
		return
	}
	s.markPoolRecordsStarted(ctx)
	name := filepath.Base(path)
	var key, value string
	if u.VM != "" {
		key = replicaSlotKey(id, u.VM, u.Disk)
		slot := replicaSlot{Files: map[string]slotFile{}}
		if v, found, err := corrosion.GetPoolRecord(ctx, s.db, key); err == nil && found {
			_ = json.Unmarshal([]byte(v), &slot)
			if slot.Files == nil {
				slot.Files = map[string]slotFile{}
			}
		}
		if forget {
			delete(slot.Files, name)
		} else {
			slot.Pool, slot.Project = u.Pool, u.Project
			slot.Files[name] = slotFile{Size: u.Size, MtimeNs: u.MtimeNs}
		}
		b, _ := json.Marshal(slot)
		value = string(b)
	} else {
		key = corrosion.PoolUploadKeyPrefix + id + "/" + name
		value = "{}"
		if !forget {
			u.Dev, u.Ino = 0, 0
			b, _ := json.Marshal(u)
			value = string(b)
		}
	}
	if err := corrosion.SetPoolRecord(ctx, s.db, key, value, s.hostName); err != nil && !errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
		slog.Warn("pool file record not shared with the cluster", "path", path, "error", err)
	}
}

// addSharedRecords adds to m the replicated records of the files in dir, when
// dir is on shared storage. This host's own record of a file comes first.
func (s *Server) addSharedRecords(ctx context.Context, m map[string]poolUpload, dir string) error {
	id, ok := sharedStorageID(dir)
	if !ok {
		return nil
	}
	ups, err := corrosion.ListPoolRecords(ctx, s.db, corrosion.PoolUploadKeyPrefix+id+"/")
	if err != nil {
		return err
	}
	for k, v := range ups {
		name := strings.TrimPrefix(k, corrosion.PoolUploadKeyPrefix+id+"/")
		var u poolUpload
		if strings.Contains(name, "/") || json.Unmarshal([]byte(v), &u) != nil || u.Size == 0 && u.MtimeNs == 0 {
			continue
		}
		u.shared = true
		if p := filepath.Join(dir, name); !hasRecord(m, p) {
			m[p] = u
		}
	}
	reps, err := corrosion.ListPoolRecords(ctx, s.db, corrosion.PoolReplicasKeyPrefix+id+"/")
	if err != nil {
		return err
	}
	for k, v := range reps {
		vm, disk, found := strings.Cut(strings.TrimPrefix(k, corrosion.PoolReplicasKeyPrefix+id+"/"), "/")
		var slot replicaSlot
		if !found || strings.Contains(disk, "/") || json.Unmarshal([]byte(v), &slot) != nil {
			continue
		}
		for name, f := range slot.Files {
			p := filepath.Join(dir, name)
			if strings.Contains(name, "/") || hasRecord(m, p) {
				continue
			}
			m[p] = poolUpload{Pool: slot.Pool, Project: slot.Project, VM: vm, Disk: disk, Size: f.Size, MtimeNs: f.MtimeNs, shared: true}
		}
	}
	return nil
}

func hasRecord(m map[string]poolUpload, path string) bool {
	_, ok := m[filepath.Clean(path)]
	return ok
}

// markPoolRecordsStarted records, once, that this host has begun recording
// pool files (called at start, and again whenever it records, in case the
// replicated rows were not writable yet).
func (s *Server) markPoolRecordsStarted(ctx context.Context) {
	if err := corrosion.MarkPoolRecordsHost(ctx, s.db, s.hostName, time.Now()); err != nil && !errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
		slog.Warn("pool file records: start not recorded", "error", err)
	}
}

// poolRecordsEpoch is when every host had begun recording pool files; false
// while one has not. Once known it never changes, so it is kept.
func (s *Server) poolRecordsEpoch(ctx context.Context) (time.Time, bool) {
	if t := s.poolRecordsEpochAt.Load(); t != nil {
		return *t, true
	}
	t, ok, err := corrosion.PoolRecordsEpoch(ctx, s.db)
	if err != nil || !ok {
		return time.Time{}, false
	}
	s.poolRecordsEpochAt.Store(&t)
	return t, true
}

// isLegacyUnrecorded reports whether a file with no record can be a replica
// made before records: it was modified before every host had begun recording
// (or not every host has yet). A file made since, by any host's daemon, is
// recorded, so an unrecorded one was put there by something else.
func (s *Server) isLegacyUnrecorded(ctx context.Context, path string) bool {
	epoch, ok := s.poolRecordsEpoch(ctx)
	if !ok {
		return true
	}
	fi, err := os.Lstat(path)
	return err == nil && !fi.ModTime().After(epoch)
}
