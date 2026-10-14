package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Ceph images a VM delete leaves in their pool (lab 2, Bug 2). A VM delete
// frees its disks best-effort: a ceph image a client still has open is
// refused as in use, and the VM is deleted all the same, as on main. Such an
// image is never left unnamed:
//
//   - the delete's response names it (KeptCephImageMD), and `lv rm` prints
//     each one with its pool, name and reason;
//   - it is recorded on this host (<data_dir>/ceph-kept-images.json, so a
//     restart keeps it) and named by ceph_image_leftover, with the check to
//     run — never a removal: the client that has it open may be a VM
//     elsewhere, running on it;
//   - it stops being named once a VM's disk names it again (reattached), and
//     is forgotten once its pool, answering, no longer has it (ScanCephTrash).

// condCephImageLeftover names the ceph images a VM delete left in their pool.
const condCephImageLeftover = "ceph_image_leftover"

// KeptCephImageMD is the DeleteVM response header that names, one value per
// image, a ceph image the delete left in its pool (a KeptCephImage, JSON).
const KeptCephImageMD = "x-litevirt-kept-ceph-image"

// KeptCephImage is a ceph image a VM delete left in its pool, and why.
type KeptCephImage struct {
	Image  string `json:"image"` // <pool>/<image>
	Disk   string `json:"disk"`
	Reason string `json:"reason"`
}

// cephKeptFile is the file, under the data directory, the kept images are
// recorded in.
const cephKeptFile = "ceph-kept-images.json"

type cephKeptRecord struct {
	Image  string `json:"image"`  // <pool>/<image>
	VM     string `json:"vm"`     // the VM whose delete left it
	Disk   string `json:"disk"`   // its disk name there
	Path   string `json:"path"`   // the disk's locator: identity and monitors, never a key
	Volume string `json:"volume"` // the litevirt pool it was on
	Reason string `json:"reason"`
	Since  string `json:"since"`
}

type cephKeptImages struct {
	mu     sync.Mutex
	loaded bool
	m      map[string]cephKeptRecord // image → record
}

// keptLocked loads the record file once; mu is held.
func (s *Server) keptLocked() map[string]cephKeptRecord {
	k := &s.cephKept
	if !k.loaded {
		k.loaded, k.m = true, map[string]cephKeptRecord{}
		if s.dataDir != "" {
			raw, err := os.ReadFile(filepath.Join(s.dataDir, cephKeptFile))
			switch {
			case err == nil:
				var list []cephKeptRecord
				if jerr := json.Unmarshal(raw, &list); jerr != nil {
					slog.Warn("ceph: the record of kept images cannot be read", "file", cephKeptFile, "error", jerr)
				}
				for _, r := range list {
					if r.Image != "" {
						k.m[r.Image] = r
					}
				}
			case !errors.Is(err, os.ErrNotExist):
				slog.Warn("ceph: the record of kept images cannot be read", "file", cephKeptFile, "error", err)
			}
		}
	}
	return k.m
}

// saveKeptLocked writes the record file durably; mu is held.
func (s *Server) saveKeptLocked() {
	if s.dataDir == "" {
		return
	}
	list := make([]cephKeptRecord, 0, len(s.cephKept.m))
	for _, r := range s.cephKept.m {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Image < list[j].Image })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeSynced(filepath.Join(s.dataDir, cephKeptFile), raw)
	}
	if err != nil {
		slog.Warn("ceph: the record of kept images was not saved; a restart forgets them", "error", err)
	}
}

// writeSynced replaces path with data: synced before the rename, the
// directory after.
func writeSynced(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}

// recordKeptCephImage records that deleting d's rbd image failed with err,
// so the image stays in its pool, and returns what the delete's caller is
// told.
func (s *Server) recordKeptCephImage(vmName string, d *corrosion.DiskRecord, err error) (KeptCephImage, bool) {
	l, ok := storage.ParseCephLocator(d.Path)
	if !ok {
		return KeptCephImage{}, false
	}
	k := KeptCephImage{Image: l.Spec, Disk: d.DiskName, Reason: err.Error()}
	s.cephKept.mu.Lock()
	m := s.keptLocked()
	m[l.Spec] = cephKeptRecord{Image: l.Spec, VM: vmName, Disk: d.DiskName, Path: d.Path, Volume: d.StorageVolume,
		Reason: k.Reason, Since: time.Now().UTC().Format(time.RFC3339)}
	s.saveKeptLocked()
	s.cephKept.mu.Unlock()
	slog.Warn("ceph: a VM delete left an image in its pool; named by "+condCephImageLeftover,
		"vm", vmName, "disk", d.DiskName, "image", l.Spec, "reason", k.Reason, "check", "rbd status "+l.Spec)
	return k, true
}

func (s *Server) keptRecords() []cephKeptRecord {
	s.cephKept.mu.Lock()
	defer s.cephKept.mu.Unlock()
	m := s.keptLocked()
	out := make([]cephKeptRecord, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Image < out[j].Image })
	return out
}

// setKeptHeader names the kept images in the delete's response header.
func setKeptHeader(ctx context.Context, kept []KeptCephImage) {
	if len(kept) == 0 {
		return
	}
	md := metadata.MD{}
	for _, k := range kept {
		if b, err := json.Marshal(k); err == nil {
			md.Append(KeptCephImageMD, string(b))
		}
	}
	_ = grpc.SetHeader(ctx, md)
}

// forwardKeptImages hands the kept images and kept disks (KeptDiskMD) a
// forwarded delete's owner named in hdr back to this delete's own caller.
func forwardKeptImages(ctx context.Context, hdr metadata.MD) {
	if vals := hdr.Get(KeptCephImageMD); len(vals) > 0 {
		_ = grpc.SetHeader(ctx, metadata.MD{KeptCephImageMD: vals})
	}
	if vals := hdr.Get(KeptDiskMD); len(vals) > 0 {
		_ = grpc.SetHeader(ctx, metadata.MD{KeptDiskMD: vals})
	}
}

// recheckKeptCephImages forgets the kept images their pool, answering, no
// longer has (an operator removed them). An image whose pool does not
// answer stays named.
func (s *Server) recheckKeptCephImages(ctx context.Context) {
	for _, r := range s.keptRecords() {
		drv, err := s.diskDriver(&corrosion.DiskRecord{Path: r.Path, StorageVolume: r.Volume, StorageType: "ceph"})
		if err != nil {
			continue
		}
		c, ok := drv.(storage.CephImageChecker)
		if !ok {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		exists, err := c.ImageExists(cctx, r.Path)
		cancel()
		if err != nil || exists {
			continue
		}
		s.cephKept.mu.Lock()
		delete(s.keptLocked(), r.Image)
		s.saveKeptLocked()
		s.cephKept.mu.Unlock()
		slog.Info("ceph: an image a VM delete left in its pool is gone", "image", r.Image)
	}
}

// judgeCephImages raises ceph_image_leftover for this host while an image a
// VM delete here left in its pool is still there and no VM's disk names it,
// and resolves it once none is.
func (s *Server) judgeCephImages(ctx context.Context) {
	var left []cephKeptRecord
	for _, r := range s.keptRecords() {
		// Reattached: a VM's disk names it again. A failed read keeps it
		// named.
		if rows, err := corrosion.DisksNamingRBDImage(ctx, s.db, r.Image); err == nil && len(rows) > 0 {
			continue
		}
		left = append(left, r)
	}
	subject := s.hostName
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, cephPoolEvaluator, condCephImageLeftover, "host", subject)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if len(left) == 0 {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("ceph: resolve the kept image condition", "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: cephPoolEvaluator, Code: condCephImageLeftover,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	type image struct {
		Image  string `json:"image"`
		VM     string `json:"vm"`
		Disk   string `json:"disk"`
		Since  string `json:"since"`
		Reason string `json:"reason"`
		ByHand string `json:"by_hand"`
	}
	var list []image
	for _, r := range left {
		list = append(list, image{Image: r.Image, VM: r.VM, Disk: r.Disk, Since: r.Since, Reason: r.Reason,
			ByHand: "rbd status " + r.Image + "; rbd info " + r.Image})
	}
	ev, _ := json.Marshal(map[string]any{
		"host": s.hostName, "images": list,
		"detail": fmt.Sprintf("%d ceph image(s) a VM delete on %s left in their pool still use its capacity and no VM's disk names them; "+
			"see who has each open (by_hand) — the client may be a VM still running on it — and decide by hand; litevirt removes none of them",
			len(list), s.hostName),
	})
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("ceph: raise the kept image condition", "error", err)
	}
}

// keptFromErrs is the kept images of a VM's disk deletes that failed: the
// rbd disks whose delete returned an error, their image still in the pool.
func (s *Server) keptFromErrs(vmName string, disks []corrosion.DiskRecord, errs []error) []KeptCephImage {
	var kept []KeptCephImage
	for i, err := range errs {
		if err == nil || !strings.HasPrefix(disks[i].Path, "rbd:") {
			continue
		}
		if k, ok := s.recordKeptCephImage(vmName, &disks[i], err); ok {
			kept = append(kept, k)
		}
	}
	return kept
}
