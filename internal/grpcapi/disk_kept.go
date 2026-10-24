package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Disk files a VM delete kept (lab 2 F-5). A delete never removes a disk it
// cannot prove unused, and never leaves one unnamed. A disk it kept — whether
// another VM uses it could not be told, it lies where the delete must not
// remove it, or its removal failed — is named:
//
//   - in the delete's response (KeptDiskMD), which `lv rm` prints;
//   - by an audit entry and a vm.disk_kept event of the VM;
//   - on this host, in <data_dir>/kept-disks.json (a restart keeps it), and by
//     disk_leftover, with the reason and what to check — never a removal.
//
// A kept file is forgotten once it is gone (an operator removed it, or a
// retried delete did), and is not named while a VM's disk names its path.

// condDiskLeftover names the disk files VM deletes on this host kept.
const condDiskLeftover = "disk_leftover"

// diskLeftoverEvaluator is the evaluator disk_leftover is raised under.
const diskLeftoverEvaluator = "vm_delete"

// KeptDiskMD is the DeleteVM response header that names, one value per disk,
// a disk file the delete kept (a KeptDisk, JSON).
const KeptDiskMD = "x-litevirt-kept-disk"

// KeptDisk is a disk file a VM delete kept, and why.
type KeptDisk struct {
	Path   string `json:"path"` // what to check: the file, or a btrfs disk's subvolume
	Disk   string `json:"disk"`
	Host   string `json:"host"` // the host the path is on
	Reason string `json:"reason"`
}

const diskKeptFile = "kept-disks.json"

type diskKeptRecord struct {
	KeptDisk
	VM    string `json:"vm"`
	Since string `json:"since"`
}

type diskKeptFiles struct {
	mu sync.Mutex
	m  map[string]diskKeptRecord // host + "\x00" + path → record
	// sig is the file as this process last read or wrote it (present, its
	// mtime, size, inode and ctime); a different one is re-read
	// (diskKeptLocked).
	sig diskKeptSig
	// unreadable is why the file cannot be read now: nothing is written
	// over it, and what is recorded meanwhile is kept in memory (unsaved).
	unreadable error
	unsaved    bool            // m holds entries the file does not
	unsavedKey map[string]bool // which: recorded while the file could not be read, or a save failed
	warned     bool            // unreadable is logged, once until the file reads
}

type diskKeptSig struct {
	known, present bool
	mod            time.Time
	size           int64
	ino            uint64
	ctime          int64
}

// diskKeptSigOf is fi's signature.
func diskKeptSigOf(fi os.FileInfo) diskKeptSig {
	ino, _ := fileInode(fi)
	return diskKeptSig{known: true, present: true, mod: fi.ModTime(), size: fi.Size(), ino: ino, ctime: fileCtimeNs(fi)}
}

func diskKeptKey(host, path string) string { return host + "\x00" + path }

// diskKeptLocked brings the in-memory record in line with the file and
// returns it; mu is held.
//
// The file is the operator's handle on disk_leftover: an entry removed from
// it by hand (a disk kept on purpose, one on another host) stops being named
// once the file is re-read, which is whenever its mtime or size differs from
// what this process last read or wrote — within one judgeKeptDisks pass. A
// file removed whole names nothing.
//
// A file that cannot be read (corrupt, a bad hand edit, an I/O error) is
// never written over and never read as empty: the names already in memory
// are kept, and what is recorded meanwhile is kept in memory too (unsaved);
// disk_leftover names the file and the recovery (judgeKeptDisks). Once it
// reads again, what was recorded meanwhile is merged in and saved.
func (s *Server) diskKeptLocked() map[string]diskKeptRecord {
	k := &s.diskKept
	if k.m == nil {
		k.m = map[string]diskKeptRecord{}
	}
	if s.dataDir == "" {
		return k.m
	}
	path := filepath.Join(s.dataDir, diskKeptFile)
	sig := diskKeptSig{known: true}
	fi, serr := os.Stat(path)
	switch {
	case serr == nil:
		sig = diskKeptSigOf(fi)
	case !errors.Is(serr, os.ErrNotExist):
		k.markUnreadable(path, serr)
		return k.m
	}
	if k.unreadable == nil && sig == k.sig {
		return k.m
	}
	fromFile := map[string]diskKeptRecord{}
	if sig.present {
		raw, err := os.ReadFile(path)
		if err == nil {
			var list []diskKeptRecord
			if jerr := json.Unmarshal(raw, &list); jerr != nil {
				err = jerr
			}
			for _, r := range list {
				if r.Path != "" {
					fromFile[diskKeptKey(r.Host, r.Path)] = r
				}
			}
		}
		if err != nil {
			k.markUnreadable(path, err)
			return k.m
		}
	}
	if k.unreadable != nil {
		slog.Info("delete: the record of kept disks reads again", "file", path)
	}
	k.unreadable, k.warned = nil, false
	k.sig = sig
	if k.unsaved {
		// Recorded while the file could not be read, or a save failed:
		// those entries alone are merged in, and saved. An entry the
		// operator removed by the fix stays removed.
		for key := range k.unsavedKey {
			if r, ok := k.m[key]; ok {
				if _, inFile := fromFile[key]; !inFile {
					fromFile[key] = r
				}
			}
		}
		k.m = fromFile
		s.saveDiskKeptLocked()
		return k.m
	}
	k.m = fromFile
	return k.m
}

// markUnreadable records that the file cannot be read; mu is held.
func (k *diskKeptFiles) markUnreadable(path string, err error) {
	k.unreadable = err
	k.sig = diskKeptSig{}
	if !k.warned {
		k.warned = true
		slog.Warn("delete: the record of kept disks cannot be read; it is not written over, and the disks it names stay named "+
			"from memory. Fix the file, or remove it (the disks recorded while it cannot be read are kept and saved), so that it reads",
			"file", path, "error", err)
	}
}

// saveDiskKeptLocked writes the record file durably; mu is held. A file that
// cannot be read is never written over: the record stays in memory.
func (s *Server) saveDiskKeptLocked() {
	k := &s.diskKept
	if s.dataDir == "" {
		return
	}
	if k.unreadable != nil {
		k.unsaved = true
		return
	}
	list := make([]diskKeptRecord, 0, len(k.m))
	for _, r := range k.m {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		return diskKeptKey(list[i].Host, list[i].Path) < diskKeptKey(list[j].Host, list[j].Path)
	})
	path := filepath.Join(s.dataDir, diskKeptFile)
	raw, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeSynced(path, raw)
	}
	if err != nil {
		k.unsaved = true
		slog.Warn("delete: the record of kept disks was not saved; a restart forgets the disks not in it", "error", err)
		return
	}
	k.unsaved, k.unsavedKey = false, nil
	if fi, serr := os.Stat(path); serr == nil {
		k.sig = diskKeptSigOf(fi)
	} else {
		k.sig = diskKeptSig{}
	}
}

// recordKeptDisks records the disks the delete of vmName kept, and names
// each in an audit entry and a vm.disk_kept event.
func (s *Server) recordKeptDisks(ctx context.Context, vmName string, kept []KeptDisk) {
	if len(kept) == 0 {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	s.diskKept.mu.Lock()
	m := s.diskKeptLocked()
	for _, k := range kept {
		key := diskKeptKey(k.Host, k.Path)
		m[key] = diskKeptRecord{KeptDisk: k, VM: vmName, Since: now}
		// Merged back on a recovery if this save does not reach the file.
		if s.diskKept.unsavedKey == nil {
			s.diskKept.unsavedKey = map[string]bool{}
		}
		s.diskKept.unsavedKey[key] = true
	}
	s.saveDiskKeptLocked()
	s.diskKept.mu.Unlock()
	for _, k := range kept {
		detail := fmt.Sprintf("kept disk %s (%s on %s): %s; named by %s", k.Disk, k.Path, k.Host, k.Reason, condDiskLeftover)
		slog.Warn("delete: a VM delete kept a disk; named by "+condDiskLeftover,
			"vm", vmName, "disk", k.Disk, "path", k.Path, "host", k.Host, "reason", k.Reason)
		s.audit(ctx, "vm.delete", vmName, detail, "ok")
		s.recordVMEventSeverity(ctx, vmName, "vm.disk_kept", "ok", "warn", detail)
	}
}

// setKeptDiskHeader names the kept disks in the delete's response header.
func setKeptDiskHeader(ctx context.Context, kept []KeptDisk) {
	if len(kept) == 0 {
		return
	}
	md := metadata.MD{}
	for _, k := range kept {
		if b, err := json.Marshal(k); err == nil {
			md.Append(KeptDiskMD, string(b))
		}
	}
	_ = grpc.SetHeader(ctx, md)
}

// diskKeptRecords is the record, re-read when the file changed, and why the
// file cannot be read ("" when it can).
func (s *Server) diskKeptRecords() ([]diskKeptRecord, string) {
	s.diskKept.mu.Lock()
	defer s.diskKept.mu.Unlock()
	m := s.diskKeptLocked()
	out := make([]diskKeptRecord, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return diskKeptKey(out[i].Host, out[i].Path) < diskKeptKey(out[j].Host, out[j].Path)
	})
	unreadable := ""
	if err := s.diskKept.unreadable; err != nil {
		unreadable = err.Error()
	}
	return out, unreadable
}

// RecordKeptDiskForTest records path as disk diskName of vmName, kept on
// this host by a delete, as such a delete records it in kept-disks.json.
func (s *Server) RecordKeptDiskForTest(ctx context.Context, vmName, diskName, path string) {
	s.recordKeptDisks(ctx, vmName, []KeptDisk{{Path: path, Disk: diskName, Host: s.hostName,
		Reason: "whether the VM runs elsewhere could not be told (test)"}})
}

// JudgeKeptDisksForTest runs one judgeKeptDisks pass.
func (s *Server) JudgeKeptDisksForTest(ctx context.Context) { s.judgeKeptDisks(ctx) }

// judgeKeptDisks forgets the kept disks on this host that are gone (a
// bounded check: one that does not answer stays named), and raises
// disk_leftover for this host while any kept disk no VM's disk names is
// left, resolving it once none is.
func (s *Server) judgeKeptDisks(ctx context.Context) {
	var left []diskKeptRecord
	records, unreadable := s.diskKeptRecords()
	// While the record or a kept chain cannot be read, each import, create,
	// clone, disk attach, volume move, restore to a named target, migration
	// onto this host or failover rebuild that writes a local disk file is
	// judged by the disk files on this host
	// (keptCollisionOnDisk), and every one is held when those cannot all be
	// read either: named here, not only in each refusal. Storage that does
	// not answer is left to the conditions about it.
	createsRefused, scanErr := "", error(nil)
	if _, err := s.keptRegistryChains(ctx); err != nil && !keptRegistryTransient(err) {
		createsRefused = err.Error()
		_, scanErr = s.keptCollisionScan(ctx, nil)
	}
	for _, r := range records {
		if r.Host == s.hostName {
			if p, _ := diskPresence(s.hostDiskFile(r.Path)); p == presenceGone {
				// Under the lock, only the entry judged: one recorded for the
				// same path since (a VM of the same name) is kept.
				s.diskKept.mu.Lock()
				m := s.diskKeptLocked()
				if cur, ok := m[diskKeptKey(r.Host, r.Path)]; ok && cur == r {
					delete(m, diskKeptKey(r.Host, r.Path))
					s.saveDiskKeptLocked()
				}
				s.diskKept.mu.Unlock()
				slog.Info("delete: a disk a VM delete kept is gone", "path", r.Path)
				continue
			}
		}
		// Reattached: another VM's disk names it again. The VM whose
		// delete kept it may still name it (a delete that failed keeps the
		// record): still named. A failed read keeps it named.
		if rows, err := corrosion.DisksReferencingPath(ctx, s.db, r.Path); err == nil && slices.ContainsFunc(rows, func(d corrosion.DiskRecord) bool {
			return d.VMName != r.VM
		}) {
			continue
		}
		left = append(left, r)
	}
	subject := s.hostName
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, diskLeftoverEvaluator, condDiskLeftover, "host", subject)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if len(left) == 0 && unreadable == "" && createsRefused == "" {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("delete: resolve the kept disk condition", "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: diskLeftoverEvaluator, Code: condDiskLeftover,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	type disk struct {
		Path   string `json:"path"`
		Host   string `json:"host"`
		VM     string `json:"vm"`
		Disk   string `json:"disk"`
		Since  string `json:"since"`
		Reason string `json:"reason"`
	}
	var list []disk
	hosts := []string{s.hostName}
	seen := map[string]bool{s.hostName: true}
	for _, r := range left {
		list = append(list, disk{Path: r.Path, Host: r.Host, VM: r.VM, Disk: r.Disk, Since: r.Since, Reason: r.Reason})
		if r.Host != "" && !seen[r.Host] {
			seen[r.Host] = true
			hosts = append(hosts, r.Host)
		}
	}
	evidence := map[string]any{
		"host": s.hostName, "disks": list,
		"detail": fmt.Sprintf("%d disk file(s) VM deletes on %s kept, each with its reason; check that nothing uses each one (another VM's disk, "+
			"a process holding it open) and remove it by hand — litevirt removes none of them. A file on this host is forgotten once it is gone",
			len(list), s.hostName),
		"forget": fmt.Sprintf("to stop naming a disk you keep on purpose, or one on another host, remove its entry from %s on %s; the file is re-read within 30 s",
			filepath.Join(s.dataDir, diskKeptFile), s.hostName),
	}
	if unreadable != "" {
		evidence["record_unreadable"] = fmt.Sprintf("%s cannot be read (%s): it is not written over, and the disks named here are kept from memory; "+
			"fix the file, or remove it (the disks recorded while it cannot be read are kept and saved)", filepath.Join(s.dataDir, diskKeptFile), unreadable)
	}
	switch {
	case createsRefused != "" && scanErr != nil:
		evidence["creates_refused"] = fmt.Sprintf("%s, and %v. Until both read, these are refused on %s, whatever their names: every import; "+
			"every VM create or clone that writes a disk file on the host's own storage (one with no disk file, or with every disk "+
			"on shared nfs, ceph or iscsi storage outside the disk directory, goes ahead); every disk attach that creates a disk; "+
			"every volume move (move-volume, stack migrate-volumes) into a pool on the host's own storage; every backup restore-from or "+
			"restore-live to a --target-path; every migration onto the host that copies a host-local disk; and every failover rebuild "+
			"of a missing overlay disk there. What a kept overlay backs on is unknown, and a new disk there could become its base",
			createsRefused, scanErr, s.hostName)
	case createsRefused != "":
		evidence["creates_refused"] = fmt.Sprintf("%s. Until it reads, an import, a VM create or clone, a disk attach that creates a disk, a volume move "+
			"(move-volume, stack migrate-volumes), a backup restore-from or restore-live to a --target-path, a migration onto the host "+
			"or a failover rebuild of a missing overlay disk on %s that writes a disk file on the host's own storage is refused when a "+
			"disk file there is, or backs on, a path it writes, and so is a create that clears a file an earlier VM of its name left, or an "+
			"import onto a file already in its pool: either may be a disk a delete kept. Any other goes ahead, with a warning",
			createsRefused, s.hostName)
	}
	ev, _ := json.Marshal(evidence)
	row.Evidence = string(ev)
	row.Hosts = hosts
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("delete: raise the kept disk condition", "error", err)
	}
}
