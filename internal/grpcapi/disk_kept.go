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
	mu     sync.Mutex
	loaded bool
	m      map[string]diskKeptRecord // host + "\x00" + path → record
}

func diskKeptKey(host, path string) string { return host + "\x00" + path }

// diskKeptLocked loads the record file once; mu is held.
func (s *Server) diskKeptLocked() map[string]diskKeptRecord {
	k := &s.diskKept
	if !k.loaded {
		k.loaded, k.m = true, map[string]diskKeptRecord{}
		if s.dataDir != "" {
			raw, err := os.ReadFile(filepath.Join(s.dataDir, diskKeptFile))
			switch {
			case err == nil:
				var list []diskKeptRecord
				if jerr := json.Unmarshal(raw, &list); jerr != nil {
					slog.Warn("delete: the record of kept disks cannot be read", "file", diskKeptFile, "error", jerr)
				}
				for _, r := range list {
					if r.Path != "" {
						k.m[diskKeptKey(r.Host, r.Path)] = r
					}
				}
			case !errors.Is(err, os.ErrNotExist):
				slog.Warn("delete: the record of kept disks cannot be read", "file", diskKeptFile, "error", err)
			}
		}
	}
	return k.m
}

// saveDiskKeptLocked writes the record file durably; mu is held.
func (s *Server) saveDiskKeptLocked() {
	if s.dataDir == "" {
		return
	}
	list := make([]diskKeptRecord, 0, len(s.diskKept.m))
	for _, r := range s.diskKept.m {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		return diskKeptKey(list[i].Host, list[i].Path) < diskKeptKey(list[j].Host, list[j].Path)
	})
	raw, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeSynced(filepath.Join(s.dataDir, diskKeptFile), raw)
	}
	if err != nil {
		slog.Warn("delete: the record of kept disks was not saved; a restart forgets them", "error", err)
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
		m[diskKeptKey(k.Host, k.Path)] = diskKeptRecord{KeptDisk: k, VM: vmName, Since: now}
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

func (s *Server) diskKeptRecords() []diskKeptRecord {
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
	return out
}

// judgeKeptDisks forgets the kept disks on this host that are gone (a
// bounded check: one that does not answer stays named), and raises
// disk_leftover for this host while any kept disk no VM's disk names is
// left, resolving it once none is.
func (s *Server) judgeKeptDisks(ctx context.Context) {
	var left []diskKeptRecord
	for _, r := range s.diskKeptRecords() {
		if r.Host == s.hostName {
			if there, err := diskFileThere(s.hostDiskFile(r.Path)); err == nil && !there {
				s.diskKept.mu.Lock()
				delete(s.diskKeptLocked(), diskKeptKey(r.Host, r.Path))
				s.saveDiskKeptLocked()
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
	if len(left) == 0 {
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
	ev, _ := json.Marshal(map[string]any{
		"host": s.hostName, "disks": list,
		"detail": fmt.Sprintf("%d disk file(s) VM deletes on %s kept, each with its reason; check that nothing uses each one (another VM's disk, "+
			"a process holding it open) and remove it by hand — litevirt removes none of them. A file on this host is forgotten once it is gone",
			len(list), s.hostName),
	})
	row.Evidence = string(ev)
	row.Hosts = hosts
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("delete: raise the kept disk condition", "error", err)
	}
}
