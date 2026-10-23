package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/storage"
)

// tombstoneDeletedVM writes a delete's tombstone. Before it, the disks this
// delete keeps are recorded where a later create of the name looks for them,
// so it moves them to <path>.kept-<time> rather than clear them
// (health.SetAsideBeforeCreate):
//
//   - this host notes its own host-local files of the VM that stay: every one
//     after --keep-disks, and one recorded delete_with_vm=false
//     (health.NoteKeptDisks);
//   - every open vm_disk_stranded record of the VM is told whether this
//     delete keeps its disks (health.MarkStrandedForDelete), so a failover's
//     old host holding one at its path leaves it there after --keep-disks.
//
// A --keep-disks delete is refused when either cannot be written: the disk
// would otherwise be cleared by a create, or set aside for the retention,
// which removes it. Nothing has been tombstoned then; retrying is safe.
func (s *Server) tombstoneDeletedVM(ctx context.Context, name string, keepDisks bool) (*corrosion.VMRecord, error) {
	err := s.noteKeptDisks(ctx, name, keepDisks)
	if err == nil {
		err = health.MarkStrandedForDelete(ctx, s.db, s.hostName, name, keepDisks, time.Now())
	}
	if err != nil {
		if keepDisks {
			var ne *health.KeptDisksNoteError
			if errors.As(err, &ne) {
				return nil, fmt.Errorf("record that --keep-disks keeps the disks of %s: this host's note of the disks deletes kept, %s, "+
					"cannot be read (%v); repair or remove that file, then retry; nothing was tombstoned", name, ne.File, ne.Err)
			}
			return nil, fmt.Errorf("record that --keep-disks keeps the disks of %s: %w; nothing was tombstoned, retry", name, err)
		}
		slog.Warn("delete: could not record the disks this delete keeps; a create of the name may clear one recorded delete_with_vm=false",
			"vm", name, "error", err)
	}
	return corrosion.DeleteVMReporting(ctx, s.db, name)
}

// noteKeptDisks notes, on this host, the host-local files of name's disks
// recorded here that the delete leaves: every one with keepDisks, and one
// recorded delete_with_vm=false. The files of such a disk's backing chain
// that a create of the name clears (<vm>-<disk>.qcow2) are noted as files a
// kept disk backs on, which a create refuses to move or clear
// (health.SetAsideBeforeCreate). The tops are noted even when a chain cannot
// be read, and that is the error returned.
func (s *Server) noteKeptDisks(ctx context.Context, name string, keepDisks bool) error {
	disks, err := corrosion.GetVMDisks(ctx, s.db, name)
	if err != nil {
		return err
	}
	var paths []string
	for _, d := range disks {
		if d.Path == "" || d.HostName != s.hostName || corrosion.DiskIsShared(d) || strings.HasPrefix(d.Path, "rbd:") {
			continue
		}
		if keepDisks || !d.DeleteWithVM {
			paths = append(paths, s.hostDiskFile(d.Path))
		}
	}
	if err := health.NoteKeptDisks(s.dataDir, name, paths); err != nil {
		return err
	}
	return s.noteKeptBackingFiles(ctx, name, keepDisks)
}

func (s *Server) noteKeptBackingFiles(ctx context.Context, name string, keepDisks bool) error {
	if s.images == nil {
		return nil
	}
	_, chains, err := s.keptDiskChains(ctx, name, keepDisks)
	if err != nil {
		return fmt.Errorf("the files a disk it keeps backs on cannot be noted: %w", err)
	}
	taken, err := s.vmDiskCandidateSet(name)
	if err != nil {
		return fmt.Errorf("the files a disk it keeps backs on cannot be noted: %w", err)
	}
	var under []string
	for _, layers := range chains {
		for _, l := range layers[min(1, len(layers)):] {
			if taken[l] {
				under = append(under, l)
			}
		}
	}
	return health.NoteKeptBackingFiles(s.dataDir, name, under)
}

// noteDeleteKeptDisks notes, on this host, the disk files a delete of name
// kept here because it could not prove them unused (KeptDisk, disk_kept.go):
// the stale-record delete keeps every disk while a host did not answer
// whether the VM runs there. Each kept file is noted as a kept disk, and
// every file of its backing chain below it, other than an image in the
// store, as a file a kept disk backs on, as `lv rm --keep-disks` notes them
// (noteKeptDisks). With kept-disks.json alone naming the top of the chain, a
// create of the name cleared the base under it and wrote its own disk there
// (rc3 lab 2, F1). Every chain is read before anything is noted: one that
// cannot be read is the error returned, with nothing noted, and the caller
// then keeps the record, so the name stays taken and a retry that frees the
// disks leaves no note behind. Only a disk on this host's own storage is noted: a note is
// this host's, and a shared disk is no file a create here clears.
func (s *Server) noteDeleteKeptDisks(ctx context.Context, name string, kept []KeptDisk) error {
	if len(kept) == 0 {
		return nil
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, name)
	if err != nil {
		return &diskRecordsReadError{err}
	}
	keptPath := map[string]bool{}
	for _, k := range kept {
		if k.Host == s.hostName {
			keptPath[k.Path] = true
		}
	}
	var tops []string
	for _, d := range disks {
		if !keptPath[d.Path] || d.HostName != s.hostName || corrosion.DiskIsShared(d) || strings.HasPrefix(d.Path, "rbd:") ||
			(d.StorageType != "" && !isHostLocalDiskDriver(d.StorageType)) {
			continue
		}
		if top := filepath.Clean(s.hostDiskFile(d.Path)); filepath.IsAbs(top) {
			tops = append(tops, top)
		}
	}
	if len(tops) == 0 {
		return nil
	}
	imageDir := ""
	if s.images != nil {
		imageDir = filepath.Clean(s.images.ImageDir())
	}
	var under []string
	for _, top := range tops {
		layers, err := storage.Bounded("read the backing chain of", top, func() ([]string, error) {
			return keptChainLayers(top)
		})
		if err != nil {
			return fmt.Errorf("the backing chain of the disk %s it keeps cannot be read, so the files under it cannot be noted (%w)", top, err)
		}
		for _, l := range layers[min(1, len(layers)):] {
			if imageDir != "" && filepath.Dir(l) == imageDir {
				continue // an image in the store: the store's, not the VM's
			}
			under = append(under, l)
		}
	}
	if err := health.NoteKeptDisks(s.dataDir, name, tops); err != nil {
		return err
	}
	return health.NoteKeptBackingFiles(s.dataDir, name, under)
}

// clearDiskDebrisBeforeCreate is createVM's debris sweep: it removes the
// <vm>-*.qcow2 files an earlier VM of the name left, as sweepVMDiskDebris
// does, from one candidate list and one keep set. Before that, a file the
// sweep would remove that the deleted VM was kept with is moved to
// <path>.kept-<time>, and the real disk a failover left here to
// <path>.superseded-<time> (health.SetAsideBeforeCreate); each move is a VM
// event of the name, as is each path of the deleted VM's disks that reads as
// missing on what may be a volume not mounted yet. An error refuses the
// create: nothing was removed. The files it moved are returned, with an error
// too, so a create that fails puts the kept ones back
// (restoreKeptAfterFailedCreate).
//
// writes is what the create writes (createKeptWrites): a kept overlay
// missing its base at one of those paths refuses it, and one that writes
// nothing on this host's own storage is not held while what kept overlays
// back on cannot be read.
//
// A candidate list that cannot be read refuses the create: without it
// neither the sweep nor the kept-disk checks on it can run, and a create
// that went ahead could write the base a kept overlay is missing.
func (s *Server) clearDiskDebrisBeforeCreate(ctx context.Context, name string, now time.Time, writes *keptWrites) ([]health.MovedBeforeCreate, error) {
	candidates, err := s.images.VMDiskCandidates(name)
	if err != nil {
		return nil, fmt.Errorf("the files an earlier VM %s left in %s cannot be listed (%v), so what the create would clear, and "+
			"whether a disk a delete kept backs on them, cannot be told; nothing was created. Fix that directory or its storage, "+
			"or place the VM on another host", name, s.images.DiskDir(name), err)
	}
	keep := s.protectedDiskPathsFrom(ctx, name, candidates)
	var unlink []string
	for _, c := range candidates {
		if !keep[c] {
			unlink = append(unlink, c)
		}
	}
	// Nothing a delete kept, and nothing a file beside it backs on, is
	// cleared: the kept-disk notes govern what they name (below), and this
	// covers what they do not.
	if err := s.keptFileCreateRefusal(ctx, name, unlink, writes, true); err != nil {
		return nil, err
	}
	trusted := func() (bool, string) {
		return corrosion.ReplicaTrusted(ctx, s.db, s.hostName, s.db.ReplicaCaughtUp)
	}
	done, err := health.SetAsideBeforeCreate(ctx, s.db, s.dataDir, s.hostName, name, unlink, s.hostDiskFile, trusted, now)
	event := func(typ, sev, detail string) {
		if eerr := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{
			ID: randid.New(), VMName: name, HostName: s.hostName, Type: typ,
			Result: "ok", Severity: sev, Detail: detail, Username: "create",
		}); eerr != nil {
			slog.Warn("create: record the event", "vm", name, "type", typ, "error", eerr)
		}
	}
	for _, p := range done.MayBeUnmounted {
		event("vm.disk.path_missing", "warn", fmt.Sprintf("the disk of the deleted VM %s at %s on %s reads as missing, and its directory is absent, "+
			"empty or cannot be listed, as a volume not mounted yet reads; the create of %s goes ahead, and vm_disk_stranded stays open. "+
			"If that directory is a mount point, a volume mounted there later hides what the create writes in it", name, p, s.hostName, name))
	}
	for _, m := range done.Moved {
		detail := fmt.Sprintf("a disk the deleted VM %s was kept with was at %s, which the create of %s on %s clears; it is moved to %s, and only an operator removes it",
			name, m.Path, name, s.hostName, m.To)
		typ, sev := "vm.disk.kept", "info"
		if !m.Kept {
			detail = fmt.Sprintf("the real disk of the deleted VM %s a failover left at %s on %s is set aside as %s before the create of %s; it follows the retention for a deleted VM's copies",
				name, m.Path, s.hostName, m.To, name)
			typ, sev = "vm.disk.set_aside", "warn"
		}
		event(typ, sev, detail)
	}
	if err != nil {
		return done.Moved, err
	}
	if err := s.images.DeleteVMDisksIn(name, candidates, keep); err != nil {
		slog.Warn("create: disk debris sweep failed", "vm", name, "error", err)
	}
	return done.Moved, nil
}
