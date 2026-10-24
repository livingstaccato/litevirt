package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// A VM delete frees each disk recorded delete_with_vm at its recorded place,
// except one another VM uses. It used to be best-effort and quiet about it:
// a disk kept because whether another VM used it could not be told, or one
// whose removal failed, was only logged, and `lv rm` printed "deleted" with
// the file still there (lab 2 F-5). Now:
//   - a disk the delete must not remove — whether another VM uses it cannot
//     be told, or (with no domain anywhere) it is not provably this host's
//     to free — is kept, the delete goes on, and the disk is named
//     (disk_kept.go: the response, an audit entry and event, disk_leftover);
//   - a disk whose removal failed fails the delete before the record goes,
//     and is named by disk_leftover too: the record is the cluster's handle
//     on it, and a retry, which finds no domain, frees it or names it.
// A disk kept on purpose (delete_with_vm=false, another VM uses it) and a
// ceph image a client still has open (named, as before) do not fail it.

// deleteProbeRefusedMD is the trailer a peer's local-only delete probe
// (deleteLocalOnly) sets when it found the VM's domain and refused to delete
// it, with the refusal's own code: the probing host then keeps the record.
const deleteProbeRefusedMD = "x-litevirt-delete-probe-refused"

// probeNoAnswer is a local-only probe's answer that it cannot tell whether
// it has the VM's domain: never marked a refusal, so the probing host counts
// it as no answer.
type probeNoAnswer struct{ error }

// GRPCStatus is the wrapped error's status.
func (e probeNoAnswer) GRPCStatus() *status.Status { return status.Convert(e.error) }

// diskLeftover is a recorded disk a VM delete set out to free and did not.
type diskLeftover struct {
	disk, path string
	// target is what is left on this host: the disk file, or for a btrfs
	// disk whose driver failed, its subvolume; named is the same, as the
	// records name it (target is it under hostDiskFile).
	target, named string
	err           error
}

// diskDecision is whether a caller lets freeRecordedVMDisks free d, and if
// not, why it is kept and on which host it lies.
type diskDecision func(d *corrosion.DiskRecord) (free bool, why, host string)

// freeRecordedVMDisks frees vmName's recorded disks the delete may free, as
// deleteRecordedVMDiskVolumes does. It returns the ceph images left in their
// pool (in use: named, as before), the disks it kept on purpose for the
// caller to name (decide said no, or whether another VM uses one cannot be
// told), and every disk it set out to free that it did not (a failed
// removal, a file still there afterwards, or one a kept disk holds).
func (s *Server) freeRecordedVMDisks(ctx context.Context, vmName string, decide diskDecision) ([]KeptCephImage, []KeptDisk, []diskLeftover) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, nil, []diskLeftover{{err: fmt.Errorf("list its disks: %w", err)}}
	}
	var kept []KeptDisk
	var cephKeptHere []KeptCephImage
	var leftovers []diskLeftover
	errs := make([]error, len(disks))
	tried := make([]bool, len(disks))
	var wg sync.WaitGroup
	for i := range disks {
		d := &disks[i]
		if d.Path == "" || !d.DeleteWithVM {
			continue
		}
		// keep names a disk kept: a ceph image by ceph_image_leftover,
		// which rechecks its pool, any other by disk_leftover.
		keep := func(host, why string) {
			if strings.HasPrefix(d.Path, "rbd:") {
				if k, ok := s.recordKeptCephImage(vmName, d, errors.New(why)); ok {
					cephKeptHere = append(cephKeptHere, k)
					return
				}
			}
			kept = append(kept, KeptDisk{Path: d.Path, Disk: d.DiskName, Host: host, Reason: why})
		}
		if decide != nil {
			if free, why, host := decide(d); !free {
				keep(host, why)
				continue
			}
		}
		used, uerr := s.diskUsedByOtherVM(ctx, vmName, d)
		if uerr != nil {
			// Never removed on a guess, never left unnamed.
			keep(s.hostName, "whether another VM uses it cannot be told ("+uerr.Error()+")")
			continue
		}
		if used {
			continue
		}
		tried[i] = true
		del := func() { errs[i] = s.deleteDiskAtRecordedLocation(ctx, d) }
		// The rbd disks are deleted together (deleteRecordedVMDiskVolumeRecords).
		if strings.HasPrefix(d.Path, "rbd:") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				del()
			}()
			continue
		}
		del()
	}
	wg.Wait()
	cephKept := append(cephKeptHere, s.keptFromErrs(vmName, disks, errs)...)
	cephNamed := map[string]bool{}
	for _, k := range cephKept {
		cephNamed[k.Disk] = true
	}
	for i := range disks {
		d := &disks[i]
		if !tried[i] {
			continue
		}
		file := s.hostDiskFile(d.Path)
		if err := errs[i]; isDiskHeld(err) {
			// Never removed: the hold, not a removal, is why it is there.
			leftovers = append(leftovers, diskLeftover{disk: d.DiskName, path: d.Path, target: file, named: d.Path, err: err})
			continue
		} else if err != nil {
			if !cephNamed[d.DiskName] {
				named := d.Path
				if s.diskDriverName(d) == "btrfs" {
					// The file may be gone and its subvolume not: what is
					// left is the subvolume (I-2).
					named = filepath.Dir(d.Path)
				}
				leftovers = append(leftovers, diskLeftover{disk: d.DiskName, path: d.Path, target: s.hostDiskFile(named), named: named, err: err})
			}
			continue
		}
		if there, err := diskFileThere(file); err != nil || there {
			if err == nil {
				err = errors.New("its file is still there after its removal")
			}
			leftovers = append(leftovers, diskLeftover{disk: d.DiskName, path: d.Path, target: file, named: d.Path, err: err})
		}
	}
	return cephKept, kept, leftovers
}

// diskDriverName is the storage driver d is freed through (diskDriver).
func (s *Server) diskDriverName(d *corrosion.DiskRecord) string {
	if pool, ok := s.lookupStoragePool(d.StorageVolume); ok && pool.Driver != "" {
		return strings.ToLower(pool.Driver)
	}
	return strings.ToLower(d.StorageType)
}

// diskSharedOrUnknown is why d may be on storage other hosts share ("" when
// it is provably not): its storage type, or its pool's driver on its own host
// or this one. A pool that cannot be read is not known to be local.
func (s *Server) diskSharedOrUnknown(ctx context.Context, d *corrosion.DiskRecord) string {
	if corrosion.DiskIsShared(*d) {
		return fmt.Sprintf("it is on shared storage (%s), which other hosts may use", d.StorageType)
	}
	if d.StorageVolume == "" {
		return ""
	}
	seen := map[string]bool{}
	for _, h := range []string{d.HostName, s.hostName} {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		p, ok, err := corrosion.GetStoragePool(ctx, s.db, h, d.StorageVolume)
		if err != nil {
			return fmt.Sprintf("whether its pool %s is shared storage cannot be read (%v)", d.StorageVolume, err)
		}
		if ok && corrosion.DiskIsShared(corrosion.DiskRecord{StorageType: p.Driver}) {
			return fmt.Sprintf("it is in pool %s on shared storage (%s), which other hosts may use", d.StorageVolume, p.Driver)
		}
	}
	return ""
}

// stillLeft is leftovers less each one whose target is positively gone by
// now: the debris sweep after the recorded pass takes a file in
// <data_dir>/disks by its name, and nothing is left behind of it. A target
// that cannot be judged here (an rbd locator, storage that does not answer)
// stays.
func stillLeft(leftovers []diskLeftover) []diskLeftover {
	var out []diskLeftover
	for _, l := range leftovers {
		if l.target != "" {
			if p, _ := diskPresence(l.target); p == presenceGone {
				continue
			}
		}
		out = append(out, l)
	}
	return out
}

// keptThere is kept less each disk on this host that is positively not there
// at all: nothing is left of it to name. One that cannot be judged here is
// named.
func (s *Server) keptThere(kept []KeptDisk) []KeptDisk {
	var out []KeptDisk
	for _, k := range kept {
		if k.Host == s.hostName {
			if p, _ := diskPresence(s.hostDiskFile(k.Path)); p == presenceGone {
				continue
			}
		}
		out = append(out, k)
	}
	return out
}

// presence is whether a disk is still there, as this host can judge it.
type presence int

const (
	presenceUnknown presence = iota // cannot be judged here
	presenceGone                    // positively gone
	presenceThere
)

// diskPresence judges whether the disk at path is still there: a file, or a
// block device's node or link under /dev (gone with its volume), by a
// bounded Lstat. A locator that is no path (rbd:...) cannot be judged here,
// nor can a path whose storage does not answer: only a positive "gone" ever
// drops a disk from what is named.
func diskPresence(path string) (presence, error) {
	if !filepath.IsAbs(path) {
		return presenceUnknown, nil
	}
	there, err := storage.Bounded("stat", path, func() (bool, error) {
		_, err := os.Lstat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	})
	switch {
	case err != nil:
		return presenceUnknown, err
	case there:
		return presenceThere, nil
	}
	return presenceGone, nil
}

// leftoversKept is the leftovers as kept disks, for disk_leftover to name
// until a retry frees them.
func (s *Server) leftoversKept(leftovers []diskLeftover) []KeptDisk {
	var out []KeptDisk
	for _, l := range leftovers {
		if l.disk == "" {
			continue
		}
		path := l.named
		if path == "" {
			path = l.path
		}
		why := "its removal failed: " + l.err.Error()
		if isDiskHeld(l.err) {
			why = "it is " + l.err.Error()
		}
		out = append(out, KeptDisk{Path: path, Disk: l.disk, Host: s.hostName, Reason: why})
	}
	return out
}

// diskFileThere reports whether the file (or directory) at path is still
// there after its driver reported it removed. A path that is not a file (an
// rbd locator, a block device — an iSCSI LUN's node stays by design) is never
// "there" here: its driver's answer is the truth. Bounded: storage that does
// not answer is an error, never "gone". Only this post-removal check uses it;
// what is named is judged by diskPresence.
func diskFileThere(path string) (bool, error) {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, "/dev/") {
		return false, nil
	}
	return storage.Bounded("stat", path, func() (bool, error) {
		_, err := os.Lstat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	})
}

// diskLeftoversError is the delete's failure for the disks it did not free:
// Unavailable when storage did not answer, else Internal.
func diskLeftoversError(vmName string, leftovers []diskLeftover) error {
	code := codes.Internal
	var parts []string
	for _, l := range leftovers {
		if storage.IsFSNoAnswer(l.err) {
			code = codes.Unavailable
		}
		if l.disk == "" {
			parts = append(parts, l.err.Error())
			continue
		}
		parts = append(parts, fmt.Sprintf("disk %s (%s): %v", l.disk, l.target, l.err))
	}
	return status.Errorf(code,
		"cannot delete VM %q: its domain is gone but not every disk was removed — %s. "+
			"Its record is kept and each disk is named by the health condition %s; a retry of the delete "+
			"removes what it can and names what it cannot, and `lv rm --keep-disks %s` completes the delete "+
			"leaving those disks to be removed by hand",
		vmName, strings.Join(parts, "; "), condDiskLeftover, vmName)
}
