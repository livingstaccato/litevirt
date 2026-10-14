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
	// disk whose driver failed, its subvolume.
	target string
	err    error
}

// diskDecision is whether a caller lets freeRecordedVMDisks free d, and if
// not, why it is kept and on which host it lies.
type diskDecision func(d *corrosion.DiskRecord) (free bool, why, host string)

// freeRecordedVMDisks frees vmName's recorded disks the delete may free, as
// deleteRecordedVMDiskVolumes does. It returns the ceph images left in their
// pool (in use: named, as before), the disks it kept on purpose for the
// caller to name (decide said no, or whether another VM uses one cannot be
// told), and every disk it set out to free that it did not (a failed
// removal, or a file still there afterwards).
func (s *Server) freeRecordedVMDisks(ctx context.Context, vmName string, decide diskDecision) ([]KeptCephImage, []KeptDisk, []diskLeftover) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, nil, []diskLeftover{{err: fmt.Errorf("list its disks: %w", err)}}
	}
	var kept []KeptDisk
	var leftovers []diskLeftover
	errs := make([]error, len(disks))
	tried := make([]bool, len(disks))
	var wg sync.WaitGroup
	for i := range disks {
		d := &disks[i]
		if d.Path == "" || !d.DeleteWithVM {
			continue
		}
		if decide != nil {
			if free, why, host := decide(d); !free {
				kept = append(kept, KeptDisk{Path: d.Path, Disk: d.DiskName, Host: host, Reason: why})
				continue
			}
		}
		used, uerr := s.diskUsedByOtherVM(ctx, vmName, d)
		if uerr != nil {
			// Never removed on a guess, never left unnamed.
			kept = append(kept, KeptDisk{Path: d.Path, Disk: d.DiskName, Host: s.hostName,
				Reason: "whether another VM uses it cannot be told (" + uerr.Error() + ")"})
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
	cephKept := s.keptFromErrs(vmName, disks, errs)
	named := map[string]bool{}
	for _, k := range cephKept {
		named[k.Disk] = true
	}
	for i := range disks {
		d := &disks[i]
		if !tried[i] {
			continue
		}
		file := s.hostDiskFile(d.Path)
		if err := errs[i]; err != nil {
			if !named[d.DiskName] {
				target := file
				if s.diskDriverName(d) == "btrfs" {
					// The file may be gone and its subvolume not: what is
					// left is the subvolume (I-2).
					target = filepath.Dir(file)
				}
				leftovers = append(leftovers, diskLeftover{disk: d.DiskName, path: d.Path, target: target, err: err})
			}
			continue
		}
		if there, err := diskFileThere(file); err != nil || there {
			if err == nil {
				err = errors.New("its file is still there after its removal")
			}
			leftovers = append(leftovers, diskLeftover{disk: d.DiskName, path: d.Path, target: file, err: err})
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

// stillLeft is leftovers less each one whose target is gone by now: the
// debris sweep after the recorded pass takes a file in <data_dir>/disks by
// its name, and nothing is left behind of it. A target that is not the file
// itself (a btrfs disk's subvolume) is dropped only when it is gone.
func stillLeft(leftovers []diskLeftover) []diskLeftover {
	var out []diskLeftover
	for _, l := range leftovers {
		if l.target != "" {
			if there, err := diskFileThere(l.target); err == nil && !there {
				continue
			}
		}
		out = append(out, l)
	}
	return out
}

// keptThere is kept less each disk on this host that is not there at all:
// nothing is left of it to name.
func (s *Server) keptThere(kept []KeptDisk) []KeptDisk {
	var out []KeptDisk
	for _, k := range kept {
		if k.Host == s.hostName {
			if there, err := diskFileThere(s.hostDiskFile(k.Path)); err == nil && !there {
				continue
			}
		}
		out = append(out, k)
	}
	return out
}

// leftoversKept is the leftovers as kept disks, for disk_leftover to name
// until a retry frees them.
func (s *Server) leftoversKept(leftovers []diskLeftover) []KeptDisk {
	var out []KeptDisk
	for _, l := range leftovers {
		if l.disk == "" {
			continue
		}
		path := l.target
		if path == "" {
			path = l.path
		}
		out = append(out, KeptDisk{Path: path, Disk: l.disk, Host: s.hostName, Reason: "its removal failed: " + l.err.Error()})
	}
	return out
}

// diskFileThere reports whether the file (or directory) at path is still
// there. A path that is not a file (an rbd locator, a block device a driver
// freed) is never "there": its driver's answer is the truth. Bounded: storage
// that does not answer is an error, never "gone".
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
			"removes what it can and names what it cannot",
		vmName, strings.Join(parts, "; "), condDiskLeftover)
}
