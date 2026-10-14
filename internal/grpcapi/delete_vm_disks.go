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
// a disk kept because whether another VM used it could not be told (a record
// read that failed, another VM's disk on storage that did not answer), or one
// whose removal failed, was only logged, and `lv rm` printed "deleted" with
// the file still there (lab 2 F-5). So:
//   - before anything is torn down, a disk whose use cannot be told refuses
//     the delete, with nothing changed (preflightDiskRemoval);
//   - after the teardown, a disk that is still there fails the delete before
//     the record goes (freeRecordedVMDisks, diskLeftoversError): the record
//     is the cluster's only handle on the disk, and a retry — which finds no
//     domain — frees it (deleteVM's stale-record path).
// A disk kept on purpose (delete_with_vm=false, another VM uses it) and a
// ceph image a client still has open (named in the response, as on main) do
// not fail it.

// diskLeftover is a recorded disk a VM delete set out to free and did not.
type diskLeftover struct {
	disk, path string
	file       string // the path on this host (hostDiskFile)
	err        error
}

// preflightDiskRemoval refuses the delete of vmName, before anything is torn
// down, when whether one of its disks is used by another VM cannot be told:
// the delete would keep that disk and report the VM deleted.
func (s *Server) preflightDiskRemoval(ctx context.Context, vmName string) error {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return status.Errorf(codes.Internal,
			"cannot delete VM %q: its disks cannot be listed (%v); nothing was changed, and the delete can be retried", vmName, err)
	}
	for i := range disks {
		d := &disks[i]
		if d.Path == "" || !d.DeleteWithVM {
			continue
		}
		if _, err := s.diskUsedByOtherVM(ctx, vmName, d); err != nil {
			return status.Errorf(snapshotFileUsersCode(err),
				"cannot delete VM %q: whether its disk %s (%s) is used by another VM cannot be told: %v; nothing was changed. "+
					"Retry once it can be read, or delete the VM with --keep-disks and remove the disk by hand",
				vmName, d.DiskName, d.Path, err)
		}
	}
	return nil
}

// freeRecordedVMDisks frees vmName's recorded disks the delete may free, as
// deleteRecordedVMDiskVolumes does, and returns the ceph images left in their
// pool (in use: named, as on main) and every other disk it set out to free
// that it did not: one whose use could not be told, one whose removal failed,
// and a disk file still there afterwards. only, when set, limits it to the
// disks it accepts.
func (s *Server) freeRecordedVMDisks(ctx context.Context, vmName string, only func(*corrosion.DiskRecord) bool) ([]KeptCephImage, []diskLeftover) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return nil, []diskLeftover{{err: fmt.Errorf("list its disks: %w", err)}}
	}
	var leftovers []diskLeftover
	errs := make([]error, len(disks))
	tried := make([]bool, len(disks))
	var wg sync.WaitGroup
	for i := range disks {
		d := &disks[i]
		if d.Path == "" || !d.DeleteWithVM || (only != nil && !only(d)) {
			continue
		}
		used, uerr := s.diskUsedByOtherVM(ctx, vmName, d)
		if uerr != nil {
			leftovers = append(leftovers, diskLeftover{disk: d.DiskName, path: d.Path, file: s.hostDiskFile(d.Path), err: uerr})
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
	kept := s.keptFromErrs(vmName, disks, errs)
	named := map[string]bool{}
	for _, k := range kept {
		named[k.Disk] = true
	}
	for i := range disks {
		d := &disks[i]
		if !tried[i] {
			continue
		}
		if err := errs[i]; err != nil {
			if !named[d.DiskName] {
				leftovers = append(leftovers, diskLeftover{disk: d.DiskName, path: d.Path, file: s.hostDiskFile(d.Path), err: err})
			}
			continue
		}
		if there, err := diskFileThere(s.hostDiskFile(d.Path)); err != nil || there {
			if err == nil {
				err = errors.New("its file is still there after its removal")
			}
			leftovers = append(leftovers, diskLeftover{disk: d.DiskName, path: d.Path, file: s.hostDiskFile(d.Path), err: err})
		}
	}
	return kept, leftovers
}

// stillLeft is leftovers less each disk file that is gone by now: the
// debris sweep after the recorded pass takes a file in <data_dir>/disks by
// its name, and nothing is left behind of it.
func stillLeft(leftovers []diskLeftover) []diskLeftover {
	var out []diskLeftover
	for _, l := range leftovers {
		if l.file != "" && filepath.IsAbs(l.file) && !strings.HasPrefix(l.file, "/dev/") {
			if there, err := diskFileThere(l.file); err == nil && !there {
				continue
			}
		}
		out = append(out, l)
	}
	return out
}

// diskFileThere reports whether the disk file at path is still there. A path
// that is not a file (an rbd locator, a block device a driver freed) is never
// "there": its driver's answer is the truth. Bounded: storage that does not
// answer is an error, never "gone".
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
		parts = append(parts, fmt.Sprintf("disk %s (%s): %v", l.disk, l.path, l.err))
	}
	return status.Errorf(code,
		"cannot delete VM %q: its domain is gone but not every disk was removed — %s. "+
			"Its record is kept so nothing is lost track of; retrying the delete removes the disks once that succeeds",
		vmName, strings.Join(parts, "; "))
}

// probeRefusal is err as a peer's local-only probe (deleteLocalOnly) returns
// it: FailedPrecondition, which the probing host reads as "this host has the
// domain and refused its delete" and passes on, keeping the record, where any
// other failure lets it clean the record up as stale.
func probeRefusal(localOnly bool, err error) error {
	if !localOnly {
		return err
	}
	return status.Error(codes.FailedPrecondition, status.Convert(err).Message())
}
