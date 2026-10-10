package grpcapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// A root disk from an image on an iscsi pool.
//
// The iscsi driver allocates nothing: the disk is the pool's LUN, as it is.
// For a root disk built on an image that used to mean a blank LUN — the guest
// booted to the firmware shell while the VM reported running. So the create
// writes the image's guest contents onto the LUN (qemu-img convert to the
// block device) before the domain is defined, after three checks:
//
//   - no VM's disk is the LUN: claimLUNs has already refused one that is, and
//     holds the LUN for this create while it writes;
//   - the LUN is at least the image's virtual size, or the create is refused
//     with both sizes;
//   - the LUN is blank — zeros in its first and last MiB, where a partition
//     table (MBR, GPT and its backup), an LVM label or a filesystem superblock
//     sit — or the disk says overwrite. A LUN holding data is never written
//     without it.
//
// The requested size of the disk is not applied: the LUN is the size the SAN
// gave it.

// lunProbeBytes is how much of each end of a LUN must be zero for it to count
// as blank.
const lunProbeBytes = 1 << 20

// openLUNDevice opens a LUN's block device to read its size and first and
// last bytes. Tests point it at a file.
var openLUNDevice = func(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// writeImageToDevice writes a qcow2 image's guest contents onto a block
// device, in place (-n: the device exists and is not created). Tests replace
// it.
var writeImageToDevice = func(ctx context.Context, image, device string) error {
	out, err := exec.CommandContext(ctx, "qemu-img", "convert", "-n", "-f", "qcow2", "-O", "raw", "--", image, device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img convert %s onto %s: %w: %s", image, device, err, out)
	}
	return nil
}

// writeImageOntoLUN makes disk of vm, LUN device, the image at imagePath —
// or refuses, writing nothing.
func (s *Server) writeImageOntoLUN(ctx context.Context, vm, disk, image, imagePath, device string, overwrite bool) error {
	info, err := qcow2.Info(imagePath)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "image %q: %v", image, err)
	}
	f, err := openLUNDevice(device)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"root disk %q of VM %q: open iSCSI LUN %s to write image %q onto it: %v", disk, vm, device, image, err)
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err == nil && size <= 0 {
		err = fmt.Errorf("it reports no size")
	}
	if err != nil {
		f.Close()
		return status.Errorf(codes.FailedPrecondition, "root disk %q of VM %q: size of iSCSI LUN %s: %v", disk, vm, device, err)
	}
	if uint64(size) < info.VirtualSize {
		f.Close()
		return status.Errorf(codes.FailedPrecondition,
			"root disk %q of VM %q: iSCSI LUN %s is %d bytes, smaller than image %q (%d bytes) — give the disk a "+
				"pool on a LUN of at least the image's size", disk, vm, device, size, image, info.VirtualSize)
	}
	blank, err := lunBlank(f, size)
	f.Close()
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "root disk %q of VM %q: read iSCSI LUN %s: %v", disk, vm, device, err)
	}
	if !blank {
		if !overwrite {
			return status.Errorf(codes.FailedPrecondition,
				"root disk %q of VM %q: iSCSI LUN %s is not blank (its first or last MiB holds data: a partition "+
					"table, a filesystem, an earlier disk), and writing image %q would destroy it — if its contents "+
					"are disposable, set overwrite on the disk (compose `overwrite: true`, `lv run --overwrite`)",
				disk, vm, device, image)
		}
		slog.Warn("iSCSI root disk: writing the image over a LUN that holds data, as the disk's overwrite asks",
			"vm", vm, "disk", disk, "lun", device, "image", image)
		s.audit(ctx, "vm.create", vm, fmt.Sprintf("image %s written over non-blank iSCSI LUN %s (overwrite)", image, device), "overwrite")
	}
	if err := writeImageToDevice(ctx, imagePath, device); err != nil {
		return status.Errorf(codes.Internal, "root disk %q of VM %q: write image %q onto iSCSI LUN %s: %v",
			disk, vm, image, device, err)
	}
	slog.Info("iSCSI root disk: image written onto the LUN", "vm", vm, "disk", disk, "lun", device, "image", image)
	return nil
}

// lunBlank reports whether the first and last lunProbeBytes of a size-byte
// device are all zeros.
func lunBlank(r io.ReaderAt, size int64) (bool, error) {
	n := int64(lunProbeBytes)
	if n > size {
		n = size
	}
	buf := make([]byte, n)
	for _, off := range []int64{0, size - n} {
		if _, err := r.ReadAt(buf, off); err != nil && err != io.EOF {
			return false, err
		}
		for _, b := range buf {
			if b != 0 {
				return false, nil
			}
		}
	}
	return true, nil
}
