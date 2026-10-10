package grpcapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
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
//   - the LUN is blank (lunBlank) or the disk says overwrite. A LUN holding
//     data is never written without it.
//
// A re-created VM that takes its previous incarnation's LUN over (claimLUNs'
// keep) writes nothing: a rebuild or a recreate keeps the LUN's contents
// exactly as they are.
//
// The requested size of the disk is not applied: the LUN is the size the SAN
// gave it. Whatever lies between the probed regions of a "blank" LUN reaches
// the new guest when it grows its filesystem — the remanence of a LUN reused
// without being wiped, which litevirt does not wipe (DeleteDisk is a no-op).
//
// overwrite is an accident interlock, not an authorization boundary: anyone
// who may create the VM on the pool may also attach the LUN as a data disk
// and write anything to it from the guest.

// lunProbeBytes is how much of each end of a LUN must be zero.
const lunProbeBytes = 1 << 20

// lunPartitionProbe is how much from 1 MiB — where a first partition starts
// (2048 sectors) and a filesystem whose partition table was wiped still has
// its superblock (1 KiB, 64 KiB in) — must be zero too.
const lunPartitionProbe = 128 << 10

// lunSampleBytes is the size of each sample taken across the device, one per
// lunSampleStride, at most lunMaxSamples of them (spread evenly beyond that).
const (
	lunSampleBytes  = 64 << 10
	lunSampleStride = 1 << 30
	lunMaxSamples   = 256
)

// lunImageWriteTimeout bounds one image write. The write runs detached from
// the caller's context: a client that gives up must not leave a LUN half
// written.
const lunImageWriteTimeout = 2 * time.Hour

// openLUNDevice opens a LUN's block device to read its size and probe it,
// bypassing the page cache (openLUNDirect). Tests point it at a file.
var openLUNDevice = openLUNDirect

// writeImageToDevice writes an image's guest contents onto a block device.
// Tests replace it; production is qemuImgWrite.
var writeImageToDevice = qemuImgWrite

// lunQemuImg runs qemu-img. Tests replace it to see the argv.
var lunQemuImg = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "qemu-img", args...).CombinedOutput()
}

// qemuImgOptValue escapes a value for qemu's option syntax (a comma is
// doubled).
func qemuImgOptValue(v string) string { return strings.ReplaceAll(v, ",", ",,") }

// qemuImgWrite writes image (format qcow2 or raw) onto device in place (-n:
// the device exists and is not created). The image is opened by explicit
// options — its format named, and for qcow2 backing=null — so nothing is
// probed and no backing chain is followed, even if the file was swapped for
// one with a backing file after it was judged standalone.
func qemuImgWrite(ctx context.Context, image, format, device string) error {
	opts := "driver=" + format + ",file.driver=file,file.filename=" + qemuImgOptValue(image)
	if format == "qcow2" {
		opts += ",backing=null"
	}
	out, err := lunQemuImg(ctx, "convert", "-n", "-O", "raw", "--image-opts", opts, device)
	if err != nil {
		return fmt.Errorf("qemu-img convert %s onto %s: %w: %s", image, device, err, out)
	}
	return nil
}

// lunImageFormat is the format and guest size of the image at path: qcow2
// (its virtual size) or raw (the file's size). A VMDK, or anything else that
// names other files, is refused.
func lunImageFormat(path string) (format string, size uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := f.ReadAt(head, 0)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, []byte("QFI\xfb")):
		info, err := qcow2.Info(path)
		if err != nil {
			return "", 0, err
		}
		return "qcow2", info.VirtualSize, nil
	case bytes.HasPrefix(head, []byte("KDMV")), bytes.Contains(head, []byte("# Disk DescriptorFile")):
		return "", 0, fmt.Errorf("a VMDK image cannot be written onto a LUN; convert it to qcow2 or raw first")
	}
	st, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	return "raw", uint64(st.Size()), nil
}

// checkLUNForImage runs the size and blank checks for writing image onto
// device, and returns the image's format. It writes nothing.
func checkLUNForImage(vm, disk, image, imagePath, device string, overwrite bool) (string, error) {
	format, need, err := lunImageFormat(imagePath)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "image %q: %v", image, err)
	}
	f, err := openLUNDevice(device)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition,
			"root disk %q of VM %q: open iSCSI LUN %s to write image %q onto it: %v", disk, vm, device, image, err)
	}
	defer f.Close()
	size, err := f.Seek(0, io.SeekEnd)
	if err == nil && size <= 0 {
		err = fmt.Errorf("it reports no size")
	}
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "root disk %q of VM %q: size of iSCSI LUN %s: %v", disk, vm, device, err)
	}
	if uint64(size) < need {
		return "", status.Errorf(codes.FailedPrecondition,
			"root disk %q of VM %q: iSCSI LUN %s is %d bytes, smaller than image %q (%d bytes) — give the disk a "+
				"pool on a LUN of at least the image's size", disk, vm, device, size, image, need)
	}
	blank, err := lunBlank(f, size)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "root disk %q of VM %q: read iSCSI LUN %s: %v", disk, vm, device, err)
	}
	if !blank && !overwrite {
		return "", status.Errorf(codes.FailedPrecondition,
			"root disk %q of VM %q: iSCSI LUN %s is not blank (it holds data: a partition table, a filesystem, an "+
				"earlier disk), and writing image %q would destroy it — if its contents are disposable, set "+
				"overwrite on the disk (compose `overwrite: true`, `lv run --overwrite`)", disk, vm, device, image)
	}
	return format, nil
}

// writeImageOntoLUN makes disk of vm, LUN device, the image at imagePath —
// or refuses, writing nothing. The write is audited, with its outcome.
func (s *Server) writeImageOntoLUN(ctx context.Context, vm, disk, image, imagePath, device string, overwrite bool) error {
	format, err := checkLUNForImage(vm, disk, image, imagePath, device, overwrite)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lunImageWriteTimeout)
	defer cancel()
	werr := writeImageToDevice(wctx, imagePath, format, device)
	result := "ok"
	if werr != nil {
		result = "failed"
	}
	if overwrite {
		s.audit(ctx, "vm.create", vm, fmt.Sprintf("image %s written onto iSCSI LUN %s with overwrite (disk %s)", image, device, disk), result)
	}
	if werr != nil {
		return status.Errorf(codes.Internal,
			"root disk %q of VM %q: write image %q onto iSCSI LUN %s: %v — the LUN may be partly written, so a retry "+
				"needs overwrite", disk, vm, image, device, werr)
	}
	slog.Info("iSCSI root disk: image written onto the LUN", "vm", vm, "disk", disk, "lun", device, "image", image)
	return nil
}

// lunProbeRegions is where lunBlank reads a size-byte device: both edges, the
// first-partition region, and a sample every lunSampleStride (at most
// lunMaxSamples, spread evenly). Offsets and lengths are 4 KiB-aligned, as a
// direct read needs.
func lunProbeRegions(size int64) [][2]int64 {
	const align = 4096
	down := func(v int64) int64 { return v / align * align }
	clip := func(off, n int64) (int64, int64) {
		if off >= size {
			return 0, 0
		}
		if off+n > size {
			n = size - off
		}
		return off, n
	}
	var out [][2]int64
	add := func(off, n int64) {
		if off, n = clip(down(off), n); n > 0 {
			out = append(out, [2]int64{off, n})
		}
	}
	add(0, lunProbeBytes)
	add(size-lunProbeBytes, lunProbeBytes)
	add(1<<20, lunPartitionProbe)
	if stops := size / lunSampleStride; stops > 0 {
		step := int64(lunSampleStride)
		if stops > lunMaxSamples {
			step = size / lunMaxSamples
		}
		for off := step; off < size; off += step {
			add(off, lunSampleBytes)
		}
	}
	return out
}

// lunBlank reports whether every probed region of a size-byte device is all
// zeros. It cannot see data that lies only between the regions.
func lunBlank(r io.ReaderAt, size int64) (bool, error) {
	buf := alignedBuffer(lunProbeBytes)
	for _, reg := range lunProbeRegions(size) {
		b := buf[:reg[1]]
		if _, err := r.ReadAt(b, reg[0]); err != nil && err != io.EOF {
			return false, err
		}
		for _, x := range b {
			if x != 0 {
				return false, nil
			}
		}
	}
	return true, nil
}

// preflightLUNs judges, before cur is torn down to be created again from
// spec, what the create would refuse about its iSCSI LUNs that the teardown
// does not change: the release gate, another VM using the LUN, and — for a
// root disk built on an image onto a LUN cur did not hold as that disk — the
// size and blank checks, where this host can open the device (the create
// judges again on its own host).
func (s *Server) preflightLUNs(ctx context.Context, spec *pb.VMSpec, cur *corrosion.VMRecord) error {
	uses, err := s.fixedDeviceUses(ctx, spec)
	if err != nil || len(uses) == 0 {
		return err
	}
	if err := s.iscsiLUNClaimGate(ctx); err != nil {
		return err
	}
	rep := replacedVM{name: cur.Name, snap: corrosion.VMDeleteSnapshot{CreatedAt: cur.CreatedAt}}
	if disks, err := corrosion.VMIncarnationDisks(ctx, s.db, cur.Name, cur.CreatedAt); err == nil {
		for _, d := range disks {
			if k, ok := storage.FixedDeviceKeyOfPath(d.Path); ok {
				if rep.luns == nil {
					rep.luns = map[string]string{}
				}
				rep.luns[k] = d.DiskName
			}
		}
	}
	keys := map[string]bool{}
	byKey := map[string]lunUse{}
	for _, u := range uses {
		keys[u.key], byKey[u.key] = true, u
	}
	here, err := s.lunHoldersHere(ctx, keys, rep, true, 0)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read disks: %v", err)
	}
	if len(here) > 0 {
		return lunHeldError(spec.Name, byKey[here[0].Lun], here[0])
	}
	if spec.Image == "" {
		return nil
	}
	for _, d := range spec.Disks {
		name := d.Name
		if name == "" {
			name = "root"
		}
		if name != "root" {
			continue
		}
		for _, u := range uses {
			if u.disk != name || rep.luns[u.key] == name {
				continue
			}
			if f, err := openLUNDevice(u.device); err != nil {
				continue // not on this host; the create judges it there
			} else {
				f.Close()
			}
			imagePath, err := s.poolRootDiskBacking(spec.Image, "iscsi")
			if err != nil {
				return err
			}
			if _, err := checkLUNForImage(spec.Name, name, spec.Image, imagePath, u.device, d.Overwrite); err != nil {
				return err
			}
		}
	}
	return nil
}
