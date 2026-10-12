package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cmdbound"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
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
	return cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, "qemu-img", args...))
}

// qemuImgSource is the json: filename qemu-img opens image (format qcow2 or
// raw) by: its format and its protocol named, so nothing is probed, and for
// qcow2 "backing": null — JSON null, which disables the backing file entirely
// (QAPI BlockdevRefOrNull, QEMU 2.10+) — so no backing chain is followed,
// even if the file was swapped for one with a backing file after it was
// judged standalone. Not --image-opts: its key=value syntax cannot spell
// null, and backing=null there names a node called "null", which every
// write then failed to find (lab 2, qemu-img 8.2.2). The path is JSON-encoded,
// so a comma or a quote in it is only ever part of the filename.
func qemuImgSource(image, format string) (string, error) {
	type file struct {
		Driver   string `json:"driver"`
		Filename string `json:"filename"`
	}
	type src struct {
		Driver  string    `json:"driver"`
		File    file      `json:"file"`
		Backing *struct{} `json:"backing"`
	}
	type rawSrc struct {
		Driver string `json:"driver"`
		File   file   `json:"file"`
	}
	var v any = rawSrc{Driver: format, File: file{Driver: "file", Filename: image}}
	if format == "qcow2" {
		v = src{Driver: format, File: file{Driver: "file", Filename: image}} // Backing nil: "backing":null
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return "json:" + strings.TrimSuffix(buf.String(), "\n"), nil
}

// qemuImgWrite writes image (format qcow2 or raw) onto device in place (-n:
// the device exists and is not created), opened as qemuImgSource says.
func qemuImgWrite(ctx context.Context, image, format, device string) error {
	srcName, err := qemuImgSource(image, format)
	if err != nil {
		return fmt.Errorf("qemu-img source for %s: %w", image, err)
	}
	out, err := lunQemuImg(ctx, "convert", "-n", "-O", "raw", srcName, device)
	if err != nil {
		return fmt.Errorf("qemu-img convert %s onto %s: %w: %s", image, device, err, out)
	}
	return nil
}

// lunImageFormat is the format and guest size of the image at path. The
// image store holds qcow2 images (<name>.qcow2); that is the source format,
// named explicitly to qemu-img. Anything else — raw bytes, a VDI, a VHDX, a
// VMDK — is refused, never guessed at as raw and copied onto the LUN.
func lunImageFormat(path string) (format string, size uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	head := make([]byte, 4)
	n, _ := f.ReadAt(head, 0)
	f.Close()
	if n < 4 || !bytes.Equal(head, []byte("QFI\xfb")) {
		return "", 0, fmt.Errorf("it is not a qcow2 image, and only a qcow2 image from the image store is written onto a LUN")
	}
	info, err := qcow2.Info(path)
	if err != nil {
		return "", 0, err
	}
	return "qcow2", info.VirtualSize, nil
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

// lunPreflightKey carries, from a recreate's preflight into its create, the
// LUNs the preflight claimed for the VM (LUN key → disk name).
type lunPreflightKey struct{}

// recreateOutcome is how a rebuild or recreate ended, as its preflight's
// done is told.
type recreateOutcome int

const (
	// recreateNotAttempted: it returned before its create was called — the
	// delete refused, or failed. No guest was started under the moved claim.
	recreateNotAttempted recreateOutcome = iota
	// recreateFailed: the create was called and returned an error. Its
	// guest may run all the same (an answer lost after it started).
	recreateFailed
	// recreateCommitted: the create returned the re-created VM.
	recreateCommitted
)

// preflightLUNs judges, before cur is torn down to be created again from
// spec on runHost, everything about its iSCSI LUNs the create would judge, so
// that nothing about them refuses after the teardown — and MOVES the claim:
//
//   - the release gate and the voter generation;
//   - this host's hold on every LUN, taken FIRST (a LUN another create holds
//     refuses here): its registry entry, and its durable record
//     (vm_lun_hold.go), which outlives the re-create and a restart and is
//     released only on positive evidence;
//   - another VM, or a domain, using a LUN (cur's own rows and domain aside);
//   - for a root disk built on an image that is written: the image's format
//     (no device needed), then the size and blank checks where this host can
//     open the device;
//   - a root disk cur keeps whose image changes: refused unless the disk says
//     overwrite (review m-3);
//   - LAST, once nothing above can refuse (re-review 3, m-1): each LUN's next
//     allocation, decided for the VM with THIS host as its allocator and
//     runHost, where the re-created VM runs, beside it. Every allocation
//     before it is proven gone, cur's own (its name and the disk) passed over
//     once nothing but cur holds the LUN. A racing create meets the new
//     allocation and asks both hosts (re-review 2, C-1; re-review 3, I-2).
//
// runHost is the host the create is pinned or placed to; every caller names
// it, and a preflight with LUNs to move and no run host refuses — the
// moved allocation must name exactly where the VM runs (re-review 4, I-2).
//
// The returned context carries the claims and the hold into the create
// (withReplacedLUNs takes them over); done(outcome) marks the re-create
// returned — call it exactly once, whatever happened:
//
//   - recreateNotAttempted (the delete refused or failed, no create called):
//     the hold is ABANDONED — no guest was started under the moved claim, and
//     a VM that survived keeps its own allocation on its own host, which
//     every walk still meets (re-review 4, I-1);
//   - recreateFailed: the hold stays until its evidence arrives;
//   - recreateCommitted: likewise, and the LUN's checkpoint moves to the
//     moved allocation now, never before the create committed.
func (s *Server) preflightLUNs(ctx context.Context, spec *pb.VMSpec, cur *corrosion.VMRecord, runHost string) (context.Context, func(recreateOutcome), error) {
	noop := func(recreateOutcome) {}
	uses, err := s.recreateFixedDeviceUses(ctx, spec, cur)
	if err != nil || len(uses) == 0 {
		return ctx, noop, err
	}
	if runHost == "" {
		return ctx, noop, status.Errorf(codes.Unavailable,
			"VM %q has a disk on an iSCSI LUN, and the host it is re-created on was not fixed before the "+
				"teardown (its storage changed while the re-create was judged) — retry", spec.Name)
	}
	if _, err := s.lunElectorate(ctx); err != nil {
		return ctx, noop, err
	}
	rep := replacedVM{name: cur.Name, snap: corrosion.VMDeleteSnapshot{CreatedAt: cur.CreatedAt}}
	if cs := vmSpecFor(cur); cs != nil {
		rep.uuid, rep.image = cs.GetUuid(), cs.GetImage()
	}
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
	held := map[string]string{}
	for _, u := range uses {
		keys[u.key], byKey[u.key], held[u.key] = true, u, u.disk
	}
	// The hold first: from here on no create on this host takes these LUNs,
	// and a create on another host that meets the moved claim is told they
	// are in flight (review m-1: a hold that cannot be taken refuses now).
	token := randid.New()
	holdID, drop, heldKey, holder := s.lunClaims.take(cur.Name, "", token, uses)
	if drop == nil {
		return ctx, noop, lunHeldError(spec.Name, byKey[heldKey], &pb.LUNHolder{
			Lun: heldKey, VmName: holder.vm, DiskName: holder.disk, HostName: s.hostName, InFlight: true, VmId: holder.vmID,
		})
	}
	if err := s.putLUNHold(&lunHoldRecord{Token: token, VM: cur.Name, ReplacedCreatedAt: cur.CreatedAt, LUNs: held,
		RunHost: runHost, Since: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
		drop()
		return ctx, noop, status.Errorf(codes.Unavailable, "cannot record this host's hold on the VM's iSCSI LUNs: %v", err)
	}
	ok := false
	defer func() {
		if !ok {
			// Refused before the teardown: the VM still holds its LUNs
			// as it did, so the hold goes with nothing to wait for.
			s.abandonLUNHold(token)
			drop()
		}
	}()
	here, err := s.lunHoldersHere(ctx, keys, rep, true, holdID, token, "")
	if err != nil {
		return ctx, noop, status.Errorf(codes.Unavailable, "read disks: %v", err)
	}
	if len(here) > 0 {
		return ctx, noop, lunHeldError(spec.Name, byKey[here[0].Lun], here[0])
	}
	if spec.Image != "" {
		for _, d := range spec.Disks {
			name := d.Name
			if name == "" {
				name = "root"
			}
			if name != "root" {
				continue
			}
			for _, u := range uses {
				if u.disk != name {
					continue
				}
				kept := rep.luns[u.key] == name
				if kept && spec.Image == rep.image {
					continue // a rebuild: the LUN is kept as it is
				}
				if kept && !d.Overwrite {
					return ctx, noop, status.Errorf(codes.FailedPrecondition,
						"root disk %q of VM %q is iSCSI LUN %s, which keeps its contents across a re-create, so the "+
							"image change from %q to %q would not reach it — set overwrite on the disk to write the "+
							"new image over it (destroying what it holds), or keep the image", name, spec.Name, u.device,
						rep.image, spec.Image)
				}
				imagePath, err := s.poolRootDiskBacking(spec.Image, "iscsi")
				if err != nil {
					return ctx, noop, err
				}
				// The image's format and size need no device (review m-4).
				if _, _, err := lunImageFormat(imagePath); err != nil {
					return ctx, noop, status.Errorf(codes.FailedPrecondition, "image %q: %v", spec.Image, err)
				}
				if f, err := openLUNDevice(u.device); err != nil {
					continue // not on this host; the create judges the device there
				} else {
					f.Close()
				}
				if _, err := checkLUNForImage(spec.Name, name, spec.Image, imagePath, u.device, d.Overwrite); err != nil {
					return ctx, noop, err
				}
			}
		}
	}
	vmID := rep.uuid
	if vmID == "" {
		vmID = cur.Name + "@" + cur.CreatedAt
	}
	moved := ""
	if runHost != s.hostName {
		moved = runHost
	}
	// The release gate last, just before the first claim: every local
	// refusal above writes nothing, so it records no use either (switch
	// review I-1). On a first use it waits with the registration and the
	// durable hold already taken: a racing create meets "in flight" for that
	// wait, retryable, and both are released on refusal (switch re-review
	// N-2).
	grant, err := s.iscsiLUNClaimGate(ctx)
	if err != nil {
		return ctx, noop, err
	}
	claimed := map[string]string{}
	decided := map[string]int64{}
	for _, u := range uses {
		mine := corrosion.LUNAllocation{LUN: u.key, ClaimID: randid.New(), VMID: vmID, VMName: cur.Name,
			Disk: u.disk, Host: s.hostName, RunHost: moved}
		if lunKeptAcross(spec, rep, u) {
			// The keep is bound to the VM's project and to the incarnation
			// this re-create replaces (keptForVM; re-review 5, R-1).
			mine.Kept, mine.Project, mine.ReplacedCreatedAt = true, tenancy.NormalizeProject(cur.Project), cur.CreatedAt
		}
		g, _, err := s.allocateLUN(ctx, grant, spec.Name, u, mine, rep, true, holdID, token, false)
		if err != nil {
			return ctx, noop, err
		}
		claimed[u.key] = u.disk
		decided[u.key] = g
	}
	ok = true
	ctx = context.WithValue(ctx, lunPreflightKey{}, claimed)
	ctx = context.WithValue(ctx, lunHandoffKey{}, token)
	var once sync.Once
	return ctx, func(out recreateOutcome) {
		once.Do(func() {
			switch out {
			case recreateNotAttempted:
				s.abandonLUNHold(token)
				drop()
				return
			case recreateCommitted:
				for k, g := range decided {
					if err := corrosion.AdvanceLUNResolved(context.WithoutCancel(ctx), s.db, grant, k, g, s.hostName); err != nil {
						slog.Warn("iSCSI LUN: record checkpoint", "lun", k, "generation", g, "error", err)
					}
				}
			}
			drop()
			s.finishLUNHold(token)
		})
	}, nil
}

// lunKeptAcross reports whether u's LUN keeps its contents across the
// re-create of rep as spec: it is the replaced VM's own disk of that name,
// and nothing is written over it — no image change written with overwrite on
// the root disk.
func lunKeptAcross(spec *pb.VMSpec, rep replacedVM, u lunUse) bool {
	if rep.luns[u.key] != u.disk {
		return false
	}
	return !(u.disk == "root" && spec.Image != "" && spec.Image != rep.image && u.overwrite)
}

// lunPreflightKeys is the LUN keys a preflight context claimed.
func lunPreflightKeys(ctx context.Context) map[string]bool {
	c, _ := ctx.Value(lunPreflightKey{}).(map[string]string)
	out := make(map[string]bool, len(c))
	for k := range c {
		out[k] = true
	}
	return out
}
