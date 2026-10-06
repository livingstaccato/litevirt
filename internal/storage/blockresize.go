package storage

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// IsBlockVolumeDriver reports whether a disk of this storage type is a host
// block volume (a zvol or a thin LV) rather than an image file.
func IsBlockVolumeDriver(storageType string) bool {
	switch strings.ToLower(storageType) {
	case "zfs", "lvm-thin", "lvmthin":
		return true
	}
	return false
}

// blockVolumeGrain is what a block volume's new size is rounded up to: a
// zvol's volsize must be a multiple of its volblocksize (at most 1 MiB in
// practice), and LVM rounds to its extent size on its own.
const blockVolumeGrain = 1 << 20

// MaxBlockVolumeBytes is the largest size a block volume is grown to: 16 PiB,
// far past any disk, and far from overflowing int64 when rounded.
const MaxBlockVolumeBytes = 1 << 54

// GrowBlockVolume grows the zvol or thin LV at path (as its driver's
// CreateDisk named it: /dev/zvol/<dataset> or /dev/<vg>/<lv>) to at least
// newSize bytes, and returns the size it was set to. `qemu-img resize` cannot
// grow either — it would only rewrite an image header. The volume is derived
// from the path and must be in its driver's strict form, which never starts
// with "-", so no other value reaches the tool. `zfs set` takes no "--":
// OpenZFS up to 2.1 parses its arguments without getopt and would take "--"
// for a dataset. lvextend (getopt) gets one. It never shrinks: the caller has
// already refused a size that is not larger than the recorded one, and
// refuses a volume whose size is not recorded.
func GrowBlockVolume(ctx context.Context, storageType, path string, newSize int64) (int64, error) {
	if newSize <= 0 || newSize > MaxBlockVolumeBytes {
		return 0, fmt.Errorf("invalid size %d (at most %d bytes)", newSize, int64(MaxBlockVolumeBytes))
	}
	size := (newSize + blockVolumeGrain - 1) / blockVolumeGrain * blockVolumeGrain
	switch strings.ToLower(storageType) {
	case "zfs":
		ds, ok := strings.CutPrefix(path, "/dev/zvol/")
		if !ok || !zfsDatasetRe.MatchString(ds) || !strings.Contains(ds, "/") || strings.HasPrefix(ds, "-") {
			return 0, fmt.Errorf("zfs disk path %q is not /dev/zvol/<pool>/<dataset>", path)
		}
		if out, err := exec.CommandContext(ctx, "zfs", "set", fmt.Sprintf("volsize=%d", size), ds).CombinedOutput(); err != nil {
			return 0, fmt.Errorf("zfs set volsize %s: %w: %s", ds, err, out)
		}
	case "lvm-thin", "lvmthin":
		rest, ok := strings.CutPrefix(path, "/dev/")
		vg, lv, ok2 := strings.Cut(rest, "/")
		if !ok || !ok2 || !lvmNameRe.MatchString(vg) || !lvmNameRe.MatchString(lv) {
			return 0, fmt.Errorf("lvm disk path %q is not /dev/<vg>/<lv>", path)
		}
		if out, err := exec.CommandContext(ctx, "lvextend", "-L", fmt.Sprintf("%db", size), "--", vg+"/"+lv).CombinedOutput(); err != nil {
			return 0, fmt.Errorf("lvextend %s/%s: %w: %s", vg, lv, err, out)
		}
	default:
		return 0, fmt.Errorf("storage type %q is not a block volume", storageType)
	}
	return size, nil
}
