package grpcapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// importFSKey names the free space dir's writes come out of, so an import's
// reservation counts only against imports writing to the same space. A
// directory whose space cannot be told apart from another's gets "", which
// counts as the same as every other: too much charged is a refusal, too
// little a full disk.
func (s *Server) importFSKey(dir string) fsKey {
	if s.fsKeyOverride != nil {
		return fsKey(s.fsKeyOverride(dir))
	}
	p, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return ""
	}
	// Without mountinfo (not Linux) volumes that share a container cannot
	// be told apart.
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	fstype, source, ok := mountOf(string(info), p)
	if !ok {
		return ""
	}
	return fsKeyFor(fstype, source, func() fsKey { return devFSKey(p) })
}

// blockFilesystems are filesystems whose free space belongs to their device
// alone, so the device number names it.
var blockFilesystems = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "f2fs": true,
	"jfs": true, "reiserfs": true, "tmpfs": true, "vfat": true,
}

// fsKeyFor names a mount's free space from its type and source:
//   - btrfs: its device, not the per-subvolume device number (every
//     subvolume of one btrfs shares its free space);
//   - ZFS: its pool, which every dataset in it draws on;
//   - NFS: its server, since two exports can share one disk there;
//   - a block filesystem: its device number;
//   - anything else (overlay, FUSE, a cluster filesystem) cannot be told
//     apart, and counts as the same as every other.
func fsKeyFor(fstype, source string, dev func() fsKey) fsKey {
	switch {
	case fstype == "btrfs":
		if source == "" || source == "none" {
			return ""
		}
		return fsKey("btrfs:" + source)
	case fstype == "zfs":
		pool, _, _ := strings.Cut(source, "/")
		if pool == "" {
			return ""
		}
		return fsKey("zfs:" + pool)
	case fstype == "nfs" || fstype == "nfs4":
		i := strings.Index(source, ":/")
		if i <= 0 {
			return ""
		}
		return fsKey("nfs:" + source[:i])
	case blockFilesystems[fstype]:
		return dev()
	}
	return ""
}

func devFSKey(p string) fsKey {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return ""
	}
	return fsKey(fmt.Sprintf("dev:%d", st.Dev))
}

// mountOf finds the mount p is on in a /proc/self/mountinfo text: the last
// listed mount whose mount point is the longest prefix of p, component by
// component (a later mount over the same point hides the earlier one).
func mountOf(mountinfo, p string) (fstype, source string, ok bool) {
	best := -1
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" && i >= 6 {
				sep = i
				break
			}
		}
		if sep < 0 || len(f) < sep+3 {
			continue
		}
		mp := unescapeMountinfo(f[4])
		if !(mp == "/" || p == mp || strings.HasPrefix(p, mp+"/")) {
			continue
		}
		if len(mp) >= best {
			best = len(mp)
			fstype, source, ok = f[sep+1], unescapeMountinfo(f[sep+2]), true
		}
	}
	return fstype, source, ok
}

// unescapeMountinfo undoes mountinfo's octal escapes (\040 for a space).
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
