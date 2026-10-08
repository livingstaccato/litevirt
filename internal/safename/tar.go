package safename

import (
	"archive/tar"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// ExtractFlatTar extracts a tar stream into dest with STRICT semantics: only
// regular files and directories are allowed; symlinks, hardlinks, device nodes,
// absolute member names and ".." traversal are rejected; and modes are clamped
// (dirs 0700, files 0600) rather than trusting header modes. It is the reusable
// counterpart of the bespoke strict extractors in internal/libvirt/vtpmstate.go
// (firmware bundles) and internal/vmimport (OVA), for simple untrusted archives
// that hold only plain files.
func ExtractFlatTar(r io.Reader, dest string) error {
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		target, err := tarMemberPath(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAllNoFollow(dest, target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := mkdirAllNoFollow(dest, filepath.Dir(target), 0o700); err != nil {
				return err
			}
			if err := writeRegularNoFollow(target, tr, 0o600); err != nil {
				return err
			}
		default:
			return fmt.Errorf("flat tar: disallowed member type %d for %q (only regular files and dirs)", hdr.Typeflag, hdr.Name)
		}
	}
	return nil
}

// ExtractRootfsTar extracts a container rootfs tar into dest with rootfs-aware
// semantics: it PRESERVES symlinks, file modes (setuid, setgid and sticky
// included, as LXC's own tooling restores a rootfs), numeric ownership and the
// extended attributes a container's files carry — file capabilities, ACLs,
// SELinux labels and user attributes (applyXattrs) — but never WRITES THROUGH a
// symlink (every path component is lstat'd; a symlinked component is refused),
// contains every member under dest, rejects hardlinks whose target isn't an
// already-extracted regular file under dest, and rejects device/char/fifo nodes.
// Symlink targets are stored verbatim (not rewritten): they are never followed
// during extraction, and lxc confines the rootfs at runtime, so an escaping link
// target is inert.
//
// If expectedTop is non-empty, every member's first path component must equal it
// (so a tampered archive can't clobber a sibling under dest by naming a
// different top-level directory).
func ExtractRootfsTar(r io.Reader, dest, expectedTop string) error {
	_, err := ExtractRootfsTarReport(r, dest, expectedTop)
	return err
}

// ExtractRootfsTarReport is ExtractRootfsTar that also returns the attributes
// the target filesystem does not support and that were therefore dropped, as
// "<member> <attribute>" (see applyXattrs).
func ExtractRootfsTarReport(r io.Reader, dest, expectedTop string) (dropped []string, err error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	// A directory's metadata (owner, mode, attributes — a default ACL among
	// them) is applied after its contents, deepest first, as GNU tar does: a
	// default ACL applied first would be inherited by children the archive
	// recorded without one, and a read-only mode would block them.
	type dirMeta struct {
		target string
		hdr    *tar.Header
		mode   os.FileMode
	}
	var dirs []dirMeta
	defer func() {
		if err != nil {
			return
		}
		for i := len(dirs) - 1; i >= 0; i-- {
			d, ferr := finishMember(dirs[i].target, dirs[i].hdr, dirs[i].mode)
			dropped = append(dropped, d...)
			if ferr != nil {
				err = ferr
				return
			}
		}
	}()
	err = extractRootfsMembers(r, dest, expectedTop, func(target string, hdr *tar.Header, mode os.FileMode) {
		dirs = append(dirs, dirMeta{target, hdr, mode})
	}, func(d []string) { dropped = append(dropped, d...) })
	return dropped, err
}

func extractRootfsMembers(r io.Reader, dest, expectedTop string, deferDir func(string, *tar.Header, os.FileMode), noteDropped func([]string)) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read rootfs tar: %w", err)
		}
		clean, err := cleanMemberName(hdr.Name)
		if err != nil {
			return err
		}
		if expectedTop != "" {
			top := clean
			if i := strings.IndexByte(clean, filepath.Separator); i >= 0 {
				top = clean[:i]
			}
			if top != expectedTop {
				return fmt.Errorf("rootfs tar: member %q is outside expected top-level dir %q", hdr.Name, expectedTop)
			}
		}
		target, err := SafeJoin(dest, clean)
		if err != nil {
			return err
		}
		// Link targets are contained under the SUBTREE root (the expected
		// top-level dir, e.g. the container dir), not just dest — so a link inside
		// ct/… can't point at a sibling under dest but outside ct/.
		linkRoot := dest
		if expectedTop != "" {
			linkRoot = filepath.Join(dest, expectedTop)
		}
		mode := os.FileMode(hdr.Mode).Perm()
		special := hdr.FileInfo().Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAllNoFollow(dest, target, 0o700); err != nil {
				return err
			}
			deferDir(target, hdr, mode|0o100|special)
		case tar.TypeReg, tar.TypeRegA:
			if err := mkdirAllNoFollow(dest, filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := writeRegularNoFollow(target, tr, mode); err != nil {
				return err
			}
			d, err := finishMember(target, hdr, mode|special)
			noteDropped(d)
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			// Validate the link TARGET stays within the extraction root: an
			// absolute target is interpreted root-relative (so "/usr/bin" works
			// and resolves inside the rootfs at runtime), a relative target is
			// resolved from the link's own directory; either way a target that
			// escapes the root ("../../host") is rejected. The link is then stored
			// verbatim (never followed during extraction).
			var resolved string
			if filepath.IsAbs(hdr.Linkname) {
				resolved = filepath.Join(linkRoot, filepath.Clean(hdr.Linkname))
			} else {
				resolved = filepath.Join(filepath.Dir(target), hdr.Linkname)
			}
			if !Contains(linkRoot, resolved) {
				return fmt.Errorf("rootfs tar: symlink %q target %q escapes root", hdr.Name, hdr.Linkname)
			}
			if err := mkdirAllNoFollow(dest, filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := ensureNotSymlink(target); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("rootfs tar: symlink %q: %w", hdr.Name, err)
			}
			_ = lchown(target, hdr.Uid, hdr.Gid)
		case tar.TypeLink:
			if err := mkdirAllNoFollow(dest, filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// A hardlink's Linkname is an archive-root-relative member name; resolve
			// it under dest, then require it to stay within the subtree root.
			linkTarget, err := SafeJoin(dest, filepath.Clean(hdr.Linkname))
			if err != nil {
				return fmt.Errorf("rootfs tar: hardlink %q target escapes root: %w", hdr.Name, err)
			}
			if !Contains(linkRoot, linkTarget) {
				return fmt.Errorf("rootfs tar: hardlink %q target %q escapes subtree", hdr.Name, hdr.Linkname)
			}
			fi, err := os.Lstat(linkTarget)
			if err != nil {
				return fmt.Errorf("rootfs tar: hardlink %q target not yet extracted", hdr.Name)
			}
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("rootfs tar: hardlink %q target is not a regular file", hdr.Name)
			}
			_ = os.Remove(target)
			if err := os.Link(linkTarget, target); err != nil {
				return fmt.Errorf("rootfs tar: hardlink %q: %w", hdr.Name, err)
			}
		default:
			return fmt.Errorf("rootfs tar: disallowed member type %d for %q (device/fifo/char not permitted)", hdr.Typeflag, hdr.Name)
		}
	}
	return nil
}

// cleanMemberName force-relativizes a tar member name and rejects empty / "."
// / absolute / ".."-escaping names. Returns the cleaned relative path.
func cleanMemberName(name string) (string, error) {
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("tar: rejected absolute member path %q", name)
	}
	clean := filepath.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "" || clean == "." {
		return "", fmt.Errorf("tar: empty member name")
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("tar: rejected path-escaping member %q", name)
	}
	return clean, nil
}

// tarMemberPath cleans+contains a member name under dest in one step.
func tarMemberPath(dest, name string) (string, error) {
	clean, err := cleanMemberName(name)
	if err != nil {
		return "", err
	}
	return SafeJoin(dest, clean)
}

// mkdirAllNoFollow creates dir (under root) like os.MkdirAll, but refuses to
// traverse a symlinked component — so a member can't be written through a
// symlink planted by an earlier member. Each path component is lstat'd: an
// existing symlink is an error, an existing dir is reused, a missing component
// is created with perm.
func mkdirAllNoFollow(root, dir string, perm os.FileMode) error {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("mkdir %q escapes %q", dir, root)
	}
	if err := os.MkdirAll(root, perm|0o700); err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	cur := filepath.Clean(root)
	for _, comp := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, comp)
		fi, err := os.Lstat(cur)
		switch {
		case err == nil && fi.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("refusing to extract through symlinked path component %q", cur)
		case err == nil && fi.IsDir():
			continue
		case err == nil:
			return fmt.Errorf("path component %q exists and is not a directory", cur)
		case os.IsNotExist(err):
			if err := os.Mkdir(cur, perm|0o100); err != nil {
				return err
			}
		default:
			return err
		}
	}
	return nil
}

// writeRegularNoFollow writes a tar entry to target, refusing to follow target
// if it already exists as a symlink (O_NOFOLLOW), and fsyncing before close.
func writeRegularNoFollow(target string, src io.Reader, mode os.FileMode) error {
	if err := ensureNotSymlink(target); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return fmt.Errorf("create %q: %w", target, err)
	}
	if _, err := io.Copy(f, src); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ensureNotSymlink errors if target exists and is a symlink (so we never clobber
// or write through one).
func ensureNotSymlink(target string) error {
	fi, err := os.Lstat(target)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write through existing symlink %q", target)
	}
	return nil
}

// lchown is os.Lchown, and lsetxattr sets an attribute without following a
// symlink; variables so a test runs without root.
var lchown = os.Lchown

func setLchownForTest(fn func(string, int, int) error) (restore func()) {
	old := lchown
	lchown = fn
	return func() { lchown = old }
}

func setLsetxattrForTest(fn func(string, string, []byte) error) (restore func()) {
	old := lsetxattr
	lsetxattr = fn
	return func() { lsetxattr = old }
}

// finishMember sets a directory's or regular file's owner, then its mode with
// the special bits (chown clears setuid and setgid), then its extended
// attributes (chown also clears a file capability). The owner is best-effort,
// as before: an unprivileged caller cannot chown.
func finishMember(target string, hdr *tar.Header, mode os.FileMode) ([]string, error) {
	_ = lchown(target, hdr.Uid, hdr.Gid)
	if err := os.Chmod(target, mode); err != nil {
		return nil, fmt.Errorf("rootfs tar: mode of %q: %w", hdr.Name, err)
	}
	return applyXattrs(target, hdr, mode)
}

// xattrPAXPrefix is how GNU tar --xattrs (and Go) carry an attribute.
const xattrPAXPrefix = "SCHILY.xattr."

// rootfsXattrNamespaces are the attributes a rootfs archive may set: file
// capabilities and SELinux labels (security.*), POSIX ACLs and user
// attributes. trusted.* is root-only metadata other subsystems act on
// (overlayfs reads trusted.overlay.*), so an archive does not get to choose
// it. An ACL GNU tar --acls also wrote as text (SCHILY.acl.*) is carried by
// its raw attribute beside it.
var rootfsXattrNamespaces = []string{"security.", "system.posix_acl_access", "system.posix_acl_default", "user."}

// applyXattrs sets the archived extended attributes of target. An attribute
// the target filesystem does not support (ENOTSUP: ZFS with acltype=off, NFS)
// is dropped and returned, as main dropped them all, rather than fail the
// restore. Dropping must never widen access: without its access ACL, a file's
// group-class mode bits (the ACL mask) would become the owning group's
// permissions, so they are narrowed to the ACL's own group entry. A dropped
// capability or label only ever removes privilege. Any other error fails.
func applyXattrs(target string, hdr *tar.Header, mode os.FileMode) ([]string, error) {
	var dropped []string
	for k, v := range hdr.PAXRecords {
		name, ok := strings.CutPrefix(k, xattrPAXPrefix)
		if !ok || !xattrAllowed(name) {
			continue
		}
		err := lsetxattr(target, name, []byte(v))
		if err == nil {
			continue
		}
		if !cannotStoreHere(name, err) {
			return dropped, fmt.Errorf("rootfs tar: set %s on %q: %w", name, hdr.Name, err)
		}
		dropped = append(dropped, hdr.Name+" "+name)
		if name == "system.posix_acl_access" {
			if g, ok := aclGroupObjPerm(v); ok {
				narrowed := mode&^0o070 | (mode & 0o070 & os.FileMode(g<<3))
				if err := os.Chmod(target, narrowed); err != nil {
					return dropped, fmt.Errorf("rootfs tar: narrow the mode of %q for its dropped ACL: %w", hdr.Name, err)
				}
			} else if err := os.Chmod(target, mode&^0o070); err != nil {
				return dropped, fmt.Errorf("rootfs tar: narrow the mode of %q for its dropped ACL: %w", hdr.Name, err)
			}
		}
	}
	sort.Strings(dropped)
	return dropped, nil
}

// aclGroupObjPerm returns the rwx bits of an ACL xattr's owning-group
// (ACL_GROUP_OBJ) entry.
func aclGroupObjPerm(v string) (uint32, bool) {
	b := []byte(v)
	if len(b) < 4 || (len(b)-4)%8 != 0 || binary.LittleEndian.Uint32(b) != 2 {
		return 0, false
	}
	for off := 4; off < len(b); off += 8 {
		if binary.LittleEndian.Uint16(b[off:]) == 0x04 {
			return uint32(binary.LittleEndian.Uint16(b[off+2:]) & 0o7), true
		}
	}
	return 0, false
}

func xattrAllowed(name string) bool {
	for _, ns := range rootfsXattrNamespaces {
		if strings.HasPrefix(name, ns) {
			return true
		}
	}
	return false
}
