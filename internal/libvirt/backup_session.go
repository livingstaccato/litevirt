// (content-based rewrite) — a BackupSession is an open
// pull-mode backup: a point-in-time NBD export of a VM disk's GUEST-VISIBLE
// content, plus a meta-context describing which regions matter
// (base:allocation for a full backup, the merged dirty bitmap for an
// incremental). The backup layer enumerates the regions it needs
// (ChangedExtents) and reads their bytes (ReadAt) — all in guest-virtual
// address space, so the dirty bitmap and the data are consistent.
//
// This supersedes the earlier qcow2-container backup: reading the guest
// disk (not the qcow2 file) is what makes incremental dirty-bitmap backups
// correct, and makes restores format-portable.
package libvirt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/randid"
)

// domainDisksXML is the minimal view of a domain's <devices><disk> list we
// need to map a disk's source file to its libvirt target dev.
type domainDisksXML struct {
	Disks []struct {
		Source struct {
			File string `xml:"file,attr"`
			Dev  string `xml:"dev,attr"`
		} `xml:"source"`
		Target struct {
			Dev string `xml:"dev,attr"`
		} `xml:"target"`
	} `xml:"devices>disk"`
}

// diskTargetForSource returns the <target dev> of the disk whose source
// (file or block dev) matches sourcePath, or "" if none.
func diskTargetForSource(domXML, sourcePath string) string {
	var d domainDisksXML
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return ""
	}
	for _, disk := range d.Disks {
		if disk.Source.File == sourcePath || disk.Source.Dev == sourcePath {
			return disk.Target.Dev
		}
	}
	return ""
}

const (
	// Scratch + socket live under /var/lib (traversable by the
	// unprivileged libvirt-qemu user), each session's in a directory of its
	// own that qemu can create the fleecing image and bind the NBD socket in
	// (prepareBackupSessionPaths). That qemu must create there was learned
	// from live testing on libvirt 10 (AppArmor-confined, qemu unprivileged).
	sessScratchDir = "/var/lib/litevirt/backup-scratch"
	sessSocketDir  = "/var/lib/litevirt/backup-sock"
)

// BackupSession holds an in-flight pull-mode backup. Close() ends it.
type BackupSession struct {
	c           *Client
	dom         golibvirt.Domain
	nbd         *nbdConn
	size        int64
	ctxID       uint32
	incremental bool
	export      string
	scratch     string
	socket      string
}

// BeginBackup starts a pull-mode backup of diskTarget (e.g. "vda") whose
// guest-visible content is `size` bytes. If parentCheckpoint != "" the
// export carries the dirty bitmap merged since that checkpoint
// (incremental); otherwise it carries base:allocation (full). newCheckpoint,
// if non-empty, is created atomically as the backup begins so the NEXT
// backup can diff against it.
//
// On any error the transient job + scratch are cleaned up. Requires a
// running domain and libvirt ≥ 6.x.
func (c *Client) BeginBackup(domain, diskPath, parentCheckpoint, newCheckpoint string) (*BackupSession, error) {
	dom, err := c.virt.DomainLookupByName(domain)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	// Resolve the libvirt target dev + the guest-visible (virtual) size
	// from the live domain — never trust caller-supplied values, which can
	// be stale/empty (e.g. vm_disks.target_dev is unset for VMs created via
	// CreateVM). This is what makes the backup cover the whole disk.
	domXML, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return nil, fmt.Errorf("dump domain xml: %w", err)
	}
	diskTarget := diskTargetForSource(domXML, diskPath)
	if diskTarget == "" {
		return nil, fmt.Errorf("no disk with source %q in domain %s", diskPath, domain)
	}
	_, capacity, _, err := c.virt.DomainGetBlockInfo(dom, diskPath, 0)
	if err != nil {
		return nil, fmt.Errorf("get block info for %s: %w", diskPath, err)
	}
	size := int64(capacity)

	tag := fmt.Sprintf("%s-%s", domain, diskTarget)
	scratch, socket, err := prepareBackupSessionPaths(sessScratchDir, sessSocketDir, tag, domainQEMUOwner(domXML))
	if err != nil {
		return nil, err
	}

	backupDoc, err := buildBackupXML(diskTarget, parentCheckpoint, socket, scratch)
	if err != nil {
		removeBackupSessionPaths(scratch, socket)
		return nil, err
	}
	var cpXML golibvirt.OptString
	if newCheckpoint != "" {
		doc, derr := buildCheckpointXML(newCheckpoint, []string{diskTarget})
		if derr != nil {
			removeBackupSessionPaths(scratch, socket)
			return nil, derr
		}
		cpXML = golibvirt.OptString{doc}
	}
	if err := c.virt.DomainBackupBegin(dom, backupDoc, cpXML, 0); err != nil {
		removeBackupSessionPaths(scratch, socket)
		return nil, fmt.Errorf("begin pull backup: %w", err)
	}
	// This session now holds the domain's one backup job: no other session of
	// this disk is live, so a crashed one's scratch can go.
	sweepStaleScratch(sessScratchDir, tag, filepath.Dir(scratch))

	s := &BackupSession{
		c: c, dom: dom, size: size, incremental: parentCheckpoint != "",
		export: diskTarget, scratch: scratch, socket: socket,
	}

	conn, err := net.DialTimeout("unix", socket, 15*time.Second)
	if err != nil {
		s.abort()
		return nil, fmt.Errorf("dial nbd %s: %w", socket, err)
	}
	n := &nbdConn{c: conn}
	if err := n.handshake(); err != nil {
		conn.Close()
		s.abort()
		return nil, fmt.Errorf("nbd handshake: %w", err)
	}
	if err := n.negotiateStructuredReply(); err != nil {
		conn.Close()
		s.abort()
		return nil, err
	}
	ctxName := "base:allocation"
	if s.incremental {
		ctxName = "qemu:dirty-bitmap:" + exportBitmapName
	}
	ctxID, err := n.setMetaContext(diskTarget, ctxName)
	if err != nil {
		conn.Close()
		s.abort()
		return nil, err
	}
	if err := n.optGo(diskTarget); err != nil {
		conn.Close()
		s.abort()
		return nil, err
	}
	s.nbd = n
	s.ctxID = ctxID
	return s, nil
}

// Size is the guest-visible disk size in bytes.
func (s *BackupSession) Size() int64 { return s.size }

// Incremental reports whether this session diffs against a parent
// checkpoint (true) or reads allocation (false).
func (s *BackupSession) Incremental() bool { return s.incremental }

// ChangedExtents returns the (offset,length) regions the backup must read:
// dirty regions for an incremental, allocated non-zero regions for a full.
// Holes / known-zero regions are excluded so a sparse guest disk is cheap
// to back up.
func (s *BackupSession) ChangedExtents() ([][2]int64, error) {
	s.nbd.c.SetDeadline(time.Now().Add(5 * time.Minute))
	exts, err := s.nbd.queryExtents(s.ctxID, s.size)
	if err != nil {
		return nil, fmt.Errorf("query extents: %w", err)
	}
	var out [][2]int64
	for _, e := range exts {
		var want bool
		if s.incremental {
			want = e.flags&nbdStateDirty != 0
		} else {
			// Full: read everything not a hole and not known-zero.
			want = e.flags&(nbdStateHole|nbdStateZero) == 0
		}
		if want && e.length > 0 {
			out = append(out, [2]int64{e.off, e.length})
		}
	}
	return out, nil
}

// ReadAt fills p with guest-visible bytes at offset (holes read as zero).
func (s *BackupSession) ReadAt(p []byte, offset int64) (int, error) {
	s.nbd.c.SetDeadline(time.Now().Add(5 * time.Minute))
	if err := s.nbd.readAt(p, offset); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends the NBD connection and the qemu backup job and removes the
// scratch file. Safe to call once.
func (s *BackupSession) Close() error {
	if s.nbd != nil {
		s.nbd.disconnect()
		s.nbd = nil
	}
	s.abort()
	return nil
}

func (s *BackupSession) abort() {
	_ = s.c.virt.DomainAbortJob(s.dom)
	removeBackupSessionPaths(s.scratch, s.socket)
}

// qemuOwner is the uid and gid qemu runs as for a domain, when known.
type qemuOwner struct {
	UID, GID int
	Known    bool
}

// domainSeclabels is the part of a live domain's XML that says which user
// qemu runs as: libvirt's DAC security label.
type domainSeclabels struct {
	Seclabels []struct {
		Model string `xml:"model,attr"`
		Label string `xml:"label"`
	} `xml:"seclabel"`
}

// lookupUserID and lookupGroupID resolve a user or group name to its numeric
// id (os/user; pure Go reads /etc/passwd and /etc/group). Variables so a test
// need not depend on the host's databases.
var (
	lookupUserID = func(name string) (string, error) {
		u, err := user.Lookup(name)
		if err != nil {
			return "", err
		}
		return u.Uid, nil
	}
	lookupGroupID = func(name string) (string, error) {
		g, err := user.LookupGroup(name)
		if err != nil {
			return "", err
		}
		return g.Gid, nil
	}
)

// dacID reads one half of a DAC label: "+N" is a number, as libvirt writes a
// dynamic label; anything else is a number or a name, as a static label may
// say, resolved through lookup.
func dacID(s string, lookup func(string) (string, error)) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if rest, ok := strings.CutPrefix(s, "+"); ok {
		n, err := strconv.Atoi(rest)
		return n, err == nil && n >= 0
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, n >= 0
	}
	id, err := lookup(s)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(id)
	return n, err == nil && n >= 0
}

// domainQEMUOwner reads the uid:gid qemu runs as from the live domain XML's
// DAC label ("+64055:+993", or "libvirt-qemu:kvm" in a static label). A label
// it cannot resolve, or none, is unknown, and the session falls back to a
// sticky directory.
func domainQEMUOwner(domXML string) qemuOwner {
	var d domainSeclabels
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return qemuOwner{}
	}
	for _, sl := range d.Seclabels {
		if sl.Model != "dac" {
			continue
		}
		u, g, ok := strings.Cut(strings.TrimSpace(sl.Label), ":")
		if !ok {
			return qemuOwner{}
		}
		uid, uok := dacID(u, lookupUserID)
		gid, gok := dacID(g, lookupGroupID)
		if !uok || !gok {
			return qemuOwner{}
		}
		return qemuOwner{UID: uid, GID: gid, Known: true}
	}
	return qemuOwner{}
}

const (
	// backupRootMode is backup-scratch/ and backup-sock/: root's, searchable
	// by qemu, listable and writable by nobody else.
	backupRootMode fs.FileMode = 0o711
	// backupSessionMode is a session directory owned by qemu's uid.
	backupSessionMode fs.FileMode = 0o700
	// backupSessionFallbackMode is a session directory whose qemu user is not
	// known, or would not take the chown: anyone may create in it (qemu
	// must), nobody but root may list it, and the sticky bit keeps one user
	// from removing or renaming another's entry. It is safe only because its
	// name is unguessable and its root is 0711: nobody else can find it.
	backupSessionFallbackMode = fs.ModeSticky | 0o733
)

// sessionSuffix is a session directory's unguessable part: 16 hex characters
// (randid, 64 bits from crypto/rand). A variable so a test can make two
// sessions collide.
var sessionSuffix = randid.New

// backupOwnerOf is the uid owning a path, from its Lstat. A variable so a test,
// which is not root, can stand for root and for a planted directory.
var backupOwnerOf = func(_ string, fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// checkBackupRoot reports why root is not what a session may make its
// directory in: a real directory (not a symlink), owned by root, exactly 0711.
func checkBackupRoot(root string) error {
	fi, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", root)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (%s)", root, fi.Mode().Type())
	}
	if uid, ok := backupOwnerOf(root, fi); !ok || uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not root", root, uid)
	}
	if m := fi.Mode() & (fs.ModePerm | fs.ModeSticky | fs.ModeSetuid | fs.ModeSetgid); m != backupRootMode {
		return fmt.Errorf("%s is %04o, not %04o", root, m, backupRootMode)
	}
	return nil
}

// ensureBackupRoot makes root a root-owned, real 0711 directory. Root's own
// directory with another mode (an earlier build's 0777) is narrowed in place.
// Anything else — another user's directory, a symlink, a file (which no chmod
// makes a directory) — is renamed aside to .<name>.aside-<time>-<random>
// beside it, kept with everything in it, logged, and made afresh: never
// deleted, and never a reason to refuse the backup.
func ensureBackupRoot(root string) error {
	if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(root), err)
	}
	bad := checkBackupRoot(root)
	if bad == nil {
		return nil
	}
	// Root's own real directory with the wrong mode — an earlier build left
	// it 0777 — is narrowed in place: no session ever adopts an entry already
	// in it (random names, exclusive mkdir), so nothing in it needs setting
	// aside, and the earlier build's stale <tag>.scratch is swept by the next
	// session of its disk (sweepStaleScratch).
	if fi, err := os.Lstat(root); err == nil && fi.IsDir() && fi.Mode()&fs.ModeSymlink == 0 {
		if uid, ok := backupOwnerOf(root, fi); ok && uid == 0 {
			if err := os.Chmod(root, backupRootMode); err != nil {
				return fmt.Errorf("chmod %s: %w", root, err)
			}
			slog.Info("backup session: narrowed a backup directory to its mode", "path", root,
				"was", fmt.Sprintf("%04o", fi.Mode()&(fs.ModePerm|fs.ModeSticky|fs.ModeSetuid|fs.ModeSetgid)))
			return checkBackupRoot(root)
		}
	}
	if !errors.Is(bad, fs.ErrNotExist) {
		aside := filepath.Join(filepath.Dir(root),
			"."+filepath.Base(root)+".aside-"+time.Now().UTC().Format("20060102T150405Z")+"-"+randid.New())
		if err := os.Rename(root, aside); err != nil {
			return fmt.Errorf("set aside %s (%v): %w", root, bad, err)
		}
		slog.Warn("backup session: a backup directory was not root's own 0711 directory; it is set aside, with everything in it, and made afresh",
			"path", root, "set_aside_as", aside, "reason", bad.Error())
	}
	if err := os.Mkdir(root, backupRootMode); err != nil {
		return fmt.Errorf("mkdir %s: %w", root, err)
	}
	if err := os.Chmod(root, backupRootMode); err != nil {
		return fmt.Errorf("chmod %s: %w", root, err)
	}
	return checkBackupRoot(root)
}

// PrepareBackupRoots narrows the backup session roots once at daemon start,
// as the first session would: an upgraded host that runs no backup does not
// keep an earlier build's 0777 directories. Best effort: a failure is logged
// and the next session tries again.
func PrepareBackupRoots() { prepareBackupRoots(sessScratchDir, sessSocketDir) }

func prepareBackupRoots(roots ...string) {
	for _, root := range roots {
		if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
			continue // made by the first session
		}
		if err := ensureBackupRoot(root); err != nil {
			slog.Warn("backup session: could not prepare a backup directory at start; the next backup tries again",
				"path", root, "error", err)
		}
	}
}

// makeSessionDir makes a NEW directory named prefix+suffix in root — a mkdir
// that fails if the name exists, so nothing already there is ever adopted;
// a taken name is skipped for another suffix — and gives it to qemu's user.
func makeSessionDir(root, prefix string, owner qemuOwner) (string, error) {
	var dir string
	for attempt := 0; ; attempt++ {
		dir = filepath.Join(root, prefix+sessionSuffix())
		err := os.Mkdir(dir, backupSessionMode)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || attempt >= 8 {
			return "", fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	mode := backupSessionFallbackMode
	if owner.Known {
		if cerr := lchown(dir, owner.UID, owner.GID); cerr != nil {
			slog.Warn("backup session: could not give the session directory to qemu's user; it is sticky, in an unlistable directory, instead",
				"dir", dir, "uid", owner.UID, "gid", owner.GID, "error", cerr)
		} else {
			mode = backupSessionMode
		}
	}
	if err := os.Chmod(dir, mode); err != nil {
		_ = os.Remove(dir)
		return "", fmt.Errorf("chmod %s: %w", dir, err)
	}
	return dir, nil
}

// prepareBackupSessionPaths makes the scratch and NBD socket paths of one
// pull-mode backup session of tag (<domain>-<disk target>) and returns them.
//
// qemu (as its own user, AppArmor-confined) creates the scratch image and
// binds the socket; the daemon (root) dials the socket. Earlier builds put both
// directly in scratchRoot and sockRoot and chmod-ed those 0777 every session:
// world-writable with no sticky bit, so any local user could replace the socket
// the daemon reads the guest's disk from. Now:
//
//   - scratchRoot and sockRoot must be root-owned, real 0711 directories;
//     one that is not is set aside and made afresh (ensureBackupRoot);
//   - every session makes a NEW directory in each, never an existing one:
//     <scratchRoot>/<tag>.<16 hex> and <sockRoot>/<16 hex>, given to qemu's
//     uid:gid and 0700 — or, when that user is not known or the chown is
//     refused, 01733, which is safe only because the name is unguessable and
//     the root unlistable;
//   - the scratch is <dir>/scratch and the socket <dir>/nbd. The socket's
//     directory is the suffix alone, so its path does not depend on the VM's
//     name: len("/var/lib/litevirt/backup-sock") 29 + "/" 1 + 16 + "/nbd" 4
//     = 50 bytes, under the 107-byte limit for any VM (the old
//     <sockRoot>/<tag>.sock was 35 + len(tag)).
//
// On failure, what this made is removed again.
func prepareBackupSessionPaths(scratchRoot, sockRoot, tag string, owner qemuOwner) (scratch, socket string, err error) {
	if err := ensureBackupRoot(scratchRoot); err != nil {
		return "", "", err
	}
	sd, err := makeSessionDir(scratchRoot, tag+".", owner)
	if err != nil {
		return "", "", err
	}
	if err := ensureBackupRoot(sockRoot); err != nil {
		_ = os.Remove(sd)
		return "", "", err
	}
	kd, err := makeSessionDir(sockRoot, "", owner)
	if err != nil {
		_ = os.Remove(sd)
		return "", "", err
	}
	return filepath.Join(sd, "scratch"), filepath.Join(kd, "nbd"), nil
}

// removeBackupSessionPaths removes a session's scratch and socket and then its
// two session directories, each only when empty.
func removeBackupSessionPaths(scratch, socket string) {
	for _, p := range []string{scratch, socket} {
		if p == "" {
			continue
		}
		_ = os.Remove(p)
		_ = os.Remove(filepath.Dir(p)) // rmdir: only when empty
	}
}

// sweepStaleScratch removes what crashed sessions of tag's disk left in root:
// an earlier build's <tag>.scratch file, and the scratch file of every
// <tag>.<16 hex> session directory but keep, then that directory when it is
// empty. The caller holds the domain's backup job —
// libvirt runs one per domain — so no other session of this disk is live.
// Nothing else is touched: another disk's directories, names that are not a
// session's, symlinks, and anything in a session directory but its scratch.
func sweepStaleScratch(root, tag, keep string) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	// The earlier build's scratch of this disk, <tag>.scratch directly in the
	// root: its own name, which it removed at every session's start.
	legacy := filepath.Join(root, tag+".scratch")
	if fi, err := os.Lstat(legacy); err == nil && fi.Mode().IsRegular() {
		if os.Remove(legacy) == nil {
			slog.Info("backup session: removed an earlier build's scratch", "path", legacy)
		}
	}
	for _, e := range ents {
		name := e.Name()
		i := strings.LastIndexByte(name, '.')
		if i < 0 || name[:i] != tag || !isSessionSuffix(name[i+1:]) {
			continue
		}
		dir := filepath.Join(root, name)
		if dir == keep {
			continue
		}
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(dir, "scratch"))
		if err := os.Remove(dir); err == nil {
			slog.Info("backup session: removed a crashed session's scratch", "dir", dir)
		}
	}
}

// isSessionSuffix reports a sessionSuffix: 16 lowercase hex characters.
func isSessionSuffix(s string) bool {
	if len(s) != 2*randid.Bytes {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// lchown is os.Lchown; a variable so a test, which is not root, can see the
// owner a session directory is given.
var lchown = os.Lchown
