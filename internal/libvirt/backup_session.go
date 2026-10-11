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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
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
		return nil, err
	}
	var cpXML golibvirt.OptString
	if newCheckpoint != "" {
		doc, derr := buildCheckpointXML(newCheckpoint, []string{diskTarget})
		if derr != nil {
			return nil, derr
		}
		cpXML = golibvirt.OptString{doc}
	}
	if err := c.virt.DomainBackupBegin(dom, backupDoc, cpXML, 0); err != nil {
		removeBackupSessionPaths(scratch, socket)
		return nil, fmt.Errorf("begin pull backup: %w", err)
	}

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
// qemu runs as: libvirt's DAC security label, "+<uid>:+<gid>".
type domainSeclabels struct {
	Seclabels []struct {
		Model string `xml:"model,attr"`
		Label string `xml:"label"`
	} `xml:"seclabel"`
}

// domainQEMUOwner reads the uid:gid qemu runs as from the live domain XML's
// DAC label. A label it cannot read as two numbers (names, none at all) is
// unknown, and the session falls back to a sticky directory.
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
		uid, uerr := strconv.Atoi(strings.TrimPrefix(u, "+"))
		gid, gerr := strconv.Atoi(strings.TrimPrefix(g, "+"))
		if uerr != nil || gerr != nil || uid < 0 || gid < 0 {
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
	// known: anyone may create in it (qemu must), nobody but root may list
	// it, and the sticky bit keeps one user from removing or renaming
	// another's entry. Its parent is 0711, so its name cannot be listed.
	backupSessionFallbackMode = fs.ModeSticky | 0o733
)

// prepareBackupSessionPaths makes the scratch and NBD socket paths of one
// pull-mode backup session of tag (<domain>-<disk target>) and returns them.
//
// qemu (as its own user, AppArmor-confined) creates the scratch image and
// binds the socket; the daemon (root) dials the socket. Earlier builds put both
// directly in scratchRoot and sockRoot and chmod-ed those 0777 every session:
// world-writable with no sticky bit, so any local user could replace the socket
// the daemon reads the guest's disk from. Now:
//
//   - scratchRoot and sockRoot are 0711, root's — narrowed from 0777 on the
//     first session after an upgrade, as every session used to chmod them;
//   - each holds one directory per session, named tag (so a crashed session's
//     leftovers are found and removed, as before), owned by qemu's uid:gid
//     and 0700; and when qemu's user is not known, or the chown is refused,
//     01733 instead (never 0777);
//   - the scratch is <scratchRoot>/<tag>/scratch and the socket
//     <sockRoot>/<tag>/nbd: never longer than the old <sockRoot>/<tag>.sock,
//     so no socket path newly exceeds the 107-byte limit.
//
// An entry at a session directory's name that is not a real directory (one
// planted while the parent was 0777) is refused, never followed. The
// earlier build's own names (<tag>.scratch, <tag>.sock), which it removed at
// the start of every session, are removed once more; nothing else is.
func prepareBackupSessionPaths(scratchRoot, sockRoot, tag string, owner qemuOwner) (scratch, socket string, err error) {
	sessionDir := func(root, legacy string) (string, error) {
		if err := os.MkdirAll(root, backupRootMode); err != nil {
			return "", fmt.Errorf("mkdir %s: %w", root, err)
		}
		if err := os.Chmod(root, backupRootMode); err != nil {
			return "", fmt.Errorf("chmod %s: %w", root, err)
		}
		_ = os.Remove(filepath.Join(root, legacy))
		dir := filepath.Join(root, tag)
		if err := os.Mkdir(dir, backupSessionMode); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("mkdir %s: %w", dir, err)
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			return "", err
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("backup session directory %s is not a directory (%s); remove it", dir, fi.Mode().Type())
		}
		mode := backupSessionFallbackMode
		if owner.Known {
			if cerr := lchown(dir, owner.UID, owner.GID); cerr != nil {
				slog.Warn("backup session: could not give the session directory to qemu's user; it is sticky and unlistable instead",
					"dir", dir, "uid", owner.UID, "gid", owner.GID, "error", cerr)
			} else {
				mode = backupSessionMode
			}
		}
		if err := os.Chmod(dir, mode); err != nil {
			return "", fmt.Errorf("chmod %s: %w", dir, err)
		}
		return dir, nil
	}
	sd, err := sessionDir(scratchRoot, tag+".scratch")
	if err != nil {
		return "", "", err
	}
	kd, err := sessionDir(sockRoot, tag+".sock")
	if err != nil {
		return "", "", err
	}
	scratch, socket = filepath.Join(sd, "scratch"), filepath.Join(kd, "nbd")
	// qemu creates these itself; clear stale leftovers from a crashed run.
	_ = os.Remove(scratch)
	_ = os.Remove(socket)
	return scratch, socket, nil
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

// lchown is os.Lchown; a variable so a test, which is not root, can see the
// owner a session directory is given.
var lchown = os.Lchown
