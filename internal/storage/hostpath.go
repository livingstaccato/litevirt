package storage

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// A pool's configuration can name places on the host's own filesystem. The
// daemon runs as root and writes there — disk files, uploaded content, an NFS
// mount laid over the directory — so whoever chooses the path chooses where
// root writes. These helpers say which parts of a Config are such paths, and
// refuse the ones no pool may ever use.

// HostPaths is what a pool configuration names on the host itself.
type HostPaths struct {
	// WriteRoots are directories the pool creates files in, or mounts over.
	WriteRoots []string
	// ReadPaths are host files the pool's tools read (Ceph conf/keyring). A
	// config file is not inert: a ceph.conf can name a log file to write.
	ReadPaths []string
	// MountOptions is set when the config passes its own NFS mount options,
	// which reach mount(8) verbatim.
	MountOptions bool
	// Network names the remote storage a network-backed pool (nfs, ceph,
	// iscsi) attaches. Its server, not the request, decides what the daemon
	// then finds there — files, symlinks, block devices — and the daemon
	// reads and writes it as root, so attaching one is a host-level act even
	// when the pool names no local directory.
	Network string
}

// Any reports whether the configuration names anything on the host.
func (h HostPaths) Any() bool {
	return len(h.WriteRoots) > 0 || len(h.ReadPaths) > 0 || h.MountOptions || h.Network != ""
}

// Describe names what was found, for an operator-facing refusal.
func (h HostPaths) Describe() string {
	var parts []string
	for _, p := range h.WriteRoots {
		parts = append(parts, fmt.Sprintf("directory %q", p))
	}
	for _, p := range h.ReadPaths {
		parts = append(parts, fmt.Sprintf("file %q", p))
	}
	if h.MountOptions {
		parts = append(parts, "custom NFS mount options")
	}
	if h.Network != "" {
		parts = append(parts, fmt.Sprintf("network storage %q, whose server controls what the daemon reads and writes", h.Network))
	}
	return strings.Join(parts, ", ")
}

// HostPathsOf returns the host paths a pool configuration names. A local pool
// with no Target names none: it lives under the daemon's own data directory.
// Every network-backed pool (nfs, ceph, iscsi) names its remote storage, with
// or without a Target.
func HostPathsOf(cfg Config) HostPaths {
	var h HostPaths
	switch strings.ToLower(cfg.Driver) {
	case "", "local":
		if cfg.Target != "" {
			h.WriteRoots = append(h.WriteRoots, cfg.Target)
		}
	case "dir":
		// Target is mandatory for dir; an empty one is refused by New.
		h.WriteRoots = append(h.WriteRoots, cfg.Target)
	case "nfs":
		h.Network = cfg.Source
		if cfg.Target != "" {
			h.WriteRoots = append(h.WriteRoots, cfg.Target)
		}
		if _, ok := cfg.Options["options"]; ok {
			h.MountOptions = true
		}
	case "iscsi":
		h.Network = cfg.Source
	case "btrfs":
		h.WriteRoots = append(h.WriteRoots, cfg.Source)
	case "ceph":
		h.Network = cfg.Source
		for _, k := range []string{"conf", "keyring"} {
			if v := cfg.Options[k]; v != "" {
				h.ReadPaths = append(h.ReadPaths, v)
			}
		}
	}
	return h
}

// systemRoots are directories no pool may write into, or below. A file the
// daemon writes as root into any of them can become code execution (cron.d,
// profile.d, systemd units, ld.so.preload, authorized_keys) or can corrupt the
// host. This is a backstop, not the boundary: the boundary is that only a
// cluster-root caller may name a host path at all. It is not exhaustive —
// /opt, /var/log, /var/tmp and /srv are left to the admin who names them — and
// it is judged when the pool is created or used, not continuously: a symlink
// or bind mount made afterwards by someone with root on the host is not seen
// (EvalSymlinks does not see mounts at all). Network pools, whose server
// could otherwise plant such links, are mounted nosymfollow.
var systemRoots = []string{
	"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/libx32",
	"/proc", "/root", "/run", "/sbin", "/sys", "/usr",
	"/var/lib/libvirt", "/var/run", "/var/spool",
}

// litevirtVarLibPrefix refuses /var/lib/litevirt and every /var/lib/litevirt-*
// (an old or side-by-side install's state) except the configured data
// directory's own pool areas.
const litevirtVarLibPrefix = "litevirt"

// dataDirPoolAreas are the only parts of the daemon's data directory a pool
// may live in: disks/ is the default local pool, mounts/ holds the NFS mounts
// the daemon makes itself, pools/<name> is a target-less local pool's own
// directory. Everything else there is the daemon's own state
// (state.db, pki, images, the audit assertion file, …).
var dataDirPoolAreas = []string{"disks", "mounts", "pools"}

// CheckWriteRoot refuses a directory no pool may write into: a relative path,
// the filesystem root, anything under a system directory, the daemon's PKI
// directory, its data directory outside disks/ and mounts/, or any parent of
// those two directories. Symlinks are resolved first (through the deepest part
// of the path that exists), and both the path as written and the path it
// resolves to must pass, so a link planted at an innocent name cannot reach a
// refused directory.
func CheckWriteRoot(p, dataDir, pkiDir string) error {
	if p == "" {
		return errors.New("an empty path names no directory")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%q is not an absolute path", p)
	}
	for _, cand := range pathForms(p) {
		if cand == "/" {
			return fmt.Errorf("%q is the filesystem root", p)
		}
		for _, root := range systemRoots {
			for _, r := range pathForms(root) {
				if within(r, cand) {
					return fmt.Errorf("%q is under %s, a system directory", p, root)
				}
			}
		}
		if underLitevirtVarLib(cand) && !inAnyPoolArea(dataDir, cand) {
			return fmt.Errorf("%q is under /var/lib/%s*, litevirt state", p, litevirtVarLibPrefix)
		}
		if pkiDir != "" {
			for _, d := range pathForms(pkiDir) {
				if within(d, cand) || within(cand, d) {
					return fmt.Errorf("%q overlaps the daemon's PKI directory %s", p, pkiDir)
				}
			}
		}
		if dataDir != "" {
			for _, d := range pathForms(dataDir) {
				if within(cand, d) {
					return fmt.Errorf("%q is the daemon's data directory %s or contains it", p, dataDir)
				}
				if within(d, cand) && !inPoolArea(d, cand) {
					return fmt.Errorf("%q is inside the daemon's data directory %s; only its disks/ and mounts/ hold pools", p, dataDir)
				}
			}
		}
	}
	return nil
}

// CheckConfig refuses a Source or option that is not in its driver's strict
// form (ValidateSource), applies CheckWriteRoot to every directory the
// configuration writes into, and refuses an NFS source that would derive a
// mount directory outside <data_dir>/mounts.
func CheckConfig(cfg Config, dataDir, pkiDir string) error {
	if err := ValidateSource(cfg); err != nil {
		return err
	}
	for _, p := range HostPathsOf(cfg).WriteRoots {
		if err := CheckWriteRoot(p, dataDir, pkiDir); err != nil {
			return err
		}
	}
	if strings.EqualFold(cfg.Driver, "nfs") && cfg.Target == "" {
		switch NFSMountName(cfg.Source) {
		case "", ".", "..":
			return fmt.Errorf("nfs source %q is not server:/export", cfg.Source)
		}
	}
	return nil
}

// NFSMountName is the directory under <data_dir>/mounts that an NFS pool with
// no Target is mounted on.
func NFSMountName(source string) string {
	return strings.NewReplacer("/", "_", ":", "_").Replace(source)
}

// pathForms returns p cleaned, plus what it resolves to when that differs.
func pathForms(p string) []string {
	clean := filepath.Clean(p)
	out := []string{clean}
	if r := resolveExisting(clean); r != clean {
		out = append(out, r)
	}
	return out
}

// resolveExisting resolves symlinks through the deepest ancestor of p that
// exists and re-attaches the rest, so a path a driver is about to create is
// judged by where it would really land.
func resolveExisting(p string) string {
	cur, rest := p, ""
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			if rest == "" {
				return r
			}
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// within reports whether path is dir or below it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func inPoolArea(dataDir, p string) bool {
	for _, a := range dataDirPoolAreas {
		if within(filepath.Join(dataDir, a), p) {
			return true
		}
	}
	return false
}

func underLitevirtVarLib(p string) bool {
	rel, err := filepath.Rel("/var/lib", p)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	first, _, _ := strings.Cut(rel, string(filepath.Separator))
	return strings.HasPrefix(first, litevirtVarLibPrefix)
}

func inAnyPoolArea(dataDir, p string) bool {
	if dataDir == "" {
		return false
	}
	for _, d := range pathForms(dataDir) {
		if inPoolArea(d, p) {
			return true
		}
	}
	return false
}

// The strict forms a pool's Source and identifying options must take. Each
// reaches a tool's argv (mount, rbd, zfs, lvs, iscsiadm, btrfs) as a positional
// argument or option value; a value that starts with "-" would be parsed as an
// option, which would let a caller pass the very options that need
// storage.hostpath (an alternate config, keyring or log file). The drivers
// also put "--" before positional arguments; this is the first line.
var (
	nfsSourceRe   = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\]):/[^\s,]*$`)
	cephNameRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	zfsDatasetRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]*(/[A-Za-z0-9_][A-Za-z0-9_.:-]*)*$`)
	lvmNameRe     = regexp.MustCompile(`^[A-Za-z0-9_+.][A-Za-z0-9_+.-]*$`)
	iscsiTargetRe = regexp.MustCompile(`^(?i:iqn|eui|naa)\.[A-Za-z0-9.:_-]+$`)
	iscsiPortalRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$`)
)

// ValidateSource refuses a Source, or a driver option that names an object,
// that is not in its driver's strict form.
func ValidateSource(cfg Config) error {
	src := cfg.Source
	bad := func(what, v, want string) error {
		return fmt.Errorf("%s %q is not %s", what, v, want)
	}
	switch strings.ToLower(cfg.Driver) {
	case "", "local", "dir":
		if src != "" {
			return fmt.Errorf("a %s pool takes no source (got %q)", strings.ToLower(cfg.Driver), src)
		}
	case "nfs":
		if !nfsSourceRe.MatchString(src) {
			return bad("nfs source", src, "server:/export")
		}
	case "ceph":
		if !cephNameRe.MatchString(src) {
			return bad("ceph pool", src, "a pool name")
		}
		if id := cfg.Options["id"]; id != "" && !cephNameRe.MatchString(id) {
			return bad("ceph id", id, "a client name")
		}
		for _, k := range []string{"conf", "keyring"} {
			if v := cfg.Options[k]; v != "" && !filepath.IsAbs(v) {
				return bad("ceph "+k, v, "an absolute path")
			}
		}
	case "zfs":
		if !zfsDatasetRe.MatchString(src) {
			return bad("zfs dataset", src, "pool/dataset")
		}
	case "btrfs":
		if !filepath.IsAbs(src) {
			return bad("btrfs source", src, "an absolute path")
		}
	case "lvm-thin", "lvmthin":
		if !lvmNameRe.MatchString(src) {
			return bad("volume group", src, "a volume group name")
		}
		if tp := cfg.Options["thinpool"]; tp != "" && !lvmNameRe.MatchString(tp) {
			return bad("thin pool", tp, "a logical volume name")
		}
	case "iscsi":
		if !iscsiTargetRe.MatchString(src) {
			return bad("iscsi target", src, "an iqn./eui./naa. name")
		}
		if pt := cfg.Options["portal"]; pt != "" && !iscsiPortalRe.MatchString(pt) {
			return bad("iscsi portal", pt, "host[:port]")
		}
	}
	return nil
}
