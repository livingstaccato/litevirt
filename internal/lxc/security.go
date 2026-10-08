package lxc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Container security: confinement, user-namespace mapping and the pids limit.
//
// All of it lives in the container's LXC config, inside a block litevirt
// owns, so it travels with the container through export, import, migrate,
// backup and clone exactly as the rest of the config does. A container with
// no block is configured as an earlier build left it (legacy confinement,
// privileged), and nothing here rewrites it until an operator converts it.

// Confinement names a container's AppArmor/seccomp/capability settings.
const (
	// ConfinementDefault is LXC's generated AppArmor profile with nesting off,
	// LXC's common seccomp policy and the standard capability drop list,
	// written explicitly rather than left to a template or include.
	ConfinementDefault = "default"
	// ConfinementLegacy is what earlier builds wrote: the generated profile
	// with nesting allowed, and whatever seccomp policy and drop list the
	// template's includes supply. Admin-only on create and convert.
	ConfinementLegacy = "legacy"
)

// capDropDefault is LXC's standard capability drop list (common.conf).
const capDropDefault = "mac_admin mac_override sys_time sys_module sys_rawio"

// IDMapSize is the id range every unprivileged container gets: uids and gids
// 0..65535 inside map to Base..Base+65535 on the host.
const IDMapSize = 65536

// IDMap is an unprivileged container's id mapping.
type IDMap struct {
	Base int64
	Size int64
}

// Security is a container's security settings as its config states them.
type Security struct {
	Confinement   string // ConfinementDefault or ConfinementLegacy
	IDMap         *IDMap // nil = privileged
	IDMappedMount bool   // the rootfs is an idmapped mount; its files are not shifted
	Converting    bool   // an lv ct convert was interrupted; start refuses
	// ConvertTo is the target an interrupted convert recorded (with
	// Converting): the next convert finishes to it.
	ConvertTo *ConvertOpts
}

// Securer is the optional runtime capability behind container security.
type Securer interface {
	Security(name string) (Security, error)
	Convert(ctx context.Context, name string, to ConvertOpts) error
}

var _ Securer = (*LxcRunner)(nil)

// Privileged reports whether the container runs without a user namespace.
func (s Security) Privileged() bool { return s.IDMap == nil }

// The LXC config files the default confinement names. Variables so a test can
// stand temporary files in for them.
var (
	lxcCommonSeccomp = "/usr/share/lxc/config/common.seccomp"
	lxcUsernsConf    = "/usr/share/lxc/config/userns.conf"
)

func setLXCConfigPathsForTest(seccomp, userns string) (restore func()) {
	os1, os2 := lxcCommonSeccomp, lxcUsernsConf
	lxcCommonSeccomp, lxcUsernsConf = seccomp, userns
	return func() { lxcCommonSeccomp, lxcUsernsConf = os1, os2 }
}

const (
	secBlockBegin = "# litevirt security begin"
	secBlockEnd   = "# litevirt security end"
	// convertMarkerFile marks a container whose conversion has not finished.
	convertMarkerFile = "litevirt-converting"
	pidsMaxKey        = "lxc.cgroup2.pids.max"
)

// renderSecurityBlock is the litevirt-owned block for a confinement and an
// optional id map. An unstated confinement ("") on a privileged container
// renders nothing: the config an earlier build wrote, left exactly as it is
// (a recreate of such a container). Legacy stated explicitly — an admin's
// create or convert — writes today's lines (the generated profile with
// nesting allowed) in place of any others.
func renderSecurityBlock(confinement string, idmap *IDMap, idmapped bool) string {
	if confinement == "" && idmap == nil {
		return ""
	}
	if confinement == "" {
		confinement = ConfinementLegacy
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s confinement=%s\n", secBlockBegin, confinement)
	if idmap != nil && fileExists(lxcUsernsConf) {
		// LXC's own unprivileged baseline. It resets the drop list, so it
		// comes before the default confinement's.
		fmt.Fprintf(&b, "lxc.include = %s\n", lxcUsernsConf)
	}
	b.WriteString("lxc.apparmor.profile = generated\n")
	if confinement == ConfinementDefault {
		b.WriteString("lxc.apparmor.allow_nesting = 0\n")
		if fileExists(lxcCommonSeccomp) {
			fmt.Fprintf(&b, "lxc.seccomp.profile = %s\n", lxcCommonSeccomp)
		}
		fmt.Fprintf(&b, "lxc.cap.drop = %s\n", capDropDefault)
	} else {
		b.WriteString("lxc.apparmor.allow_nesting = 1\n")
	}
	if idmap != nil {
		fmt.Fprintf(&b, "lxc.idmap = u 0 %d %d\n", idmap.Base, idmap.Size)
		fmt.Fprintf(&b, "lxc.idmap = g 0 %d %d\n", idmap.Base, idmap.Size)
		if idmapped {
			b.WriteString("lxc.rootfs.options = idmap=container\n")
		}
	}
	b.WriteString(secBlockEnd + "\n")
	return b.String()
}

// configKey returns the key of an "lxc.x = y" line, or "".
func configKey(line string) (key, val string) {
	k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
	if !ok {
		return "", ""
	}
	return strings.TrimSpace(k), strings.TrimSpace(v)
}

// withSecurityBlock returns cfg with block in place of any earlier one. When
// block is non-empty, the lines it decides are dropped from the rest of the
// config, so a template's or an earlier convert's setting cannot override it.
func withSecurityBlock(cfg, block string) string {
	var out []string
	in := false
	for _, line := range strings.Split(strings.TrimRight(cfg, "\n"), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, secBlockBegin):
			in = true
			continue
		case t == secBlockEnd:
			in = false
			continue
		case in:
			continue
		}
		if block != "" {
			k, v := configKey(line)
			switch {
			case k == "lxc.apparmor.profile", k == "lxc.apparmor.allow_nesting", k == "lxc.seccomp.profile", k == "lxc.idmap":
				continue
			case k == "lxc.rootfs.options" && strings.Contains(v, "idmap=container"):
				continue
			case k == "lxc.include" && v == lxcUsernsConf:
				continue
			}
		}
		out = append(out, line)
	}
	s := strings.Join(out, "\n") + "\n"
	return s + block
}

// ParseSecurity is parseSecurity for callers outside the package that hold a
// config rendering (the fleet harness's container fake).
func ParseSecurity(cfg string) Security { return parseSecurity(cfg) }

// SecurityConfig is the config block a container with this confinement and
// mapping gets (no idmapped mount), for the fleet harness's container fake.
func SecurityConfig(confinement string, idmap *IDMap) string {
	return renderSecurityBlock(confinement, idmap, false)
}

// parseSecurity reads Security from a config rendering.
func parseSecurity(cfg string) Security {
	sec := Security{Confinement: ConfinementLegacy}
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(t, secBlockBegin); ok {
			if c, ok := strings.CutPrefix(strings.TrimSpace(rest), "confinement="); ok && c == ConfinementDefault {
				sec.Confinement = ConfinementDefault
			}
			continue
		}
		k, v := configKey(line)
		switch k {
		case "lxc.idmap":
			f := strings.Fields(v)
			if len(f) == 4 && f[0] == "u" && f[1] == "0" {
				base, e1 := strconv.ParseInt(f[2], 10, 64)
				size, e2 := strconv.ParseInt(f[3], 10, 64)
				if e1 == nil && e2 == nil {
					sec.IDMap = &IDMap{Base: base, Size: size}
				}
			}
		case "lxc.rootfs.options":
			if strings.Contains(v, "idmap=container") {
				sec.IDMappedMount = true
			}
		}
	}
	return sec
}

// Security reads a container's security settings from its config.
func (r *LxcRunner) Security(name string) (Security, error) {
	cfg := filepath.Join(r.lxcpath(), name, "config")
	b, err := os.ReadFile(cfg)
	if err != nil {
		return Security{}, fmt.Errorf("read container config %s: %w", cfg, err)
	}
	sec := parseSecurity(string(b))
	if b, err := os.ReadFile(filepath.Join(r.lxcpath(), name, convertMarkerFile)); err == nil {
		sec.Converting = true
		var to ConvertOpts
		if json.Unmarshal(b, &to) == nil {
			sec.ConvertTo = &to
		}
	}
	return sec, nil
}

// useIDMappedMount decides whether a new mapping uses an idmapped rootfs
// mount on this host (IDMappedRootfs: "on", "off", or "auto"/"" to probe).
func (r *LxcRunner) useIDMappedMount() bool {
	switch r.IDMappedRootfs {
	case "on":
		return true
	case "off":
		return false
	}
	return r.idmappedProbe()
}

// idmappedProbe reports, once per runner, whether this host can give a
// container an idmapped rootfs: Linux 5.19 or later (idmapped mounts on the
// common filesystems), LXC 5 or later (lxc.rootfs.options idmap=container),
// and the container store on ext4, xfs or btrfs. Anything else — and any
// doubt — answers no, and the rootfs is shifted instead, which works on every
// host.
func (r *LxcRunner) idmappedProbe() bool {
	r.probeOnce.Do(func() {
		r.probeIDMapped = kernelAtLeast(5, 19) && lxcAtLeast(5) && idmappableFS(r.lxcpath())
	})
	return r.probeIDMapped
}

func kernelAtLeast(major, minor int) bool {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	return versionAtLeast(strings.TrimSpace(string(b)), major, minor)
}

func lxcAtLeast(major int) bool {
	out, err := exec.Command("lxc-start", "--version").Output()
	if err != nil {
		return false
	}
	return versionAtLeast(strings.TrimSpace(string(out)), major, 0)
}

// versionAtLeast compares the leading "major.minor" of v.
func versionAtLeast(v string, major, minor int) bool {
	f := strings.FieldsFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if len(f) == 0 {
		return false
	}
	ma, _ := strconv.Atoi(f[0])
	mi := 0
	if len(f) > 1 {
		mi, _ = strconv.Atoi(f[1])
	}
	return ma > major || (ma == major && mi >= minor)
}

// applySecurity rewrites the container's config with its security block and,
// for a mapping without an idmapped mount, shifts the rootfs from `from` (nil:
// host ids) into idmap. The block is written last: until then the config still
// states what the files on disk mostly are.
func (r *LxcRunner) applySecurity(name, confinement string, from, idmap *IDMap, idmapped bool) error {
	dir := filepath.Join(r.lxcpath(), name)
	if idmap != nil {
		if err := r.ensureRootSubIDs(idmap); err != nil {
			return err
		}
		if !idmapped {
			rootfs, err := r.RootFSPath(name)
			if err != nil {
				return err
			}
			if err := shiftTree(rootfs, from, idmap); err != nil {
				return fmt.Errorf("shift %s into ids %d-%d: %w", rootfs, idmap.Base, idmap.Base+idmap.Size-1, err)
			}
		}
	}
	cfgPath := filepath.Join(dir, "config")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read container config %s: %w", cfgPath, err)
	}
	cfg := withSecurityBlock(string(b), renderSecurityBlock(confinement, idmap, idmapped))
	return writeFileAtomic(cfgPath, []byte(cfg), 0o644)
}

// ConvertOpts is an lv ct convert target. A nil IDMap keeps the container's
// mapping, an empty Confinement keeps its confinement.
type ConvertOpts struct {
	IDMap       *IDMap
	Confinement string
}

// Convert changes a STOPPED container's security settings in place (the
// caller stops it). Moving into a new id range shifts every file's owner,
// ACL and file capability; the data itself is never copied or removed. A
// marker in the container directory records the target first and is removed
// last, so an interrupted convert leaves a container start refuses, and running
// the same convert again finishes it (the shift moves only ids still in the
// old range).
func (r *LxcRunner) Convert(ctx context.Context, name string, to ConvertOpts) error {
	sec, err := r.Security(name)
	if err != nil {
		return err
	}
	// An interrupted convert is finished to the target it recorded: part of
	// the rootfs is already there, and a different range would strand those
	// files outside the container's map. A different request is applied once
	// that is done (only a confinement can still change: a range is fixed).
	if sec.Converting && sec.ConvertTo != nil {
		rec := *sec.ConvertTo
		if err := r.convertTo(name, sec, rec); err != nil {
			return err
		}
		if to.Confinement != "" && to.Confinement != rec.Confinement {
			return r.Convert(ctx, name, ConvertOpts{Confinement: to.Confinement})
		}
		return nil
	}
	return r.convertTo(name, sec, to)
}

func (r *LxcRunner) convertTo(name string, sec Security, to ConvertOpts) error {
	dir := filepath.Join(r.lxcpath(), name)
	marker, _ := json.Marshal(to)
	if err := os.WriteFile(filepath.Join(dir, convertMarkerFile), marker, 0o600); err != nil {
		return fmt.Errorf("mark %s converting: %w", name, err)
	}
	confinement := to.Confinement
	if confinement == "" {
		confinement = sec.Confinement
	}
	idmap, idmapped, from := sec.IDMap, sec.IDMappedMount, (*IDMap)(nil)
	if to.IDMap != nil {
		idmap = to.IDMap
		// A shifted rootfs stays shifted (its files are owned in the old
		// range); an unshifted one (privileged, or idmapped) may be mapped
		// by the mount where the host supports it.
		shifted := sec.IDMap != nil && !sec.IDMappedMount
		idmapped = !shifted && r.useIDMappedMount()
		if shifted {
			from = sec.IDMap
		}
	}
	if err := r.applySecurity(name, confinement, from, idmap, idmapped && idmap != nil); err != nil {
		return err
	}
	if err := r.secureContainerDir(name); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, convertMarkerFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// prepareStart readies a container's config for lxc-start: a conversion that
// did not finish is refused; a rootfs mapped by an idmapped mount on a host
// that cannot make one (a migrate from a host that could) is shifted instead;
// and a container whose config sets no pids.max gets the configured default.
// This is the "next restart" at which an existing container takes a new
// default.
func (r *LxcRunner) prepareStart(name string) error {
	sec, err := r.Security(name)
	if err != nil {
		return err
	}
	if sec.Converting {
		return fmt.Errorf("container %q has an unfinished conversion; run the same lv ct convert again to finish it before starting", name)
	}
	// LXC refuses an unprivileged container whose range lies outside root's
	// subordinate ranges (when the host hands them out): ensured on every
	// start, so a container this host never created starts too.
	if sec.IDMap != nil {
		if err := r.ensureRootSubIDs(sec.IDMap); err != nil {
			return err
		}
	}
	if sec.IDMap != nil && sec.IDMappedMount && !r.useIDMappedMount() {
		if err := r.applySecurity(name, sec.Confinement, nil, sec.IDMap, false); err != nil {
			return fmt.Errorf("container %q: this host cannot mount its rootfs idmapped, and shifting it failed: %w", name, err)
		}
	}
	if r.DefaultPidsMax <= 0 {
		return nil
	}
	cfgPath := filepath.Join(r.lxcpath(), name, "config")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, _ := configKey(line); k == pidsMaxKey {
			return nil
		}
	}
	cfg := strings.TrimRight(string(b), "\n") + "\n" + fmt.Sprintf("%s = %d\n", pidsMaxKey, r.DefaultPidsMax)
	return writeFileAtomic(cfgPath, []byte(cfg), 0o644)
}

// writeFileAtomic replaces path with data via a temp file and a rename.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	tmp := path + ".litevirt-tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Subordinate ids. When the host hands out subordinate ranges (newuidmap is
// installed), LXC insists that root's mappings fall inside root's ranges in
// /etc/subuid and /etc/subgid. Variables so a test can use temp files.
var (
	subUIDPath    = "/etc/subuid"
	subGIDPath    = "/etc/subgid"
	subIDsWanted  = func() bool { _, err := exec.LookPath("newuidmap"); return err == nil }
	subIDsMu      sync.Mutex
	subIDsEnsured = map[int64]bool{}
	// subIDLockWait is how long an append waits for shadow's lock file.
	subIDLockWait = 10 * time.Second
)

// ensureRootSubIDs makes root's subordinate ranges cover idmap, appending one
// line "root:<base>:<span>" to /etc/subuid and /etc/subgid when no root range
// in the file covers it. The append is:
//   - append-only: every existing line, the daemon's or anyone's, is kept byte
//     for byte (a last line with no newline gets one before ours), and nothing
//     is ever rewritten or removed;
//   - idempotent: the covering check runs again under the lock, so concurrent
//     creates and daemons add the line once;
//   - locked the way shadow's tools lock the file (usermod, useradd): an
//     exclusive <file>.lock, created O_EXCL and removed afterwards; another
//     tool's lock is waited for, never removed;
//   - skipped on a host that hands out no ranges (no newuidmap) and has no
//     file.
func (r *LxcRunner) ensureRootSubIDs(idmap *IDMap) error {
	subIDsMu.Lock()
	defer subIDsMu.Unlock()
	if subIDsEnsured[idmap.Base] {
		return nil
	}
	span := r.SubIDSpan
	if span == nil || idmap.Base < span.Base || idmap.Base+idmap.Size > span.Base+span.Size {
		span = idmap
	}
	for _, p := range []string{subUIDPath, subGIDPath} {
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) && !subIDsWanted() {
			continue
		}
		if covered(p, idmap) {
			continue
		}
		if err := appendSubIDLocked(p, idmap, span); err != nil {
			return err
		}
	}
	subIDsEnsured[idmap.Base] = true
	return nil
}

// appendSubIDLocked appends root's span to the subid file p under shadow's
// lock, unless a root range there covers idmap by then.
func appendSubIDLocked(p string, idmap, span *IDMap) error {
	lock := p + ".lock"
	deadline := time.Now().Add(subIDLockWait)
	var lf *os.File
	for {
		f, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			lf = f
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("lock %s: %w", p, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("lock %s: %s is held by another tool; root's subordinate range was not added", p, lock)
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Fprintf(lf, "%d\n", os.Getpid())
	_ = lf.Close()
	defer os.Remove(lock)
	if covered(p, idmap) {
		return nil
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("add root's subordinate range to %s: %w", p, err)
	}
	line := fmt.Sprintf("root:%d:%d\n", span.Base, span.Size)
	if fi, serr := f.Stat(); serr == nil && fi.Size() > 0 {
		last := make([]byte, 1)
		if _, rerr := f.ReadAt(last, fi.Size()-1); rerr == nil && last[0] != '\n' {
			line = "\n" + line
		}
	}
	_, werr := f.WriteString(line)
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("add root's subordinate range to %s: %w", p, werr)
	}
	return nil
}

// covered reports whether a root range in the subid file at p covers idmap.
func covered(p string, idmap *IDMap) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(parts) != 3 || (parts[0] != "root" && parts[0] != "0") {
			continue
		}
		start, e1 := strconv.ParseInt(parts[1], 10, 64)
		n, e2 := strconv.ParseInt(parts[2], 10, 64)
		if e1 == nil && e2 == nil && idmap.Base >= start && idmap.Base+idmap.Size <= start+n {
			return true
		}
	}
	return false
}

// secureContainerDir makes <lxcpath>/<name> untraversable by other host users,
// as LXC makes a container directory: 0770, owned by the container's mapped
// root when it is unprivileged (the container reaches its rootfs through it)
// and left root's otherwise. A rootfs may hold setuid binaries and file
// capabilities (a restore keeps them), and a host user who could reach one
// under the directory could run it.
func (r *LxcRunner) secureContainerDir(name string) error {
	return secureContainerDirAt(filepath.Join(r.lxcpath(), name))
}

// secureContainerDirAt is secureContainerDir for a container directory at dir,
// its security read from dir/config.
func secureContainerDirAt(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		return fmt.Errorf("read container config in %s: %w", dir, err)
	}
	if sec := parseSecurity(string(b)); sec.IDMap != nil {
		if err := lchown(dir, int(sec.IDMap.Base), int(sec.IDMap.Base)); err != nil {
			return fmt.Errorf("give container directory %s to its mapped root: %w", dir, err)
		}
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		return fmt.Errorf("container directory %s mode: %w", dir, err)
	}
	return nil
}

// EnsureRootSubIDs is ensureRootSubIDs for a migrate's preflight on the
// target host.
func (r *LxcRunner) EnsureRootSubIDs(idmap *IDMap) error { return r.ensureRootSubIDs(idmap) }

// RevertContainerConverting is RevertContainer for a container whose current
// security (to) the snapshot may not carry: when the snapshot's config
// differs, the restored copy is marked converting to `to` before it is
// swapped into place, so a crash before the caller's Convert leaves a
// container that refuses to start until lv ct convert finishes it.
func (r *LxcRunner) RevertContainerConverting(ctx context.Context, name string, src io.Reader, to ConvertOpts) error {
	return r.importContainerMarked(ctx, name, src, true, &to)
}
