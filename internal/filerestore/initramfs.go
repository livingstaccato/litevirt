//go:build linux

package filerestore

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

// The restore VM boots the host's own kernel with an initramfs built here:
//
//	/init              this litevirt binary (static), run as the agent
//	/modules/order     the modules to load, in dependency order
//	/modules/*.ko      those modules, decompressed
//	/dev/console       so the agent has a console before devtmpfs
//	/dev /proc /sys /mnt
//
// Nothing is installed on the host for it; it is rebuilt when the binary,
// the kernel release or the module list changes.

// agentModules are the kernel modules the agent may need. One built into the
// kernel is skipped; one that is neither built in nor present is skipped
// too, unless it is required.
var agentModules = []string{
	"virtio_pci", "virtio_blk", "qemu_fw_cfg",
	"vsock", "vmw_vsock_virtio_transport_common", "vmw_vsock_virtio_transport",
	"ext4", "xfs", "btrfs", "vfat", "isofs",
	"nls_cp437", "nls_iso8859_1", "nls_utf8",
}

// requiredModules must be available (built in or as a module): without a
// disk, a vsock transport, or fw_cfg (which carries the session nonce) the
// agent cannot work at all.
var requiredModules = []string{"virtio_blk", "vsock", "vmw_vsock_virtio_transport", "qemu_fw_cfg"}

// modName normalizes a module file or name: basename without .ko and a
// compression suffix, '-' as '_'.
func modName(s string) string {
	s = filepath.Base(s)
	for _, suf := range []string{".zst", ".xz", ".gz"} {
		s = strings.TrimSuffix(s, suf)
	}
	s = strings.TrimSuffix(s, ".ko")
	return strings.ReplaceAll(s, "-", "_")
}

// moduleSet is what modules.dep and modules.builtin say about a kernel.
type moduleSet struct {
	dir     string
	paths   map[string]string   // name -> path relative to dir
	deps    map[string][]string // name -> dependency names
	builtin map[string]bool
}

func loadModuleSet(dir string) (*moduleSet, error) {
	ms := &moduleSet{dir: dir, paths: map[string]string{}, deps: map[string][]string{}, builtin: map[string]bool{}}
	f, err := os.Open(filepath.Join(dir, "modules.dep"))
	if err != nil {
		return nil, fmt.Errorf("kernel modules: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		mod := line[:i]
		n := modName(mod)
		ms.paths[n] = mod
		for _, d := range strings.Fields(line[i+1:]) {
			ms.deps[n] = append(ms.deps[n], modName(d))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(filepath.Join(dir, "modules.builtin")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				ms.builtin[modName(l)] = true
			}
		}
	}
	return ms, nil
}

// resolve returns the module files to load for want, dependencies first,
// each once. Built-in and absent modules are skipped; an absent required
// one is an error.
func (ms *moduleSet) resolve(want, required []string) ([]string, error) {
	var order []string
	seen := map[string]bool{}
	var visit func(n string, depth int) error
	visit = func(n string, depth int) error {
		if seen[n] || ms.builtin[n] {
			return nil
		}
		if depth > 32 {
			return fmt.Errorf("module dependency loop at %s", n)
		}
		p, ok := ms.paths[n]
		if !ok {
			return nil
		}
		seen[n] = true
		for _, d := range ms.deps[n] {
			if err := visit(d, depth+1); err != nil {
				return err
			}
		}
		order = append(order, p)
		return nil
	}
	for _, n := range want {
		if err := visit(n, 0); err != nil {
			return nil, err
		}
	}
	for _, n := range required {
		if !ms.builtin[n] && ms.paths[n] == "" {
			return nil, fmt.Errorf("kernel modules in %s have no %s (neither built in nor a module)", ms.dir, n)
		}
	}
	return order, nil
}

// readModule returns a module's bytes, decompressing zstd and gzip here so
// the agent does not depend on in-kernel module decompression. An xz module
// is passed through for the kernel to decompress.
func readModule(path string) (data []byte, compressed bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	switch {
	case strings.HasSuffix(path, ".zst"):
		d, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(256<<20))
		if err != nil {
			return nil, false, err
		}
		defer d.Close()
		out, err := d.DecodeAll(raw, nil)
		return out, false, err
	case strings.HasSuffix(path, ".gz"):
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, false, err
		}
		out, err := io.ReadAll(io.LimitReader(zr, 256<<20))
		return out, false, err
	case strings.HasSuffix(path, ".xz"):
		return raw, true, nil
	default:
		return raw, false, nil
	}
}

// cpioWriter writes an uncompressed "newc" archive (the format the kernel
// unpacks as an initramfs).
type cpioWriter struct {
	w   io.Writer
	ino uint32
	err error
}

const (
	cpioDir  = 0o040000
	cpioReg  = 0o100000
	cpioChar = 0o020000
)

func (c *cpioWriter) entry(name string, mode uint32, data []byte, rmaj, rmin uint32) {
	c.entryFrom(name, mode, bytes.NewReader(data), int64(len(data)), rmaj, rmin)
}

// entryFrom writes an entry whose size bytes come from r.
func (c *cpioWriter) entryFrom(name string, mode uint32, r io.Reader, size int64, rmaj, rmin uint32) {
	if c.err != nil {
		return
	}
	if size > 0xFFFFFFFF {
		c.err = fmt.Errorf("cpio: %s is too large (%d bytes)", name, size)
		return
	}
	c.ino++
	nlink := uint32(1)
	if mode&cpioDir != 0 {
		nlink = 2
	}
	hdr := fmt.Sprintf("070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
		c.ino, mode, 0, 0, nlink, 0, size, 0, 0, rmaj, rmin, len(name)+1, 0)
	buf := make([]byte, 0, len(hdr)+len(name)+8)
	buf = append(buf, hdr...)
	buf = append(buf, name...)
	buf = append(buf, 0)
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	if _, c.err = c.w.Write(buf); c.err != nil {
		return
	}
	if size > 0 {
		n, err := io.CopyN(c.w, r, size)
		if err != nil {
			c.err = fmt.Errorf("cpio: %s: wrote %d of %d bytes: %w", name, n, size, err)
			return
		}
		if pad := (4 - size%4) % 4; pad > 0 {
			_, c.err = c.w.Write(make([]byte, pad))
		}
	}
}

func (c *cpioWriter) close() error {
	c.entry("TRAILER!!!", 0, nil, 0, 0)
	return c.err
}

// InitramfsSpec is what an initramfs is built from.
type InitramfsSpec struct {
	Agent      string // the litevirt binary to run as /init
	ModulesDir string // /lib/modules/<release>
}

// fileStamp identifies one version of a file without reading it.
type fileStamp struct {
	path               string
	dev, ino           uint64
	size, mtime, ctime int64
}

var (
	hashMu   sync.Mutex
	hashMemo = map[fileStamp]string{}
)

// fileHash is the sha256 of a file's whole content, remembered per version
// of the file, so the 70+ MB agent binary is hashed once, not per session.
func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	stamp := fileStamp{path: path, size: st.Size(), mtime: st.ModTime().UnixNano()}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		stamp.dev, stamp.ino = uint64(sys.Dev), uint64(sys.Ino)
		stamp.ctime = sys.Ctim.Nano()
	}
	hashMu.Lock()
	h, ok := hashMemo[stamp]
	hashMu.Unlock()
	if ok {
		return h, nil
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	h = hex.EncodeToString(sum.Sum(nil))
	hashMu.Lock()
	hashMemo[stamp] = h
	hashMu.Unlock()
	return h, nil
}

// initramfsKey identifies a built initramfs by everything that goes into
// it: the whole agent binary, every module file packed, modules.dep, and the
// module list.
func initramfsKey(spec InitramfsSpec) (string, error) {
	h := sha256.New()
	ah, err := fileHash(spec.Agent)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(h, "v2|agent=%s|", ah)
	if dh, err := fileHash(filepath.Join(spec.ModulesDir, "modules.dep")); err == nil {
		fmt.Fprintf(h, "dep=%s|", dh)
	}
	if ms, err := loadModuleSet(spec.ModulesDir); err == nil {
		if order, err := ms.resolve(agentModules, nil); err == nil {
			for _, rel := range order {
				mh, err := fileHash(filepath.Join(ms.dir, rel))
				if err != nil {
					return "", err
				}
				fmt.Fprintf(h, "%s=%s|", rel, mh)
			}
		}
	}
	m := append([]string(nil), agentModules...)
	sort.Strings(m)
	fmt.Fprintf(h, "|%s", strings.Join(m, ","))
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

// The boot files (initramfs, kernel copy) are the daemon's: owned by it
// (root in production), group the restore user's group, mode 0440, in a
// directory that is 0750 the same way (/var/cache/litevirt-restore). qemu
// can read them through its group and never write them. Beside each, a
// root-only sidecar (<file>.sha256, 0600) records the digest written; every
// reuse re-hashes the file against it, so a file changed by anyone is
// rebuilt — and reported (TamperFunc) — before a restore VM boots it.

const (
	cacheFileMode = 0o440
	cacheDirMode  = 0o750
)

// cachedFile checks a cache file before reuse: a regular file, one link,
// owned by this process, group gid, mode 0440, whose content still hashes
// to its sidecar's digest. ok=false with why="" means it does not exist.
func cachedFile(path string, gid int) (ok bool, why string) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false, ""
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return false, "not a regular file"
	case st.Nlink != 1:
		return false, fmt.Sprintf("%d links", st.Nlink)
	case int(st.Uid) != os.Geteuid():
		return false, fmt.Sprintf("owned by uid %d", st.Uid)
	case int(st.Gid) != gid:
		return false, fmt.Sprintf("group %d, want %d", st.Gid, gid)
	case st.Mode&0o7777 != cacheFileMode:
		return false, fmt.Sprintf("mode %o", st.Mode&0o7777)
	}
	want, err := os.ReadFile(path + ".sha256")
	if err != nil {
		return false, "no recorded digest"
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err.Error()
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err.Error()
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.TrimSpace(string(want)) {
		return false, "content does not match the digest recorded when it was written"
	}
	return true, ""
}

// prepareCacheDir makes the cache directory: the daemon's, group gid, 0750
// (qemu reads the files it is given through its group; no one else can
// even look).
func prepareCacheDir(dir string, gid int) error {
	if err := os.MkdirAll(dir, cacheDirMode); err != nil {
		return err
	}
	if err := os.Chmod(dir, cacheDirMode); err != nil {
		return err
	}
	return os.Chown(dir, -1, gid)
}

// writeCacheFile writes dst atomically with fill: owned by this process,
// group gid, mode 0440, and records its digest in a 0600 sidecar.
func writeCacheFile(dir, dst string, gid int, fill func(io.Writer) error) error {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if err := fill(io.MultiWriter(tmp, h)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chown(-1, gid); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(cacheFileMode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	side, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(side.Name())
	_ = side.Chmod(0o600)
	if _, err := side.WriteString(hex.EncodeToString(h.Sum(nil)) + "\n"); err != nil {
		side.Close()
		return err
	}
	if err := side.Close(); err != nil {
		return err
	}
	// The sidecar first: a reader never sees a new file with an old digest
	// pass (it would mismatch and be rebuilt).
	if err := os.Rename(side.Name(), dst+".sha256"); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// ensureCacheFile returns dst, reusing it when it checks out, or writing it
// with fill. A file that exists but does not check out is reported to
// onTamper before it is rebuilt.
func ensureCacheFile(dir, dst string, gid int, onTamper TamperFunc, fill func(io.Writer) error) error {
	// The directory first: owned by this process, group gid, 0750. A
	// directory not exactly so is reported and put right.
	if why := cacheDirWrong(dir, gid); why != "" {
		if onTamper != nil {
			onTamper(dir, why)
		}
		if err := prepareCacheDir(dir, gid); err != nil {
			return err
		}
	}
	ok, why := cachedFile(dst, gid)
	if ok {
		return nil
	}
	if why != "" && onTamper != nil {
		onTamper(dst, why)
	}
	if err := prepareCacheDir(dir, gid); err != nil {
		return err
	}
	_ = os.Remove(dst)
	return writeCacheFile(dir, dst, gid, fill)
}

// cacheDirWrong says what is wrong with an existing cache directory ("" if
// nothing, or if it does not exist yet).
func cacheDirWrong(dir string, gid int) string {
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return ""
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return "not a directory"
	case int(st.Uid) != os.Geteuid():
		return fmt.Sprintf("directory owned by uid %d", st.Uid)
	case int(st.Gid) != gid:
		return fmt.Sprintf("directory group %d, want %d", st.Gid, gid)
	case st.Mode&0o7777 != cacheDirMode:
		return fmt.Sprintf("directory mode %o", st.Mode&0o7777)
	}
	return ""
}

// GCCache removes the boot files in cacheDir (and their sidecars) for which
// keep is false. The launcher calls it with the files current or in use by a
// running session, so a session never loses the files it is about to boot.
func GCCache(cacheDir string, keep func(path string) bool) {
	for _, glob := range []string{"initramfs-*", "kernel-*"} {
		files, _ := filepath.Glob(filepath.Join(cacheDir, glob))
		for _, f := range files {
			base := strings.TrimSuffix(f, ".sha256")
			if !keep(base) {
				_ = os.Remove(f)
			}
		}
	}
}

// EnsureInitramfs returns the path of an initramfs for spec under cacheDir,
// building it if it is not there yet or does not check out (cachedFile).
// gid is the restore user's group (the daemon's own gid when not root).
func EnsureInitramfs(cacheDir string, spec InitramfsSpec, gid int, onTamper TamperFunc) (string, error) {
	key, err := initramfsKey(spec)
	if err != nil {
		return "", fmt.Errorf("restore VM agent binary: %w", err)
	}
	dst := filepath.Join(cacheDir, "initramfs-"+key+".cpio")
	if err := ensureCacheFile(cacheDir, dst, gid, onTamper, func(w io.Writer) error { return writeInitramfs(w, spec) }); err != nil {
		return "", err
	}
	return dst, nil
}

// ensureKernelCopy returns a copy of kernel the restore group can read: the
// host's own image is usually root-only (0600).
func ensureKernelCopy(cacheDir, kernel string, gid int, onTamper TamperFunc) (string, error) {
	h, err := fileHash(kernel)
	if err != nil {
		return "", err
	}
	dst := filepath.Join(cacheDir, "kernel-"+h[:32])
	if err := ensureCacheFile(cacheDir, dst, gid, onTamper, func(w io.Writer) error {
		f, err := os.Open(kernel)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	}); err != nil {
		return "", err
	}
	return dst, nil
}

func writeInitramfs(w io.Writer, spec InitramfsSpec) error {
	ms, err := loadModuleSet(spec.ModulesDir)
	if err != nil {
		return err
	}
	order, err := ms.resolve(agentModules, requiredModules)
	if err != nil {
		return err
	}
	agent, err := os.Open(spec.Agent)
	if err != nil {
		return fmt.Errorf("restore VM agent binary: %w", err)
	}
	defer agent.Close()
	ast, err := agent.Stat()
	if err != nil {
		return fmt.Errorf("restore VM agent binary: %w", err)
	}
	c := &cpioWriter{w: w}
	for _, d := range []string{"dev", "proc", "sys", "mnt", "modules"} {
		c.entry(d, cpioDir|0o755, nil, 0, 0)
	}
	c.entry("dev/console", cpioChar|0o600, nil, 5, 1)
	c.entryFrom("init", cpioReg|0o755, agent, ast.Size(), 0, 0)
	var list strings.Builder
	for i, rel := range order {
		data, compressed, err := readModule(filepath.Join(ms.dir, rel))
		if err != nil {
			return fmt.Errorf("kernel module %s: %w", rel, err)
		}
		name := fmt.Sprintf("modules/%03d-%s.ko", i, modName(rel))
		if compressed {
			name += ".xz"
		}
		c.entry(name, cpioReg|0o644, data, 0, 0)
		list.WriteString(filepath.Base(name) + "\n")
	}
	c.entry("modules/order", cpioReg|0o644, []byte(list.String()), 0, 0)
	return c.close()
}
