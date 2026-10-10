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

	"github.com/klauspost/compress/zstd"
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
	"virtio_pci", "virtio_blk",
	"vsock", "vmw_vsock_virtio_transport_common", "vmw_vsock_virtio_transport",
	"ext4", "xfs", "btrfs", "vfat", "isofs",
	"nls_cp437", "nls_iso8859_1", "nls_utf8",
}

// requiredModules must be available (built in or as a module): without a
// disk or a vsock transport the agent cannot work at all.
var requiredModules = []string{"virtio_blk", "vsock", "vmw_vsock_virtio_transport"}

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

// initramfsKey identifies a built initramfs: the agent binary (size, mtime,
// a hash of its first MiB), the modules dir and its modules.dep.
func initramfsKey(spec InitramfsSpec) (string, error) {
	h := sha256.New()
	st, err := os.Stat(spec.Agent)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(h, "v1|%s|%d|%d|%s|", spec.Agent, st.Size(), st.ModTime().UnixNano(), spec.ModulesDir)
	if f, err := os.Open(spec.Agent); err == nil {
		_, _ = io.CopyN(h, f, 1<<20)
		f.Close()
	}
	if b, err := os.ReadFile(filepath.Join(spec.ModulesDir, "modules.dep")); err == nil {
		h.Write(b)
	}
	m := append([]string(nil), agentModules...)
	sort.Strings(m)
	fmt.Fprintf(h, "|%s", strings.Join(m, ","))
	return hex.EncodeToString(h.Sum(nil))[:24], nil
}

// EnsureInitramfs returns the path of an initramfs for spec under cacheDir,
// building it if it is not there yet. The file is the daemon's own (0600)
// and written atomically.
func EnsureInitramfs(cacheDir string, spec InitramfsSpec) (string, error) {
	key, err := initramfsKey(spec)
	if err != nil {
		return "", fmt.Errorf("restore VM agent binary: %w", err)
	}
	dst := filepath.Join(cacheDir, "initramfs-"+key+".cpio")
	if st, err := os.Stat(dst); err == nil && st.Mode().IsRegular() {
		return dst, nil
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(cacheDir, ".initramfs-*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := writeInitramfs(tmp, spec); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", err
	}
	// Drop older builds.
	if old, _ := filepath.Glob(filepath.Join(cacheDir, "initramfs-*.cpio")); len(old) > 0 {
		for _, o := range old {
			if o != dst {
				_ = os.Remove(o)
			}
		}
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
