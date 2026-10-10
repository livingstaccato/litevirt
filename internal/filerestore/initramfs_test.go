//go:build linux

package filerestore

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

type cpioEnt struct {
	mode       uint32
	rmaj, rmin uint32
	data       []byte
}

// parseCPIO reads a newc archive the way the kernel's initramfs unpacker
// does, so the test checks the bytes, not the writer's intent.
func parseCPIO(t *testing.T, b []byte) map[string]cpioEnt {
	t.Helper()
	out := map[string]cpioEnt{}
	off := 0
	field := func(h []byte, i int) uint32 {
		v, err := strconv.ParseUint(string(h[6+8*i:6+8*i+8]), 16, 32)
		if err != nil {
			t.Fatalf("cpio field %d: %v", i, err)
		}
		return uint32(v)
	}
	for {
		if off+110 > len(b) {
			t.Fatal("cpio: no trailer")
		}
		h := b[off : off+110]
		if string(h[:6]) != "070701" {
			t.Fatalf("cpio magic at %d: %q", off, h[:6])
		}
		mode, size, namesize := field(h, 1), field(h, 6), field(h, 11)
		rmaj, rmin := field(h, 9), field(h, 10)
		name := string(b[off+110 : off+110+int(namesize)-1])
		off += 110 + int(namesize)
		for off%4 != 0 {
			off++
		}
		if name == "TRAILER!!!" {
			return out
		}
		data := b[off : off+int(size)]
		off += int(size)
		for off%4 != 0 {
			off++
		}
		out[name] = cpioEnt{mode: mode, rmaj: rmaj, rmin: rmin, data: data}
	}
}

// fakeModules lays out a modules dir: xfs depends on libcrc32c; ext4 and
// virtio_blk are built in; vsock transport depends on its common part and
// vsock.
func fakeModules(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	enc, _ := zstd.NewWriter(nil)
	put := func(rel, content string, compress bool) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		data := []byte(content)
		if compress {
			data = enc.EncodeAll(data, nil)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("kernel/lib/libcrc32c.ko.zst", "MOD libcrc32c", true)
	put("kernel/fs/xfs/xfs.ko.zst", "MOD xfs", true)
	put("kernel/net/vmw_vsock/vsock.ko", "MOD vsock", false)
	put("kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko.zst", "MOD common", true)
	put("kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko.zst", "MOD transport", true)
	put("kernel/fs/btrfs/btrfs.ko.xz", "MOD btrfs (xz, passed through)", false)
	put("modules.dep", strings.Join([]string{
		"kernel/lib/libcrc32c.ko.zst:",
		"kernel/fs/xfs/xfs.ko.zst: kernel/lib/libcrc32c.ko.zst",
		"kernel/net/vmw_vsock/vsock.ko:",
		"kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko.zst: kernel/net/vmw_vsock/vsock.ko",
		"kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko.zst: kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko.zst kernel/net/vmw_vsock/vsock.ko",
		"kernel/fs/btrfs/btrfs.ko.xz: kernel/lib/libcrc32c.ko.zst",
	}, "\n")+"\n", false)
	put("modules.builtin", "kernel/fs/ext4/ext4.ko\nkernel/drivers/block/virtio_blk.ko\n", false)
	return dir
}

func fakeAgent(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "litevirt")
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInitramfs_Contents(t *testing.T) {
	mods := fakeModules(t)
	agent := fakeAgent(t, "#!agent binary bytes, 33 bytes long")
	path, err := EnsureInitramfs(t.TempDir(), InitramfsSpec{Agent: agent, ModulesDir: mods}, -1)
	if err != nil {
		t.Fatalf("EnsureInitramfs: %v", err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o400 {
		t.Errorf("initramfs mode %v, want 0400", st.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	ents := parseCPIO(t, b)

	init := ents["init"]
	if string(init.data) != "#!agent binary bytes, 33 bytes long" || init.mode != cpioReg|0o755 {
		t.Fatalf("/init: mode %o data %q", init.mode, init.data)
	}
	if c := ents["dev/console"]; c.mode != cpioChar|0o600 || c.rmaj != 5 || c.rmin != 1 {
		t.Fatalf("/dev/console: %+v", c)
	}
	for _, d := range []string{"dev", "proc", "sys", "mnt", "modules"} {
		if ents[d].mode&cpioDir == 0 {
			t.Errorf("%s is not a directory", d)
		}
	}
	order := strings.Fields(string(ents["modules/order"].data))
	pos := map[string]int{}
	// Files are "<NNN>-<module>.ko[.xz]": the prefix is the load order.
	packed := func(n string) string { return modName(n[strings.IndexByte(n, '-')+1:]) }
	for i, n := range order {
		pos[packed(n)] = i
		data := ents["modules/"+n].data
		if strings.HasSuffix(n, ".ko") && !bytes.HasPrefix(data, []byte("MOD ")) {
			t.Errorf("%s is not decompressed: %q", n, data[:8])
		}
	}
	for _, dep := range [][2]string{
		{"libcrc32c", "xfs"}, {"vsock", "vmw_vsock_virtio_transport_common"},
		{"vmw_vsock_virtio_transport_common", "vmw_vsock_virtio_transport"}, {"libcrc32c", "btrfs"},
	} {
		a, aok := pos[dep[0]]
		b, bok := pos[dep[1]]
		if !aok || !bok || a > b {
			t.Errorf("%s must load before %s (order %v)", dep[0], dep[1], order)
		}
	}
	if _, ok := pos["ext4"]; ok {
		t.Error("a built-in module was packed")
	}
	if strings.Count(strings.Join(order, " "), "libcrc32c") != 1 {
		t.Errorf("a shared dependency is loaded twice: %v", order)
	}
	var xz string
	for _, n := range order {
		if strings.HasSuffix(n, ".xz") {
			xz = n
		}
	}
	if xz == "" || packed(xz) != "btrfs" {
		t.Errorf("an xz module is passed through for the kernel to decompress, named .xz: %v", order)
	}
}

func TestInitramfs_RequiredModuleMissing(t *testing.T) {
	mods := fakeModules(t)
	dep, _ := os.ReadFile(filepath.Join(mods, "modules.dep"))
	var keep []string
	for _, l := range strings.Split(string(dep), "\n") {
		if !strings.Contains(l, "vmw_vsock_virtio_transport.ko") || strings.HasPrefix(l, "kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common") {
			keep = append(keep, l)
		}
	}
	if err := os.WriteFile(filepath.Join(mods, "modules.dep"), []byte(strings.Join(keep, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := EnsureInitramfs(t.TempDir(), InitramfsSpec{Agent: fakeAgent(t, "a"), ModulesDir: mods}, -1)
	if err == nil || !strings.Contains(err.Error(), "vmw_vsock_virtio_transport") {
		t.Fatalf("want an error naming the missing vsock transport, got %v", err)
	}
}

// The initramfs is cached and rebuilt when the binary changes.
func TestInitramfs_Cache(t *testing.T) {
	mods := fakeModules(t)
	cache := t.TempDir()
	agent := fakeAgent(t, "v1")
	p1, err := EnsureInitramfs(cache, InitramfsSpec{Agent: agent, ModulesDir: mods}, -1)
	if err != nil {
		t.Fatal(err)
	}
	st1, _ := os.Stat(p1)
	p2, err := EnsureInitramfs(cache, InitramfsSpec{Agent: agent, ModulesDir: mods}, -1)
	if err != nil || p2 != p1 {
		t.Fatalf("second build: %q %v (want the cached %q)", p2, err, p1)
	}
	if st2, _ := os.Stat(p2); !st2.ModTime().Equal(st1.ModTime()) {
		t.Error("the cached initramfs was rebuilt")
	}
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(agent, []byte("v2 — an upgraded binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	p3, err := EnsureInitramfs(cache, InitramfsSpec{Agent: agent, ModulesDir: mods}, -1)
	if err != nil || p3 == p1 {
		t.Fatalf("a changed binary reused %q (%v)", p3, err)
	}
	if _, err := os.Stat(p1); !os.IsNotExist(err) {
		t.Error("the stale initramfs was left behind")
	}
	b, _ := os.ReadFile(p3)
	if got := string(parseCPIO(t, b)["init"].data); got != "v2 — an upgraded binary" {
		t.Fatalf("/init = %q", got)
	}
}

func TestModName(t *testing.T) {
	for in, want := range map[string]string{
		"kernel/fs/xfs/xfs.ko.zst":        "xfs",
		"kernel/lib/crc-t10dif.ko":        "crc_t10dif",
		"kernel/fs/btrfs/btrfs.ko.xz":     "btrfs",
		"vmw_vsock_virtio_transport":      "vmw_vsock_virtio_transport",
		"kernel/x/nls_iso8859-1.ko.gz":    "nls_iso8859_1",
		"/lib/modules/k/kernel/a/b.ko":    "b",
		"kernel/drivers/block/virtio_blk": "virtio_blk",
	} {
		if got := modName(in); got != want {
			t.Errorf("modName(%q) = %q, want %q", in, got, want)
		}
	}
}
