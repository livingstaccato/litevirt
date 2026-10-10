//go:build linux

package filerestore

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Boots real restore VMs. Needs KVM, /dev/vhost-vsock, qemu, a READABLE
// kernel matching /lib/modules/<release> (the host's /boot/vmlinuz is
// usually root-only), a static litevirt binary to use as the agent, and
// mkfs.ext4 / sfdisk / mkfs.xfs / qemu-img:
//
//	CGO_ENABLED=0 go build -o /tmp/lv ./cmd/litevirt
//	LITEVIRT_FR_KERNEL=/path/vmlinuz-$(uname -r) LITEVIRT_FR_AGENT=/tmp/lv \
//	  go test ./internal/filerestore/ -run TestRestoreVM -v
//
// Skipped without those variables. What it checks is what the unit tests
// cannot: that the host's kernel boots the initramfs, the agent loads its
// modules, mounts the guest filesystems inside the VM, answers over vsock,
// and that the host mounted nothing and kept no VM afterwards.

type fileDev struct {
	f    *os.File
	size int64
}

func (d *fileDev) ReadAt(p []byte, off int64) (int, error) { return d.f.ReadAt(p, off) }
func (d *fileDev) Size() int64                             { return d.size }

func openDev(t *testing.T, path string) *fileDev {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	st, _ := f.Stat()
	return &fileDev{f: f, size: st.Size()}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "PATH=/usr/sbin:/usr/bin:/sbin:/bin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func bootLauncher(t *testing.T) *Launcher {
	t.Helper()
	kernel, agent := os.Getenv("LITEVIRT_FR_KERNEL"), os.Getenv("LITEVIRT_FR_AGENT")
	if kernel == "" || agent == "" {
		t.Skip("set LITEVIRT_FR_KERNEL and LITEVIRT_FR_AGENT to boot real restore VMs")
	}
	l := NewLauncher(Config{Kernel: kernel, Agent: agent, StateDir: t.TempDir(), BootTimeout: 120 * time.Second})
	if err := l.Preflight(); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	return l
}

func hostMounts(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertGone(t *testing.T, l *Launcher) {
	t.Helper()
	ents, _ := os.ReadDir(filepath.Join(l.cfg.StateDir, "run"))
	if len(ents) != 0 {
		t.Errorf("session directories left behind: %v", ents)
	}
	out, _ := exec.Command("pgrep", "-f", "litevirt-file-restore.*"+l.cfg.StateDir).Output()
	if len(bytes.TrimSpace(out)) != 0 {
		t.Errorf("a restore VM is still running: %s", out)
	}
}

func TestRestoreVM_PartitionedExt4(t *testing.T) {
	l := bootLauncher(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(src, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "etc", "hostname"), []byte("restored-guest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(src, "etc", "shadow-link")); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(dir, "disk.img")
	run(t, "truncate", "-s", "64M", img)
	run(t, "sh", "-c", "printf 'label: gpt\nstart=2048, size=110000, type=L\n' | sfdisk -q "+img)
	run(t, "mkfs.ext4", "-q", "-F", "-d", src, "-E", "offset=1048576", img, "50000k")

	before := hostMounts(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	s, err := l.Open(ctx, openDev(t, img), KindFS, "raw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	vols, err := s.Volumes()
	if err != nil || len(vols) != 1 || vols[0].Name != "vda1" || vols[0].FSType != "ext4" {
		s.Close()
		t.Fatalf("volumes %v %v, want vda1 ext4", vols, err)
	}
	ents, _, _, err := s.List("/vda1/etc")
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	names := map[string]Entry{}
	for _, e := range ents {
		names[e.Name] = e
	}
	if names["hostname"].Size != 15 || names["shadow-link"].Type != TypeSymlink {
		t.Errorf("etc: %+v", ents)
	}
	var out bytes.Buffer
	if _, err := s.Tar(&out, []string{"/vda1/etc"}, TarLimits{}); err != nil {
		s.Close()
		t.Fatal(err)
	}
	got := readTar(t, out.Bytes())
	if got["vda1/etc/hostname"].body != "restored-guest\n" {
		t.Errorf("hostname = %q (%v)", got["vda1/etc/hostname"].body, keys(got))
	}
	if after := hostMounts(t); after != before {
		t.Error("the host's mount table changed during file restore")
	}
	s.Close()
	assertGone(t, l)
}

func TestRestoreVM_WholeDiskXFSAndQcow2(t *testing.T) {
	l := bootLauncher(t)
	dir := t.TempDir()
	raw := filepath.Join(dir, "xfs.img")
	run(t, "truncate", "-s", "320M", raw)
	run(t, "mkfs.xfs", "-q", "-f", raw)
	q := filepath.Join(dir, "xfs.qcow2")
	run(t, "qemu-img", "convert", "-f", "raw", "-O", "qcow2", raw, q)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	s, err := l.Open(ctx, openDev(t, q), KindFS, "qcow2")
	if err != nil {
		t.Fatalf("Open qcow2: %v", err)
	}
	vols, err := s.Volumes()
	s.Close()
	if err != nil || len(vols) != 1 || vols[0].Name != "vda" || vols[0].FSType != "xfs" {
		t.Fatalf("volumes %v %v, want the whole disk vda as xfs", vols, err)
	}
	assertGone(t, l)
}

func TestRestoreVM_ContainerArchive(t *testing.T) {
	l := bootLauncher(t)
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range []struct {
		name string
		typ  byte
		body string
	}{
		{"web/", tar.TypeDir, ""},
		{"web/config", tar.TypeReg, "lxc.rootfs.path = /x\n"},
		{"web/rootfs/", tar.TypeDir, ""},
		{"web/rootfs/etc/", tar.TypeDir, ""},
		{"web/rootfs/etc/os-release", tar.TypeReg, "ID=debian\n"},
	} {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Size: int64(len(e.body)), ModTime: time.Unix(1700000000, 0)}
		if e.typ == tar.TypeDir {
			h.Mode, h.Size = 0o755, 0
		}
		_ = tw.WriteHeader(h)
		_, _ = tw.Write([]byte(e.body))
	}
	_ = tw.Close()
	// A block device's size is whole sectors: pad like the backup's disk.
	for b.Len()%512 != 0 {
		b.WriteByte(0)
	}
	p := filepath.Join(t.TempDir(), "ct.tar")
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	s, err := l.Open(ctx, openDev(t, p), KindArchive, "raw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { s.Close(); assertGone(t, l) }()
	var out bytes.Buffer
	if _, err := s.Tar(&out, []string{"/rootfs/etc/os-release"}, TarLimits{}); err != nil {
		t.Fatal(err)
	}
	if got := readTar(t, out.Bytes())["rootfs/etc/os-release"].body; !strings.HasPrefix(got, "ID=debian") {
		t.Fatalf("os-release = %q", got)
	}
}
