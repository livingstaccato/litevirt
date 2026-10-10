//go:build linux

package filerestore

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// bootLauncher returns a launcher for real restore VMs, or skips — loudly,
// naming what is missing — when this host cannot run them. As root the
// host's own kernel is used unless LITEVIRT_FR_KERNEL names another; a
// non-root run needs a readable copy (the host's /boot/vmlinuz is root-only).
func bootLauncher(t *testing.T) *Launcher {
	t.Helper()
	kernel, agent := os.Getenv("LITEVIRT_FR_KERNEL"), os.Getenv("LITEVIRT_FR_AGENT")
	if agent == "" || (kernel == "" && os.Geteuid() != 0) {
		reason := "SKIPPING real restore-VM boot tests: set LITEVIRT_FR_AGENT (a static litevirt build) " +
			"and, when not root, LITEVIRT_FR_KERNEL (a readable kernel matching /lib/modules/$(uname -r)); " +
			"`make test-filerestore-vm` runs them"
		fmt.Fprintln(os.Stderr, reason)
		t.Skip(reason)
	}
	// As root, qemu runs as another user, who must be able to traverse to
	// the cache and run directories.
	base, err := os.MkdirTemp("", "frboot-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	_ = os.Chmod(base, 0o711)
	l := NewLauncher(Config{
		Kernel: kernel, Agent: agent, BootTimeout: 120 * time.Second,
		CacheDir: filepath.Join(base, "cache"), RunDir: filepath.Join(base, "run"),
	})
	if err := l.Preflight(); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	return l
}

// relevantMounts is the host's mounts whose source is a block device a
// file restore could have mounted (nbd, loop, virtio) or a path under dir.
// Unrelated churn (automounts, containers) does not count.
func relevantMounts(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		i := strings.Index(l, " - ")
		if i < 0 {
			continue
		}
		f := strings.Fields(l[i+3:])
		if len(f) < 2 {
			continue
		}
		src := f[1]
		if strings.HasPrefix(src, "/dev/nbd") || strings.HasPrefix(src, "/dev/loop") || strings.HasPrefix(src, "/dev/vd") ||
			strings.Contains(l, dir) {
			out = append(out, l)
		}
	}
	return out
}

func sameMounts(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// assertConfined checks, from /proc, that the running qemu is the
// unprivileged user it should be (as root: the configured qemu user, never
// root) with a seccomp filter on.
func assertConfined(t *testing.T, s *Session) {
	t.Helper()
	if s.cmd == nil {
		t.Fatal("no qemu process")
	}
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", s.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	var uid, seccomp string
	for _, l := range strings.Split(string(st), "\n") {
		if f := strings.Fields(l); len(f) >= 2 {
			switch f[0] {
			case "Uid:":
				uid = f[1]
			case "Seccomp:":
				seccomp = f[1]
			}
		}
	}
	if seccomp != "2" {
		t.Errorf("qemu runs without a seccomp filter (Seccomp: %q)", seccomp)
	}
	if os.Geteuid() == 0 {
		if uid == "0" {
			t.Errorf("qemu runs as root")
		}
		u, _ := lookupQemuUser("")
		if u == nil || uid != strconv.FormatUint(uint64(u.uid), 10) {
			t.Errorf("qemu runs as uid %s, want the qemu user %+v", uid, u)
		}
	}
	t.Logf("qemu pid %d: uid %s, seccomp %s", s.cmd.Process.Pid, uid, seccomp)
}

func assertGone(t *testing.T, l *Launcher) {
	t.Helper()
	ents, _ := os.ReadDir(l.cfg.RunDir)
	if len(ents) != 0 {
		t.Errorf("session directories left behind: %v", ents)
	}
	out, _ := exec.Command("pgrep", "-f", "litevirt-file-restore.*"+l.cfg.RunDir).Output()
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

	before := relevantMounts(t, dir)
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
	assertConfined(t, s)
	if after := relevantMounts(t, dir); !sameMounts(before, after) {
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

// I-4: a restore VM dies with the daemon that started it — including as
// root, where qemu runs as another user (a parent-death signal set before a
// user switch would have been cleared; Go sets it after). The "daemon" here
// is a helper process: it opens a session, records qemu's pid, and exits
// without closing anything.
func TestRestoreVM_DiesWithTheDaemon(t *testing.T) {
	if os.Getenv("LITEVIRT_FR_HELPER") == "1" {
		l := bootLauncher(t)
		img := filepath.Join(t.TempDir(), "blank.img")
		run(t, "truncate", "-s", "16M", img)
		run(t, "mkfs.ext4", "-q", "-F", img)
		s, err := l.Open(context.Background(), openDev(t, img), KindFS, "raw")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		_ = os.WriteFile(os.Getenv("LITEVIRT_FR_PIDFILE"), []byte(strconv.Itoa(s.cmd.Process.Pid)), 0o644)
		os.Exit(0) // the daemon dies: no Close, no cleanup
	}
	_ = bootLauncher(t) // skips, loudly, without the environment
	pidFile := filepath.Join(t.TempDir(), "qemu.pid")
	_ = os.Chmod(filepath.Dir(pidFile), 0o755)
	cmd := exec.Command(os.Args[0], "-test.run", "^TestRestoreVM_DiesWithTheDaemon$", "-test.count=1")
	cmd.Env = append(os.Environ(), "LITEVIRT_FR_HELPER=1", "LITEVIRT_FR_PIDFILE="+pidFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper daemon: %v\n%s", err, out)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("the helper recorded no qemu pid: %v", err)
	}
	pid, _ := strconv.Atoi(string(b))
	deadline := time.Now().Add(15 * time.Second)
	for {
		st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil || strings.Contains(string(st), "State:\tZ") {
			t.Logf("qemu %d died with its daemon", pid)
			return
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("qemu %d outlived the daemon that started it", pid)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// I-4: the agent powers the VM off on its own when nothing talks to it —
// the backstop when the host is gone without killing it.
func TestRestoreVM_AgentPowersOffWhenIdle(t *testing.T) {
	l := bootLauncher(t)
	l.cfg.AgentIdle = 5 * time.Second
	img := filepath.Join(t.TempDir(), "blank.img")
	run(t, "truncate", "-s", "16M", img)
	run(t, "mkfs.ext4", "-q", "-F", img)
	s, err := l.Open(context.Background(), openDev(t, img), KindFS, "raw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	select {
	case <-s.exited:
		t.Logf("the restore VM powered off on its own after %v idle", l.cfg.AgentIdle)
	case <-time.After(60 * time.Second):
		t.Fatal("an idle restore VM kept running past the agent's idle timeout")
	}
}
