package grpcapi

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The host checks lv image rm relies on, read from the real host: which
// processes hold a file open, and which filesystem the image store is on.

// A file this process holds open is reported with this process; a file no
// one holds is not.
func TestProcessesHolding_FindsARealOpenFile(t *testing.T) {
	dir := t.TempDir()
	held, idle := filepath.Join(dir, "held.qcow2"), filepath.Join(dir, "idle.qcow2")
	for _, p := range []string{held, idle} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(held)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	want := fmt.Sprintf("process %d ", os.Getpid())

	// Every process: as root this reads them all; otherwise another user's
	// process cannot be read and the answer fails closed — but what was found
	// is still reported.
	got, err := processesHolding([]string{held, idle})
	if !strings.HasPrefix(got[held], want) {
		t.Fatalf("holders %v (err %v); want %s reported as holding %s", got, err, want, held)
	}
	if got[idle] != "" {
		t.Errorf("%s is reported held by %s", idle, got[idle])
	}
	if os.Geteuid() != 0 && err == nil {
		t.Error("not root, yet every process's open files read: the answer cannot have failed closed")
	}

	self := strconv.Itoa(os.Getpid())
	got, err = processesHoldingIn("/proc", func(pid string) bool { return pid == self }, []string{held, idle})
	if err != nil || !strings.HasPrefix(got[held], want) || got[idle] != "" {
		t.Fatalf("this process only: holders %v, err %v", got, err)
	}
}

// A process whose open files cannot be read fails the answer closed.
func TestProcessesHolding_AnUnreadableProcessFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 directory")
	}
	root := t.TempDir()
	fd := filepath.Join(root, "4242", "fd")
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fd, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fd, 0o755) })
	target := filepath.Join(t.TempDir(), "img.qcow2")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "4242", "comm"), []byte("qemu-x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := processesHoldingIn(root, func(string) bool { return true }, []string{target}); err == nil ||
		!strings.Contains(err.Error(), "process 4242 (qemu-x)") {
		t.Fatalf("err %v; want the unreadable process named, with its command", err)
	}
}

// An open file whose target cannot be read (a dead FUSE daemon's, a stale
// share's) fails the answer closed too, and the reason names the process and
// the fd, so an operator can act on it.
func TestProcessesHolding_AnUnreadableFdIsNamed(t *testing.T) {
	root := t.TempDir()
	fd := filepath.Join(root, "777", "fd")
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "777", "comm"), []byte("fusermount\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// fd 7 resolves to itself: stat fails with ELOOP, not "gone".
	if err := os.Symlink(filepath.Join(fd, "7"), filepath.Join(fd, "7")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "img.qcow2")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := processesHoldingIn(root, func(string) bool { return true }, []string{target})
	if err == nil || !strings.Contains(err.Error(), "fd 7 of process 777 (fusermount)") {
		t.Fatalf("err %v; want process 777 and its fd 7 named", err)
	}
}

// A local directory is on no network filesystem; every network filesystem
// mounted here is told as one; and each magic means what it says.
func TestNetworkFilesystem_ReadsTheRealFilesystem(t *testing.T) {
	if fs, err := networkFilesystem(t.TempDir()); err != nil || fs != "" {
		t.Fatalf("a temp dir: %q, %v; want a local filesystem", fs, err)
	}
	// Whatever network or FUSE filesystem this host mounts (lxcfs, an nfs
	// share) is told as one, through the real statfs.
	mf, err := os.Open("/proc/self/mounts")
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Close()
	seen := 0
	sc := bufio.NewScanner(mf)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		typ := fields[2]
		if !(strings.HasPrefix(typ, "nfs") || strings.HasPrefix(typ, "fuse.") || typ == "fuse" ||
			typ == "cifs" || typ == "smb3" || typ == "ceph" || typ == "9p") {
			continue
		}
		fs, err := networkFilesystem(fields[1])
		if err != nil {
			continue // not ours to read
		}
		seen++
		if fs == "" {
			t.Errorf("%s (%s) is not told as a network filesystem", fields[1], typ)
		}
	}
	if seen == 0 {
		t.Log("no network or FUSE filesystem is mounted here; only the magic table is checked")
	}
	for magic, want := range map[uint32]string{0x6969: "nfs", 0xff534d42: "cifs", 0xfe534d42: "smb2", 0x65735546: "fuse", 0x00c36400: "ceph", 0x01021997: "9p"} {
		if got := networkFilesystems[magic]; got != want {
			t.Errorf("magic %#x: %q, want %q", magic, got, want)
		}
	}
	orig := statfsType
	t.Cleanup(func() { statfsType = orig })
	statfsType = func(string) (uint32, error) { return 0x6969, nil }
	if fs, _ := networkFilesystem("/x"); fs != "nfs" {
		t.Errorf("an nfs statfs: %q", fs)
	}
}
