package storage

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// mountinfoFDs is the set of this process's descriptors open on its
// mountinfo.
func mountinfoFDs(t *testing.T) map[int]bool {
	t.Helper()
	want := fmt.Sprintf("/proc/%d/mountinfo", os.Getpid())
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	out := map[int]bool{}
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if l, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && l == want {
			out[fd] = true
		}
	}
	return out
}

// epollWatched is the set of descriptors any epoll instance of this process
// watches (the Go runtime's netpoller is one).
func epollWatched(t *testing.T) map[int]bool {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	out := map[int]bool{}
	for _, e := range ents {
		if l, err := os.Readlink("/proc/self/fd/" + e.Name()); err != nil || l != "anon_inode:[eventpoll]" {
			continue
		}
		b, err := os.ReadFile("/proc/self/fdinfo/" + e.Name())
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "tfd:" {
				if fd, err := strconv.Atoi(f[1]); err == nil {
					out[fd] = true
				}
			}
		}
	}
	return out
}

// The watch's descriptor is never in the Go runtime's netpoller. An epoll
// instance watching mountinfo calls the kernel's mounts_poll on every
// epoll_wait after a mount, and that call consumes the change mark, so the
// watch's own poll then sees no change and the cache keeps a table without
// the mount (bug B1: an NFS pool read as not mounted for hours). os.Open
// registers any pollable file with the netpoller; /proc/self/mountinfo is
// pollable.
//
// Mutation "open the watch with os.Open" (the base): the descriptor is in
// the netpoller's set, red.
func TestProcMountWatch_DescriptorIsNotInTheRuntimePoller(t *testing.T) {
	before := mountinfoFDs(t)
	w := &procMountWatch{}
	defer w.close()
	w.changed()
	var fd = -1
	for f := range mountinfoFDs(t) {
		if !before[f] {
			fd = f
		}
	}
	if fd < 0 {
		t.Fatal("the watch holds no descriptor on mountinfo")
	}
	if epollWatched(t)[fd] {
		t.Fatalf("the watch's descriptor %d on mountinfo is in an epoll set of this process (the runtime's netpoller), which consumes the kernel's change mark", fd)
	}
}

const mountWatchChildEnv = "LITEVIRT_TEST_MOUNTWATCH_CHILD"

// A mount made while the runtime sits idle is seen by the watch: the child
// runs in its own user and mount namespaces, mounts a tmpfs, lets the runtime
// idle (its netpoller blocks in epoll_wait then), and asks the watch. Each of
// ten mounts must be seen, and each unmount too.
//
// Mutation "open the watch with os.Open" (the base): the child misses every
// mount (10 of 10), as the lab's repro missed 50 of 50, red.
func TestProcMountWatch_SeesAMountMadeWhileTheRuntimeIdles(t *testing.T) {
	if os.Getenv(mountWatchChildEnv) != "" {
		t.Skip("run by the parent in its own namespaces")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcMountWatch_Child$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), mountWatchChildEnv+"="+dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	if err != nil && errors.Is(err, syscall.EPERM) || err != nil && strings.Contains(string(out), "MOUNTWATCH-NOMOUNT") {
		t.Skipf("this host refuses an unprivileged user namespace or its mount (%v): %s; TestProcMountWatch_DescriptorIsNotInTheRuntimePoller still covers the cause", err, out)
	}
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "MOUNTWATCH-OK") {
		t.Fatalf("child did not finish:\n%s", out)
	}
}

func TestProcMountWatch_Child(t *testing.T) {
	dir := os.Getenv(mountWatchChildEnv)
	if dir == "" {
		t.Skip("only as the child of TestProcMountWatch_SeesAMountMadeWhileTheRuntimeIdles")
	}
	// Keep this namespace's mounts out of the host's.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		fmt.Println("MOUNTWATCH-NOMOUNT", err)
		t.Fatal(err)
	}
	mnt := filepath.Join(dir, "m")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	w := &procMountWatch{}
	defer w.close()
	w.changed()
	w.changed()
	const n = 10
	missedMount, missedUnmount := 0, 0
	for range n {
		if err := unix.Mount("none", mnt, "tmpfs", 0, ""); err != nil {
			fmt.Println("MOUNTWATCH-NOMOUNT", err)
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond) // the runtime idles in epoll_wait
		if !w.changed() {
			missedMount++
		}
		if err := unix.Unmount(mnt, 0); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		if !w.changed() {
			missedUnmount++
		}
	}
	if missedMount+missedUnmount > 0 {
		t.Fatalf("the watch missed %d of %d mounts and %d of %d unmounts", missedMount, n, missedUnmount, n)
	}
	fmt.Println("MOUNTWATCH-OK")
}
