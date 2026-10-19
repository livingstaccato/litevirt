//go:build linux

package lxc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The daemon runs under KillMode=process: when it dies, a child it spawned
// into a staging directory (umoci unpacking a replacing pull, lxc-create
// fetching a recreate's image) must die with it, or the start-up sweep
// races a process still writing there ("directory not empty"). The test
// plays the daemon in a child process that starts the work, waits for the
// tool to be running, and exits; the tool must not outlive it.
func TestStagingChildrenDieWithTheDaemon(t *testing.T) {
	for _, tc := range []string{"umoci", "lxc-create"} {
		t.Run(tc, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			pidf := filepath.Join(dir, "child.pid")
			sleeper := "#!/bin/sh\necho $$ > " + pidf + "\nexec sleep 30\n"
			for _, tool := range []string{"umoci", "lxc-create"} {
				body := sleeper
				if tool != tc {
					body = "#!/bin/sh\nexit 0\n"
				}
				if err := os.WriteFile(filepath.Join(bin, tool), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(bin, "skopeo"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperDaemonForDeathSig$")
			cmd.Env = append(os.Environ(), "LXC_DEATHSIG_HELPER="+tc, "LXC_DEATHSIG_DIR="+dir,
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("helper daemon: %v\n%s", err, out)
			}
			b, err := os.ReadFile(pidf)
			if err != nil {
				t.Fatalf("the tool never ran: %v\n%s", err, out)
			}
			pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			deadline := time.Now().Add(5 * time.Second)
			for alive(pid) {
				if time.Now().After(deadline) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("%s (pid %d) outlived the daemon that started it", tc, pid)
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

// alive reports whether pid is a live, non-zombie process.
func alive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	if i := strings.LastIndex(s, ")"); i >= 0 && i+2 < len(s) {
		return s[i+2] != 'Z'
	}
	return true
}

// TestHelperDaemonForDeathSig is the "daemon" of the test above: it starts
// the staging work and exits once the tool is running.
func TestHelperDaemonForDeathSig(t *testing.T) {
	tool := os.Getenv("LXC_DEATHSIG_HELPER")
	if tool == "" {
		t.Skip("helper process only")
	}
	dir := os.Getenv("LXC_DEATHSIG_DIR")
	pidf := filepath.Join(dir, "child.pid")
	go func() {
		switch tool {
		case "umoci":
			dest := filepath.Join(dir, "lib", "web")
			_ = PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.22", Dest: dest})
		case "lxc-create":
			r := &LxcRunner{Lxcpath: filepath.Join(dir, "store")}
			_ = r.FetchImage(context.Background(), CreateOpts{Name: "web", Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"})
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(pidf); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			t.Fatalf("the tool did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	os.Exit(0) // the daemon dies with the tool still running
}

// A tool's own children (lxc-create's download template runs tar and
// friends) are not covered by the parent-death signal, so the start-up
// sweep also stops any process still working inside the staging
// directories before it removes them.
func TestStartupSweepStopsAProcessStillInTheStage(t *testing.T) {
	for _, tc := range []string{"fetch", "unpack"} {
		t.Run(tc, func(t *testing.T) {
			store, lib := t.TempDir(), t.TempDir()
			var work string
			if tc == "fetch" {
				work = filepath.Join(store, fetchDirName, "web", "web", "rootfs")
			} else {
				work = filepath.Join(lib, unpackDirName, "web+1", "rootfs")
			}
			if err := os.MkdirAll(work, 0o755); err != nil {
				t.Fatal(err)
			}
			// A writer that keeps creating files in the stage, from inside it.
			w := exec.Command("/bin/sh", "-c", "while :; do touch f.$$.$RANDOM 2>/dev/null; sleep 0.01; done")
			w.Dir = work
			if err := w.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _ = w.Wait(); close(done) }()
			t.Cleanup(func() { _ = w.Process.Kill(); <-done })
			time.Sleep(100 * time.Millisecond)
			var err error
			if tc == "fetch" {
				err = (&LxcRunner{Lxcpath: store}).SweepFetchDir()
			} else {
				err = RecoverOCILibrary(lib)
			}
			if err != nil {
				t.Fatalf("sweep with a live writer in the stage: %v", err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the process working in the stage was left running")
			}
			if _, err := os.Stat(work); err == nil {
				t.Error("the stage survived the sweep")
			}
		})
	}
}

// The sweep reads /proc/<pid>/{cwd,root,fd}, which the kernel renders
// relative to each process's own namespace root. A process in another mount
// namespace (a container, a nested litevirt) whose own path is spelled like
// the stage is not in the stage, and must survive the sweep.
func TestStartupSweepSparesAnotherMountNamespace(t *testing.T) {
	if err := exec.Command("unshare", "-Urm", "true").Run(); err != nil {
		t.Skipf("user and mount namespaces unavailable: %v", err)
	}
	store := t.TempDir()
	if err := os.MkdirAll(filepath.Join(store, fetchDirName, "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	script := "mount -t tmpfs none " + store + " && mkdir -p " + store + "/" + fetchDirName + "/x && cd " + store + "/" + fetchDirName + "/x && touch " + ready + " && exec sleep 30"
	c := exec.Command("unshare", "-Urm", "sh", "-c", script)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	t.Cleanup(func() { _ = c.Process.Kill(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the other-namespace process did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	cwd, _ := os.Readlink("/proc/" + strconv.Itoa(c.Process.Pid) + "/cwd")
	if !strings.HasPrefix(cwd, filepath.Join(store, fetchDirName)) {
		t.Skipf("the kernel renders its cwd as %q here; nothing to tell apart", cwd)
	}
	if err := (&LxcRunner{Lxcpath: store}).SweepFetchDir(); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	select {
	case <-done:
		t.Fatal("a process in another mount namespace, not in the stage, was killed by the sweep")
	case <-time.After(1 * time.Second):
	}
}

// A pull holds a file lock on the item that another process (lv ct pull
// --local) also takes, so the two never touch the item's staging entries
// at once.
func TestPullOCI_HoldsTheItemsFileLock(t *testing.T) {
	fakeOCITools(t, false)
	dest := filepath.Join(t.TempDir(), "web")
	release, err := lockItemFile(context.Background(), dest)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: dest}) }()
	select {
	case err := <-done:
		release()
		t.Fatalf("the pull did not wait for the item's file lock (%v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A process in another mount namespace that is working in the stage itself
// (the same directory, by device and inode) is stopped like any other.
func TestStartupSweepStopsAnotherNamespaceInTheStage(t *testing.T) {
	if err := exec.Command("unshare", "-Urm", "true").Run(); err != nil {
		t.Skipf("user and mount namespaces unavailable: %v", err)
	}
	store := t.TempDir()
	work := filepath.Join(store, fetchDirName, "web")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	c := exec.Command("unshare", "-Urm", "sh", "-c", "cd "+work+" && touch "+ready+" && exec sleep 30")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	t.Cleanup(func() { _ = c.Process.Kill(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the other-namespace process did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := (&LxcRunner{Lxcpath: store}).SweepFetchDir(); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a process working in the stage from another mount namespace was left running")
	}
}

// A pull in another process (lv ct pull --local) holds its item's flock for
// its whole run. A daemon start leaves that item's staging alone: it neither
// stops the lock holder nor removes its live stage.
func TestStartupRecoverySparesAPullHoldingTheItemLock(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock(1) not installed")
	}
	lib := t.TempDir()
	stage := filepath.Join(lib, unpackDirName, "web+7")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(lib, unpackDirName, "web"+lockSuffix)
	ready := filepath.Join(t.TempDir(), "ready")
	c := exec.Command("flock", lock, "sh", "-c", "cd "+stage+" && touch "+ready+" && exec sleep 30")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	t.Cleanup(func() { _ = c.Process.Kill(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the lock holder did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := RecoverOCILibrary(lib); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	select {
	case <-done:
		t.Fatal("start-up recovery killed a pull holding the item's lock")
	case <-time.After(1 * time.Second):
	}
	if _, err := os.Stat(stage); err != nil {
		t.Fatal("start-up recovery removed the live stage of a pull holding the item's lock")
	}
}

type fakeStat struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (f fakeStat) Sys() any { return f.st }

// The stage's objects are matched by device AND inode: an object on another
// filesystem with the same inode number is not in the stage.
func TestStageObjectsMatchDeviceAndInode(t *testing.T) {
	dir := t.TempDir()
	objs := stageObjects(dir)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := *fi.Sys().(*syscall.Stat_t)
	if !objs[devInoOf(fakeStat{fi, &st})] {
		t.Fatal("the stage directory itself is not among its objects")
	}
	other := st
	other.Dev++
	if objs[devInoOf(fakeStat{fi, &other})] {
		t.Fatal("an object with the stage's inode number on another device counts as the stage")
	}
}

// Waiting for an item's lock honours the caller: a cancelled pull returns
// instead of waiting for another process's pull to finish.
func TestPullOCI_TheLockWaitHonoursCancel(t *testing.T) {
	fakeOCITools(t, false)
	dest := filepath.Join(t.TempDir(), "web")
	release, err := lockItemFile(context.Background(), dest)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- PullOCI(ctx, PullOCIOptions{Image: "alpine:3.21", Dest: dest}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a pull whose item is locked elsewhere succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a cancelled pull kept waiting for the item's lock")
	}
}
