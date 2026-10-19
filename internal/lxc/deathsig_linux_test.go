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
