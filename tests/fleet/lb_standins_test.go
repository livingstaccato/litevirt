package fleet

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// standInProcs is every live process whose command line names dir: the
// keepalived and conntrackd stand-ins lbStandIns leaves running.
func standInProcs(t *testing.T, dir string) map[int]string {
	t.Helper()
	out := map[int]string{}
	matches, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, cf := range matches {
		data, err := os.ReadFile(cf)
		if err != nil {
			continue
		}
		cmdline := strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
		if !strings.Contains(cmdline, dir) {
			continue
		}
		pid, err := strconv.Atoi(filepath.Base(filepath.Dir(cf)))
		if err != nil {
			continue
		}
		if st, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")); err == nil {
			if f := strings.Fields(string(st)); len(f) > 2 && f[2] == "Z" {
				continue // exited, waiting to be reaped
			}
		}
		out[pid] = cmdline
	}
	return out
}

// TestLBStandIns_AnotherRunsCleanupLeavesThemAlone: the keepalived and
// conntrackd stand-ins cannot be matched by the cleanup that other branches'
// copies of this harness still run, and this run's cleanup kills exactly its
// own stand-ins.
//
// Every branch without the per-run cleanup ends each LB test with
// `pkill -f "sleep 600; : .*<test name>"`. The stand-ins' command lines name
// their temp dir, which names the test, so one such cleanup anywhere on the
// host killed the stand-ins of every process running the same test at that
// moment; the next apply in each found keepalived and conntrackd dead and
// started them again, and LBSNATNoFlapAcrossApplyPaths counted 4 starts.
// On kvm003, 12 of 12 processes restarted both at 19:06:38 on 2026-10-17,
// the second another worktree's fleet shard finished that test.
//
// Mutations (each red): the stand-ins' shell runs 'sleep 600; :' again; the
// cleanup kills nothing.
func TestLBStandIns_AnotherRunsCleanupLeavesThemAlone(t *testing.T) {
	var dir string
	var pids map[int]string
	t.Run("run", func(t *testing.T) {
		dir = lbStandIns(t)
		pidf := filepath.Join(dir, "k.pid")
		for _, c := range [][]string{
			{"keepalived", "-f", filepath.Join(dir, "k.conf"), "-p", pidf},
			{"conntrackd", "-C", filepath.Join(dir, "c.conf"), "-d"},
		} {
			if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
				t.Fatalf("%s: %v: %s", c[0], err, out)
			}
		}
		pids = standInProcs(t, dir)
		if len(pids) != 2 {
			t.Fatalf("stand-ins running: %v, want keepalived's and conntrackd's", pids)
		}
		// The cleanup every branch before the per-run one runs, with the
		// test name this run's temp dirs carry.
		legacy := regexp.MustCompile("sleep 600; : .*" + regexp.QuoteMeta(filepath.Base(filepath.Dir(dir))))
		for pid, cmdline := range pids {
			if legacy.MatchString(cmdline) {
				t.Errorf("stand-in %d (%q) is matched by another run's cleanup %q", pid, cmdline, legacy)
			}
		}
	})
	// The subtest's cleanup has run: every stand-in it started is gone.
	deadline := time.Now().Add(5 * time.Second)
	for {
		alive := standInProcs(t, dir)
		if len(alive) == 0 {
			break
		}
		if time.Now().After(deadline) {
			for pid := range alive {
				syscall.Kill(pid, syscall.SIGKILL) //nolint:errcheck // this test's own stand-ins
			}
			t.Fatalf("stand-ins %v outlived their test's cleanup (started: %v)", alive, pids)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestLBStandIns_KilledTestLeavesNoneBehind: a test process killed before
// t.Cleanup runs (a timeout, a SIGKILL, kbuild rebuilding the tree under a
// running shard) must not leave its stand-ins running. On kvm003, 26
// `sleep 600` stand-ins were orphaned this way on 2026-10-19.
//
// Mutation (red): the stand-ins sleep for a fixed 600 seconds again instead
// of polling their test process.
func TestLBStandIns_KilledTestLeavesNoneBehind(t *testing.T) {
	if os.Getenv("LB_STANDIN_HELPER") == "1" {
		dir := lbStandIns(t)
		for _, c := range [][]string{
			{"keepalived", "-f", filepath.Join(dir, "k.conf"), "-p", filepath.Join(dir, "k.pid")},
			{"conntrackd", "-C", filepath.Join(dir, "c.conf"), "-d"},
		} {
			if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
				t.Fatalf("%s: %v: %s", c[0], err, out)
			}
		}
		os.WriteFile(os.Getenv("LB_STANDIN_DIRFILE"), []byte(dir), 0o644) //nolint:errcheck
		time.Sleep(time.Minute)                                           // killed by the parent
		return
	}
	dirFile := filepath.Join(t.TempDir(), "dir")
	cmd := exec.Command(os.Args[0], "-test.run", "^TestLBStandIns_KilledTestLeavesNoneBehind$")
	cmd.Env = append(os.Environ(), "LB_STANDIN_HELPER=1", "LB_STANDIN_DIRFILE="+dirFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill() //nolint:errcheck
	var dir string
	deadline := time.Now().Add(20 * time.Second)
	for dir == "" {
		if b, err := os.ReadFile(dirFile); err == nil {
			dir = string(b)
		} else if time.Now().After(deadline) {
			t.Fatal("helper never started its stand-ins")
		} else {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if n := len(standInProcs(t, dir)); n != 2 {
		t.Fatalf("stand-ins running: %d, want 2", n)
	}
	cmd.Process.Kill() //nolint:errcheck // no t.Cleanup runs in the helper
	cmd.Wait()         //nolint:errcheck
	deadline = time.Now().Add(10 * time.Second)
	for {
		alive := standInProcs(t, dir)
		if len(alive) == 0 {
			return
		}
		if time.Now().After(deadline) {
			for pid := range alive {
				syscall.Kill(pid, syscall.SIGKILL)                            //nolint:errcheck
				exec.Command("pkill", "-KILL", "-P", strconv.Itoa(pid)).Run() //nolint:errcheck
			}
			t.Fatalf("stand-ins %v outlived their killed test", alive)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
