package fleet

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/litevirt/litevirt/internal/lbtestproc"
)

// Private runtime children survive another fixture's cleanup, even when both
// use the same configuration names. They also cannot match the shell-pattern
// cleanup still used by older branches. Closing the owner kills and reaps its
// children before returning.
func TestLBStandIns_AnotherRunsCleanupLeavesThemAlone(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "shared.conf")
	var owner *lbtestproc.Runtime
	var ownedPID int
	t.Run("run", func(t *testing.T) {
		owner = lbtestproc.New(t, true)
		other := lbtestproc.New(t, true)
		for _, runtime := range []*lbtestproc.Runtime{owner, other} {
			pidfile := filepath.Join(runtime.Dir, "keepalived.pid")
			if err := runtime.StartKeepalived(cfg, pidfile); err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.Run(context.Background(), "conntrackd", "-C", cfg, "-d"); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(pidfile)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(b))
			if err != nil {
				t.Fatal(err)
			}
			if runtime == owner {
				ownedPID = pid
			}
			cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
			if err != nil {
				t.Fatal(err)
			}
			legacy := regexp.MustCompile("sleep 600; : .*" + regexp.QuoteMeta(t.Name()))
			if legacy.MatchString(strings.ReplaceAll(string(cmdline), "\x00", " ")) {
				t.Fatalf("owned child matches another branch's cleanup: %q", cmdline)
			}
		}
		other.Close()
		for _, bin := range []string{"keepalived", "conntrackd"} {
			if !owner.ConfigAlive(bin, cfg) || other.ConfigAlive(bin, cfg) {
				t.Fatalf("%s cleanup did not preserve the other owner", bin)
			}
		}
	})
	if owner == nil {
		return
	}
	for _, bin := range []string{"keepalived", "conntrackd"} {
		if owner.ConfigAlive(bin, cfg) {
			t.Errorf("%s outlived its owner cleanup", bin)
		}
	}
	if ownedPID > 0 && syscall.Kill(ownedPID, 0) != syscall.ESRCH {
		t.Errorf("owned keepalived child %d was not reaped", ownedPID)
	}
}
