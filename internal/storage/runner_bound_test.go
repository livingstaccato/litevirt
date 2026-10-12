package storage

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// F-3: the storage runner returns within its context's bound even when a
// child the command forked keeps the output pipe open — mount's mount.nfs,
// reparented to init once mount is killed. On lab 2 the 30 s mount took
// three minutes, the pool reading active all along.
//
// Mutation "realCmd without cmdbound" (plain exec.CommandContext) — the call
// waits for the child's 60 s: red.
func TestRealCmd_ReturnsWithinItsBoundWhenAChildHoldsThePipe(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	_, err := realCmd(ctx, "sh", "-c", `setsid sh -c 'echo $$ > "$1"; exec sleep 60' sh "$0" & wait`, pidFile)
	took := time.Since(t0)
	t.Cleanup(func() {
		if b, rerr := os.ReadFile(pidFile); rerr == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	if err == nil {
		t.Fatal("a command killed by its deadline returned no error")
	}
	if took > 10*time.Second {
		t.Fatalf("realCmd returned after %v; want within its 500ms bound plus the wait delay", took)
	}
}
