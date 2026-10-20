package lxc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeLxcAttach puts an lxc-attach on PATH that forks its command (as the
// real one forks into the container) and waits for it.
func fakeLxcAttach(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done; shift\n\"$@\" &\nwait $!\n"
	if err := os.WriteFile(filepath.Join(bin, "lxc-attach"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// ExecStarted reports the attach once lxc-attach has forked into the
// container, while the command still runs, not when it ends.
func TestExecStarted_ReportsTheAttachWhileTheCommandRuns(t *testing.T) {
	fakeLxcAttach(t)
	r := &LxcRunner{Lxcpath: t.TempDir()}
	var at time.Time
	start := time.Now()
	res, err := r.ExecStarted(context.Background(), "web", []string{"sleep", "1"}, func() { at = time.Now() })
	end := time.Now()
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("exec: %v %+v", err, res)
	}
	if at.IsZero() {
		t.Fatal("the attach was never reported")
	}
	if at.Sub(start) > 500*time.Millisecond || end.Sub(at) < 500*time.Millisecond {
		t.Fatalf("attach reported %v after the start and %v before the end; want it early", at.Sub(start), end.Sub(at))
	}
}

// An lxc-attach that exits without forking (the container is not running)
// reports no attach.
func TestExecStarted_NoAttachNoReport(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "lxc-attach"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	called := false
	_, _ = (&LxcRunner{Lxcpath: t.TempDir()}).ExecStarted(context.Background(), "web", []string{"true"}, func() { called = true })
	if called {
		t.Fatal("an exec that never attached was reported attached")
	}
}

// On a kernel that cannot list a process's children, the attach cannot be
// seen, so it is never reported: the caller keeps its lock for the exec.
func TestExecStarted_NoChildrenFileNoReport(t *testing.T) {
	fakeLxcAttach(t)
	prev := procChildren
	t.Cleanup(func() { procChildren = prev })
	procChildren = func(int) string { return filepath.Join(t.TempDir(), "no-such-file") }
	called := false
	if _, err := (&LxcRunner{Lxcpath: t.TempDir()}).ExecStarted(context.Background(), "web", []string{"sleep", "0.3"}, func() { called = true }); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("an attach that could not be seen was reported")
	}
}
