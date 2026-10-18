package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// failedVars makes a vars file and a flush failure that identifies it.
func failedVars(t *testing.T, dir, vm string) libvirt.NvramFlushFailure {
	t.Helper()
	p := filepath.Join(dir, vm+"_VARS.fd")
	if err := os.WriteFile(p, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return libvirt.NvramFlushFailure{Path: p, VM: vm, Error: "input/output error", Dev: uint64(st.Dev), Ino: st.Ino}
}

// A vars file whose fsync failed raises nvram_flush_failed (critical) about
// this host, naming the file and its VM; the failure survives a daemon
// restart through the condition's evidence; the condition resolves once the
// file is gone.
func TestNvramFlushCondition_RaisedSurvivesRestartAndResolves(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "h1"}}
	dir := t.TempDir()
	fail := failedVars(t, dir, "web-1")

	f := libvirt.NewNvramFlusher(dir)
	f.Seed([]libvirt.NvramFlushFailure{fail})
	var last string
	d.syncNvramFlushCondition(ctx, f.Failures(), &last)

	row, found, err := corrosion.GetHealthCondition(ctx, db, nvramFlushEvaluator, CondNvramFlushFailed, "host", "h1")
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition after a failed flush: found=%v err=%v row=%+v", found, err, row)
	}
	if row.Severity != corrosion.SeverityCritical {
		t.Fatalf("severity %q, want critical", row.Severity)
	}
	if !strings.Contains(row.Evidence, fail.Path) || !strings.Contains(row.Evidence, `"vm":"web-1"`) || !strings.Contains(row.Evidence, "remedy") {
		t.Fatalf("evidence does not name the file, its VM and the remedy: %s", row.Evidence)
	}
	var ev nvramFlushEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || len(ev.Files) != 1 {
		t.Fatalf("evidence %s: %v", row.Evidence, err)
	}

	// A restart: the new flusher knows nothing until it is seeded from the
	// open condition.
	g := libvirt.NewNvramFlusher(dir)
	d.seedNvramFlushFailures(ctx, g)
	if got := g.Failures(); len(got) != 1 || got[0].Path != fail.Path {
		t.Fatalf("after a restart the flusher holds %+v; want %s", got, fail.Path)
	}

	// The file is removed: the condition resolves.
	g.Sweep()
	if err := os.Remove(fail.Path); err != nil {
		t.Fatal(err)
	}
	g.Sweep()
	last = ""
	d.syncNvramFlushCondition(ctx, g.Failures(), &last)
	row, _, _ = corrosion.GetHealthCondition(ctx, db, nvramFlushEvaluator, CondNvramFlushFailed, "host", "h1")
	if row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition after the file was removed: %+v", row)
	}
}

// The daemon flushes litevirt's vars directory and libvirt's.
func TestNvramDirs(t *testing.T) {
	got := nvramDirs("/srv/lv")
	want := []string{"/var/lib/libvirt/qemu/nvram", "/srv/lv/nvram"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("nvramDirs = %v, want %v", got, want)
	}
	if got := nvramDirs(""); len(got) != 1 {
		t.Fatalf("no data dir: nvramDirs = %v, want libvirt's only", got)
	}
}
