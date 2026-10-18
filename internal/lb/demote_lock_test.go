package lb

import (
	"context"
	"github.com/litevirt/litevirt/internal/lbtestproc"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDemoteByName_ReadsCurrentConfigUnderApplyLock(t *testing.T) {
	root := t.TempDir()
	m := NewManagerAt(filepath.Join(root, "config"), filepath.Join(root, "run"))
	r := lbtestproc.New(t, false)
	m.SetProcessRuntime(r)
	cfg := stickyRedirectConfig()
	cfg.Interface = "fleet0"
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	parked, unpark := make(chan struct{}), make(chan struct{})
	entered, done, applied := make(chan struct{}), make(chan struct{}), make(chan struct{})
	order := make(chan string, 3)
	var entryOnce, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(unpark) }) }
	m.ownershipObservation = func(operation, event string) {
		if operation == "apply" && event == "locked" {
			close(parked)
			<-unpark
		}
		if operation == "demote" && event == "entry" {
			entryOnce.Do(func() { close(entered) })
		}
		if operation == "demote" && (event == "read" || event == "locking") {
			order <- event
		}
	}
	current := cfg
	current.VIP = "10.0.1.101"
	current.VIPPrefix = 25
	current.Interface = "fleet1"
	var applyErr, demoteErr error
	demoteStarted := false
	t.Cleanup(func() {
		release()
		select {
		case <-applied:
		case <-time.After(5 * time.Second):
			t.Error("actual concurrent Apply failed to join")
		}
		if demoteStarted {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("actual by-name demotion failed to join")
			}
		}
	})
	go func() { defer close(applied); applyErr = m.Apply(context.Background(), current) }()
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("actual Apply never owned the per-LB lock")
	}
	demoteStarted = true
	go func() { defer close(done); demoteErr = m.DemoteByName(cfg.Name, time.Second) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("actual by-name entry absent")
	}
	select {
	case event := <-order:
		if event != "locking" {
			t.Error("by-name demotion read config before owning Apply lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual demotion did not reach read/lock boundary")
	}
	release()
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("actual replacement Apply did not finish")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("actual demotion did not finish")
	}
	if applyErr != nil || demoteErr != nil {
		t.Fatal(applyErr, demoteErr)
	}
	if r.Starts["keepalived"] != 2 {
		t.Error("actual changed-config Apply did not replace child", r.Starts)
	}
	if m.KeepalivedRunning(cfg.Name) {
		t.Error("actual replacement child remains alive after demotion")
	}
	b, err := os.ReadFile(filepath.Join(r.Dir, "ip.calls"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "addr del 10.0.1.101/25 dev fleet1" {
		t.Error("demotion deleted stale pre-lock VIP tuple", string(b))
	}
}
