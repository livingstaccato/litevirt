package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestRunPendingAuditFold_FoldsAtStart: the first pass runs as the loop starts,
// not a tick later, so a reset made while the daemon was down is on the record
// as soon as the daemon is.
func TestRunPendingAuditFold_FoldsAtStart(t *testing.T) {
	dir := t.TempDir()
	db, err := corrosion.NewLocalClient(dir, "node-0")
	if err != nil {
		t.Fatalf("NewLocalClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	j, err := corrosion.OpenPendingAuditJournal(dir)
	if err != nil {
		t.Fatalf("OpenPendingAuditJournal: %v", err)
	}
	if err := j.Record(&corrosion.PendingAuditEntry{Action: "user.reset-admin", Target: "admin", Result: "ok"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	j.Close()

	d := &Daemon{db: db, cfg: &Config{HostName: "node-0", DataDir: dir}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.runPendingAuditFold(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	// Well inside the 30s interval: only the first pass can have folded it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, err := db.Query(context.Background(), `SELECT id FROM audit_log WHERE action = 'user.reset-admin'`)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(rows) == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d user.reset-admin rows 5s after start, want 1 from the first pass", len(rows))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
