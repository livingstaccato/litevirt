package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func TestReceiverCurrentCancellationAtRealWaits(t *testing.T) {
	for _, mode := range []string{"pki-owner", "client-mutex"} {
		t.Run(mode, func(t *testing.T) {
			f := currentProofFixture(t)
			p, err := f.receiver.VerifyCurrent(context.Background(), f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			var release func()
			if mode == "pki-owner" {
				view, e := pki.CaptureHostTrust(context.Background(), f.local.pki, f.local.name)
				if e != nil {
					t.Fatal(e)
				}
				pair, e := pki.ServedHostKeyPair(f.local.pki)
				if e != nil {
					t.Fatal(e)
				}
				cap, e := view.ValidateServedHost(context.Background(), pair)
				if e != nil {
					t.Fatal(e)
				}
				lease, e := pki.AcquireHostCertificateLease(context.Background(), f.local.pki, cap)
				if e != nil {
					t.Fatal(e)
				}
				release = lease.Release
			} else {
				f.local.c.mu.Lock()
				release = f.local.c.mu.Unlock
			}
			released := false
			defer func() {
				if !released {
					release()
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- f.receiver.consumeCurrent(ctx, p) }()
			deadline := time.Now().Add(2 * time.Second)
			for f.receiver.mu.TryLock() {
				f.receiver.mu.Unlock()
				if time.Now().After(deadline) {
					t.Fatal("consumer never acquired actual receiver owner")
				}
				time.Sleep(time.Millisecond)
			}
			select {
			case early := <-result:
				t.Fatal("consumer crossed held actual owner", early)
			case <-time.After(30 * time.Millisecond):
			}
			// The held real owner prevents any transaction entry. Cancellation must
			// consume this proof even when the waited-on owner is subsequently released.
			cancel()
			release()
			released = true
			select {
			case err = <-result:
			case <-time.After(3 * time.Second):
				t.Fatal("canceled wait did not finish")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatal("real waited cancellation not reported", err)
			}
			if err = f.receiver.consumeCurrent(context.Background(), p); err == nil {
				t.Fatal("canceled waited proof revived")
			}
			fresh, err := f.receiver.VerifyCurrent(context.Background(), f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.receiver.consumeCurrent(context.Background(), fresh); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReceiverCurrentActualSQLiteSnapshotRefusal(t *testing.T) {
	f := currentProofFixture(t)
	ctx := context.Background()
	p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	other, err := sql.Open("sqlite", f.local.c.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.Exec(`CREATE TABLE current_snapshot_probe(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	// The consumer already read its real snapshot. Another connection commits a
	// harmless probe, then an attempted write in that old snapshot must fail.
	reached := false
	f.receiver.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
		reached = true
		if _, e := other.Exec(`INSERT INTO current_snapshot_probe(id) VALUES(1)`); e != nil {
			return e
		}
		_, e := tx.Exec(`UPDATE local_automation_receiver_current SET attempt=attempt WHERE id=1`)
		return e
	}}
	err = f.receiver.consumeCurrent(ctx, p)
	if !reached || err == nil || (!strings.Contains(err.Error(), "locked") && !strings.Contains(err.Error(), "BUSY")) {
		t.Fatal("real SQLite snapshot conflict not refused", reached, err)
	}
	f.receiver.seams = nil
	fresh, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.receiver.consumeCurrent(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if err = f.receiver.consumeCurrent(ctx, p); err == nil {
		t.Fatal("failed snapshot proof revived")
	}
}
