package daemon

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// TestRunAuditHold_LandsNothingBeforeTheKeyringIsWired is M-A: rows an earlier
// process left in the spool, whose history has since arrived, land on the
// hold's first poll. Landed before the signing keyring is installed they are
// written unsigned after a signed history — an unsigned-after-signed finding
// on every node. runAuditHold waits for wireAuditKeyring whatever order startup
// runs them in.
//
// Mutation: drop the wait at the top of runAuditHold — held-1 lands unsigned.
func TestRunAuditHold_LandsNothingBeforeTheKeyringIsWired(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const host = "node-0"
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	pkiDir := t.TempDir()
	caCert, caKey := filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(pkiDir, "host.crt"),
		filepath.Join(pkiDir, "host.key"), host, net.IPv4(127, 0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	serial, err := pki.CertSerial(filepath.Join(pkiDir, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	// The admitted history: the host's chain reached seq 2, and has not arrived.
	rj, err := corrosion.SignAuditRejoin(pkiDir, host, serial, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(rj)
	if err := os.WriteFile(filepath.Join(pkiDir, corrosion.AuditRejoinFileName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &Config{HostName: host, PKIDir: pkiDir, DataDir: t.TempDir()}, db: db}
	d.cfg.Enforcement.AuditSignature = true

	d.configureAuditHold(ctx)
	if err := corrosion.InsertAuditLog(ctx, db, corrosion.AuditRecord{ID: "held-1", HostName: host,
		Action: "vm.start", Target: "vm1", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	// The history arrives (written here by a client that is not holding).
	for _, id := range []string{"old-1", "old-2"} {
		if err := db.Execute(ctx, `INSERT INTO audit_log (id, timestamp, username, host_name, action, target,
			detail, result, prev_hash, content_hash, key_id, signature, seq)
			VALUES (?, '2026-10-01T00:00:00Z', 'u', ?, 'vm.start', 'x', '', 'ok', '', ?, '', '', ?)`,
			id, host, "h-"+id, map[string]int{"old-1": 1, "old-2": 2}[id]); err != nil {
			t.Fatal(err)
		}
	}

	go d.runAuditHold(ctx) // started before the keyring, on purpose
	time.Sleep(300 * time.Millisecond)
	if n := rowsWithID(t, db, "held-1"); n != 0 {
		t.Fatal("held-1 landed before the signing keyring was installed")
	}
	d.wireAuditKeyring(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for rowsWithID(t, db, "held-1") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("held-1 did not land after the keyring was wired")
		}
		time.Sleep(50 * time.Millisecond)
	}
	rows, err := db.Query(ctx, `SELECT signature, seq FROM audit_log WHERE id = 'held-1'`)
	if err != nil || len(rows) != 1 || rows[0].String("signature") == "" || rows[0].Int64("seq") != 3 {
		t.Fatalf("held-1: %v %v; want signed, at seq 3", rows, err)
	}
}

func rowsWithID(t *testing.T, db *corrosion.Client, id string) int {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id FROM audit_log WHERE id = ?`, id)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}
