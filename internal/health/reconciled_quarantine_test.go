package health

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
)

const (
	rqUUID    = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"
	rqAttempt = "6f1c0c5e-0a43-4c55-9b5e-2b2b1f4d0e11"
)

// reconciledAt writes a reconciler quarantine of vm set aside at at.
func reconciledAt(t *testing.T, dataDir, vm string, at time.Time) string {
	t.Helper()
	p := filepath.Join(dataDir, fwmig.QuarantineDir, fmt.Sprintf("%s%s%d", vm, reconciledInfix, at.Unix()))
	for _, f := range []string{"nvram", "reason.txt", filepath.Join("swtpm", "tpm2", "tpm2-00.permall")} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(p, f)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, f), []byte("state"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// D2-18 re-review 3, m-1: the reconciler's firmware quarantines follow the
// superseded-disk rule. Once the VM is gone, one older than the retention is
// removed by the sweep and one inside it is kept; while a VM of the name
// exists it is retained whatever its age; while the VM's firmware move state
// is unresolved (a record on this host, an open owed DISCARD) it is held, even
// from a named removal; an unfinished quarantine is held. A doctor quarantine
// (<vm>-<attempt>) is not touched.
//
// Mutations: drop the age check — red (young); drop the retention of an
// existing VM — red (alive); drop the record hold — red (leftover); drop the
// owed-DISCARD condition hold — red (owed); purge an unfinished quarantine —
// red (staging); drop the quarantine sweep from SweepSetAside — red (old).
func TestReconciledQuarantine_Retention(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dataDir := t.TempDir()
	now := time.Now()
	retention := 7 * 24 * time.Hour
	old := now.Add(-8 * 24 * time.Hour)

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "alive", HostName: "node-b", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := fwmig.New(dataDir).PutLeftover(fwmig.Leftover{VM: "leftover",
		Binding: fwmig.Binding{UUID: rqUUID, CreatedAt: "2026-10-01T00:00:00Z", Attempt: rqAttempt},
		Source:  "node-b", Since: now}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{Evaluator: "firmware_migration",
		Code: "firmware_migration_discard_owed", SubjectKind: "vm", SubjectID: "owed",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical}); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{
		"old":     reconciledAt(t, dataDir, "gone", old),
		"young":   reconciledAt(t, dataDir, "gone", now.Add(-24*time.Hour)),
		"alive":   reconciledAt(t, dataDir, "alive", old),
		"left":    reconciledAt(t, dataDir, "leftover", old),
		"owed":    reconciledAt(t, dataDir, "owed", old),
		"staging": filepath.Join(dataDir, fwmig.QuarantineDir, reconcilingName("gone2", rqUUID)),
		"doctor":  filepath.Join(dataDir, fwmig.QuarantineDir, "gone-"+rqAttempt),
	}
	for _, k := range []string{"staging", "doctor"} {
		if err := os.MkdirAll(paths[k], 0o700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(paths[k], old, old)
	}

	qs, err := ListReconciledQuarantines(ctx, db, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ReconciledQuarantine{}
	for _, q := range qs {
		by[q.Path] = q
	}
	if _, ok := by[paths["doctor"]]; ok {
		t.Error("a doctor quarantine is listed as a reconciled one")
	}
	if q := by[paths["alive"]]; q.Retained == "" {
		t.Errorf("alive: %+v, want retained", q)
	}
	for _, k := range []string{"left", "owed", "staging"} {
		if q := by[paths[k]]; q.Held == "" {
			t.Errorf("%s: %+v, want held", k, q)
		}
	}
	if q := by[paths["old"]]; q.VM != "gone" || q.SizeBytes == 0 || q.Held != "" || q.Retained != "" {
		t.Errorf("old: %+v", q)
	}

	// A named removal of a held one is refused, and removes nothing.
	if _, err := RemoveReconciledQuarantines(ctx, db, dataDir, []string{paths["left"]}); err == nil || !strings.Contains(err.Error(), "held") {
		t.Errorf("named removal of a held quarantine: %v", err)
	}

	SweepSetAside(ctx, db, dataDir, retention, now, nil)
	for k, p := range paths {
		want := k != "old"
		if exists(p) != want {
			t.Errorf("%s (%s): exists %v after the sweep, want %v", k, p, exists(p), want)
		}
	}

	// A named removal takes a retained one.
	gone, err := RemoveReconciledQuarantines(ctx, db, dataDir, []string{paths["alive"]})
	if err != nil || len(gone) != 1 || exists(paths["alive"]) {
		t.Errorf("named removal of a retained quarantine: %v %+v", err, gone)
	}
	if IsReconciledQuarantinePath(dataDir, paths["doctor"]) || !IsReconciledQuarantinePath(dataDir, paths["young"]) ||
		!IsReconciledQuarantinePath(dataDir, paths["staging"]) {
		t.Error("IsReconciledQuarantinePath")
	}
}

// D2-18 re-review 4, n-1: a VM row that cannot be read holds that entry,
// named with the error, and the listing goes on: it does not fail, and so does
// not take the disk-copy listing with it.
//
// Mutation: fail the listing on the read error — red.
func TestReconciledQuarantine_UnreadableRowHoldsThatEntry(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dataDir := t.TempDir()
	p := reconciledAt(t, dataDir, "gone", time.Now().Add(-30*24*time.Hour))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	qs, err := ListReconciledQuarantines(ctx, db, dataDir)
	if err != nil {
		t.Fatalf("the listing failed on one unreadable row: %v", err)
	}
	if len(qs) != 1 || qs[0].Path != p || !strings.Contains(qs[0].Held, "cannot be read") {
		t.Fatalf("listing %+v, want the entry held naming the read error", qs)
	}
	if gone, _ := PurgeReconciledQuarantines(ctx, db, dataDir, 0, time.Now()); len(gone) != 0 || !exists(p) {
		t.Fatalf("an entry whose VM row cannot be read was purged: %+v", gone)
	}
}
