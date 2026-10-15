package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

type fwNoVirt struct{}

func (fwNoVirt) SetFirmwareMoveGuard(lv.FirmwareMoveGuard) {}

// A firmware move record that cannot be read refuses, host-wide, every call
// that carries a uuid; it is raised as a critical host condition naming the
// file and the remedy, with every wipe it refused (each also an event on its
// VM, the state still on disk), and resolved once the file reads (review I-1).
//
// Mutations: judgeFirmwareMoveRecords raising nothing — red; dropping the
// refused wipes — red; never resolving — red.
func TestFirmwareRecordUnreadable_RaisedNamedAndResolved(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	s := NewServerForTests(TestServerOpts{HostName: "h1", DataDir: dir, DB: db})
	fwmig.Wire(fwNoVirt{}, s.fw())

	bad := filepath.Join(dir, fwmig.HoldDir, "vm9.json")
	if err := os.MkdirAll(filepath.Dir(bad), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Another VM's delete wipes its firmware state: refused, still on disk.
	const id = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"
	s.fw().SwtpmBase = t.TempDir()
	tree := filepath.Join(s.fw().SwtpmDir(id), "tpm2")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	s.fw().WipeFirmwareState("web", id)
	if _, err := os.Stat(tree); err != nil {
		t.Fatalf("the refused wipe removed the state: %v", err)
	}

	s.judgeFirmwareMoveRecords(ctx)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, firmwareMoveEvaluator, condFirmwareRecordUnreadable, "host", "h1")
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved || row.Severity != corrosion.SeverityCritical {
		t.Fatalf("condition = %+v found=%v err=%v, want raised critical", row, found, err)
	}
	for _, want := range []string{bad, "repair the file", `"vm":"web"`, id} {
		if !strings.Contains(row.Evidence, want) {
			t.Errorf("evidence lacks %q: %s", want, row.Evidence)
		}
	}
	evs, err := corrosion.ListVMEvents(ctx, s.db, "web", 10, "")
	if err != nil || len(evs) != 1 || evs[0].Type != eventFirmwareStateWipeRefused || !strings.Contains(evs[0].Detail, "still on disk") {
		t.Fatalf("events of web = %+v (%v), want one %s", evs, err, eventFirmwareStateWipeRefused)
	}

	// A second pass keeps naming the refused wipe.
	s.judgeFirmwareMoveRecords(ctx)
	row, _, _ = corrosion.GetHealthCondition(ctx, s.db, firmwareMoveEvaluator, condFirmwareRecordUnreadable, "host", "h1")
	if row.Lifecycle != corrosion.ConditionConfirmed || !strings.Contains(row.Evidence, `"vm":"web"`) {
		t.Fatalf("second pass: %+v", row)
	}

	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}
	s.judgeFirmwareMoveRecords(ctx)
	row, _, _ = corrosion.GetHealthCondition(ctx, s.db, firmwareMoveEvaluator, condFirmwareRecordUnreadable, "host", "h1")
	if row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("after the file was removed: %+v, want resolved", row)
	}
}
