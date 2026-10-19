package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

// captureSchemaLog routes slog to a buffer for the test and returns a reader
// of the ledger records: message → the migration ids logged under it.
func captureSchemaLog(t *testing.T) func() map[string][]string {
	t.Helper()
	var buf bytes.Buffer
	prev, prevW, prevF := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevW)
		log.SetFlags(prevF)
	})
	return func() map[string][]string {
		out := map[string][]string{}
		for _, line := range strings.Split(buf.String(), "\n") {
			var rec struct {
				Msg   string `json:"msg"`
				Level string `json:"level"`
				ID    string `json:"id"`
			}
			if json.Unmarshal([]byte(line), &rec) != nil || !strings.HasPrefix(rec.Msg, "schema ledger:") {
				continue
			}
			out[rec.Level+" "+rec.Msg] = append(out[rec.Level+" "+rec.Msg], rec.ID)
		}
		return out
	}
}

const silentGapWarn = "WARN schema ledger: healed a missing migration (silent gap from a prior daemon)"

// A migration newer than the version the database was stamped at is the
// upgrade itself, not a gap a prior daemon left: an upgrade logs no
// silent-gap WARN for the columns and tables it adds (lab eqts-26, A4).
func TestInitSchema_UpgradeIsNotASilentGap(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	buildV42DB(t, c)
	// buildV42DB leaves out the columns only an ALTER adds, at every version.
	// A database a v42 daemon ran holds those up to v42, so add them: only the
	// post-v42 ones are left for the upgrade.
	for i, sql := range schemaMigrations {
		if alterVersions[i] > 42 {
			continue
		}
		table, col := parseAddColumn(sql)
		if ok, err := columnExists(ctx, c.db, table, col); err != nil || ok {
			continue
		}
		if err := c.execLocal(ctx, sql); err != nil {
			t.Fatalf("v42 column %s.%s: %v", table, col, err)
		}
	}
	records := captureSchemaLog(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema v42 → current: %v", err)
	}
	got := records()
	if ids := got[silentGapWarn]; len(ids) > 0 {
		t.Fatalf("an upgrade from v42 logged %d silent-gap WARNs, first %q", len(ids), ids[0])
	}
	if len(got["INFO schema ledger: applied a migration of this upgrade"]) == 0 {
		t.Fatalf("an upgrade from v42 logged no applied migration; records %v", got)
	}
}

// A migration at or below the stamped version that is missing is a genuine
// gap, and keeps its WARN.
func TestInitSchema_SilentGapStillWarns(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	buildLegacyV28DB(t, c)
	if err := c.execLocal(ctx, `ALTER TABLE containers DROP COLUMN on_host_failure`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	records := captureSchemaLog(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	ids := records()[silentGapWarn]
	if !slices.ContainsFunc(ids, func(id string) bool { return strings.HasSuffix(id, "_containers_on_host_failure") }) {
		t.Fatalf("silent-gap WARNs %v, want one for the dropped containers.on_host_failure", ids)
	}
}
