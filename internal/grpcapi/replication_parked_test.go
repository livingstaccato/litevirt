package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A change this node holds because it cannot apply it raises
// replication_entry_parked, and the event detail names the sender, sequence
// and table, so the operator is told which change has not happened here.
func TestEvaluateHADegraded_ReportsAHeldChange(t *testing.T) {
	s := testServer(t)
	s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})
	ctx := context.Background()

	if got, _ := s.evaluateHADegraded(ctx); got[haReplicationParked] {
		t.Fatal("a node holding nothing reported replication_entry_parked")
	}

	if _, err := s.db.DB().Exec(`INSERT INTO snapshots (id, vm_name, host_name, name, state, created_at, updated_at)
		VALUES ('mine', 'vm', 'test-host', 's1', 'ok', '2026-01-01T00:00:00Z', '0000000000001-0000-test-host')`); err != nil {
		t.Fatal(err)
	}
	hlcTS := "1791898219346-0000-peer-a"
	stmts, _ := json.Marshal([]corrosion.Statement{{
		SQL: `INSERT OR REPLACE INTO snapshots (id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		Params: []interface{}{"theirs", "vm", "peer-a", "s1", "ok", 1, "disk", "", 0, "2026-10-12T00:00:00Z", hlcTS},
	}})
	if _, err := s.replicator.ApplyRemoteMutations(ctx, []*pb.MutationEntry{
		{Seq: 7, Hlc: hlcTS, Origin: "peer-a", Stmts: string(stmts)},
	}); err != nil {
		t.Fatalf("the refused change back-pressured instead of being held: %v", err)
	}

	got, _ := s.evaluateHADegraded(ctx)
	if !got[haReplicationParked] {
		t.Fatal("a node holding a change it cannot apply did not report replication_entry_parked")
	}
	d := s.replicationParkedDetail()
	for _, want := range []string{"peer-a", "seq 7", "snapshots", "UNIQUE"} {
		if !strings.Contains(d, want) {
			t.Errorf("event detail %q does not name %q", d, want)
		}
	}
}

// A change re-derived from an anti-entropy refusal has no sequence: the event
// names the refused row instead of "seq 0".
func TestParkedEntryDetail_NamesTheRowForAnAntiEntropyRefusal(t *testing.T) {
	ae := parkedEntryDetail(corrosion.ParkedEntry{Origin: "node-3", Table: "snapshots", RowID: "cc3197e1", Error: "UNIQUE", Source: "ae"})
	if !strings.Contains(ae, "row cc3197e1") || !strings.Contains(ae, "anti-entropy") || strings.Contains(ae, "seq") {
		t.Fatalf("anti-entropy detail = %q", ae)
	}
	wal := parkedEntryDetail(corrosion.ParkedEntry{Origin: "node-3", Seq: 197117, Table: "snapshots", Error: "UNIQUE", Source: "wal"})
	if !strings.Contains(wal, "seq 197117") {
		t.Fatalf("WAL detail = %q", wal)
	}
}
