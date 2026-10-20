package grpcapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A server built by the production constructor ends its stub record of an
// incoming move when replication applies that move's commit naming this
// host (round-13c review m2: fleet builds its servers another way, so it
// cannot see the production wiring go missing).
//
// Mutation: drop wireMoveRecordWatch from NewServer — the record outlives the
// commit, red.
func TestNewServer_EndsAStubRecordWhenItsMoveCommitsHere(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := NewServer("dst-host", t.TempDir(), t.TempDir(), db, nil, nil)
	insertTestVM(t, adminCtx(), db, "mig", "src-host", "running")
	mark, ok, err := corrosion.VMPlacementMark(ctx, db, "mig")
	if err != nil || !ok {
		t.Fatalf("VMPlacementMark: %v %v", ok, err)
	}
	p := filepath.Join(s.dataDir, "disks", "mig-root.qcow2")
	s.migrationStubs.add("mig", p, mark)

	hlc := "9999999999999-0000-src-host"
	stmts, _ := json.Marshal([]corrosion.Statement{{
		SQL:    `UPDATE vms SET host_name = ?, state = ?, state_detail = '', updated_at = ? WHERE name = ?`,
		Params: []interface{}{"dst-host", "running", hlc, "mig"},
	}})
	if _, err := corrosion.NewReplicator(db, "", corrosion.RelayConfig{}).ApplyRemoteMutations(ctx, []*pb.MutationEntry{
		{Seq: 1, Hlc: hlc, Origin: "src-host", Stmts: string(stmts)},
	}); err != nil {
		t.Fatalf("apply the move's commit: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, db, "mig"); vm == nil || vm.HostName != "dst-host" {
		t.Fatalf("fixture: mig after the commit = %+v, want on dst-host", vm)
	}
	if got := s.migrationStubs.vms(); len(got) != 0 {
		t.Fatalf("the stub record outlived its move's commit here: %v", got)
	}
}
