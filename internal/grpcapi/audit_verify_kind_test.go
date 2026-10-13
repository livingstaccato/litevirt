package grpcapi

import (
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestVerifyAuditChain_CarriesTheKindOfBreak: the RPC passes the verifier's
// classification of the first broken link through, so `lv audit verify`, the
// web UI and the REST poller can name a forked chain as one instead of as an
// edited row.
func TestVerifyAuditChain_CarriesTheKindOfBreak(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
		ID: "orig-1", Username: "u", HostName: "node-3", Action: "vm.start", Target: "x", Result: "ok",
		Timestamp: "2026-10-03T22:16:00.000000000Z",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	// A second genesis row under the same name, correctly hashed: the shape a
	// host rebuilt on an empty database wrote before its history replicated back.
	fork := corrosion.AuditRecord{
		ID: "fork-1", Username: "u", HostName: "node-3", Action: "vm.start", Target: "x", Result: "ok",
		Timestamp: "2026-10-03T22:16:30.767241380Z",
	}
	if err := s.db.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
		 result, prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, '', ?, '', '', 1)`,
		fork.ID, fork.Timestamp, fork.Username, fork.HostName, fork.Action, fork.Target, fork.Result,
		corrosion.HashAuditRow(fork)); err != nil {
		t.Fatalf("insert fork: %v", err)
	}
	resp, err := s.VerifyAuditChain(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if resp.BrokenAtId != "fork-1" || resp.BrokenAtKind != corrosion.AuditBrokenForked {
		t.Fatalf("broken_at_id=%q broken_at_kind=%q, want fork-1 / %q",
			resp.BrokenAtId, resp.BrokenAtKind, corrosion.AuditBrokenForked)
	}
	if !resp.Tampered {
		t.Error("a forked chain must still fail verification")
	}
}
