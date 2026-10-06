package grpcapi

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// heldServer is a server whose host is re-added under a name with history it
// does not hold: its audit rows are held.
func heldServer(t *testing.T, limit int) *Server {
	t.Helper()
	s := testServer(t)
	corrosion.SetMaxHeldAuditRowsForTest(t, limit)
	s.db.HoldAuditUntilCaughtUp(corrosion.AuditHoldConfig{Host: s.hostName, Target: 50, TargetHash: "ab"})
	return s
}

func interceptOK(t *testing.T, s *Server, method string) error {
	t.Helper()
	called := false
	_, err := s.UnaryAuthInterceptor(adminCtx(), nil, &grpc.UnaryServerInfo{FullMethod: method},
		func(context.Context, interface{}) (interface{}, error) { called = true; return nil, nil })
	if err == nil && !called {
		t.Fatalf("%s: no error and the handler did not run", method)
	}
	if err != nil && called {
		t.Fatalf("%s: refused after the handler ran", method)
	}
	return err
}

// TestAuditHoldGate_AFullHoldRefusesAuditedActions: while the hold has room an
// audited action runs and its row is held; once full, a mutation and a login
// are refused Unavailable before they run, and a read still passes.
//
// Mutation: drop the gateAuditHold call from UnaryAuthInterceptor — DeleteVM
// runs on a full hold, with nowhere for its row to go.
func TestAuditHoldGate_AFullHoldRefusesAuditedActions(t *testing.T) {
	s := heldServer(t, 2)
	ctx := context.Background()
	const deleteVM = "/litevirt.v1.LiteVirt/DeleteVM"
	if err := interceptOK(t, s, deleteVM); err != nil {
		t.Fatalf("DeleteVM refused while the hold has room: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
			HostName: s.hostName, Action: "vm.delete", Target: fmt.Sprintf("vm%d", i), Result: "success",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if !s.db.AuditHoldFull(s.hostName) {
		t.Fatal("fixture: the hold is not full")
	}
	for _, m := range []string{deleteVM, "/litevirt.v1.LiteVirt/Login", "/litevirt.v1.LiteVirt/FinishWebAuthnLogin"} {
		if err := interceptOK(t, s, m); status.Code(err) != codes.Unavailable {
			t.Errorf("%s on a full hold: %v, want Unavailable", m, err)
		}
	}
	for _, m := range []string{"/litevirt.v1.LiteVirt/ListVMs", "/litevirt.v1.LiteVirt/VerifyAuditChain", "/litevirt.v1.LiteVirt/Ping"} {
		if err := interceptOK(t, s, m); err != nil {
			t.Errorf("read %s refused on a full hold: %v", m, err)
		}
	}
}

// TestAuditHoldGate_DeniedLoginsCannotFillIt: an unauthenticated caller
// repeating bad passwords — through the real Login handler, lockouts included —
// folds into one held row, and the node keeps taking actions.
//
// Mutation: hold denied logins as rows of their own — the hold fills and
// DeleteVM is refused.
func TestAuditHoldGate_DeniedLoginsCannotFillIt(t *testing.T) {
	s := heldServer(t, 3)
	seedUser(t, s, "alice", "admin", "hunter2")
	for i := 0; i < 40; i++ {
		_, _ = s.Login(context.Background(), &pb.LoginRequest{Username: "alice", Password: fmt.Sprintf("guess%d", i)})
	}
	if s.db.AuditHoldFull(s.hostName) {
		t.Fatal("forty denied logins filled the hold")
	}
	if err := interceptOK(t, s, "/litevirt.v1.LiteVirt/DeleteVM"); err != nil {
		t.Fatalf("DeleteVM refused after denied logins: %v", err)
	}
}
