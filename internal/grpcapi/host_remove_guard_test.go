package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A removal's checks and its delete are one decision: a removal paused after
// it checked the old machine's serial and incarnation, while another removal
// and a re-admission of the name commit, deletes nothing when it resumes. The
// successor stays, with its serial, its incarnation and its related rows, and
// no removal of the name is logged beyond the one that happened.
//
// Mutations: delete by name alone after the checks (corrosion.DeleteHost) —
// the successor is tombstoned under the old removal, red; leave the serial
// out of the guard — "certificate renewed" red; leave the incarnation out —
// "incarnation advanced" red.
func TestRemoveHost_ADelayedRemovalNeverDeletesTheReadmittedSuccessor(t *testing.T) {
	ctx := context.Background()
	s := incServer(t, 0)
	s.SetReleaseFeatureGate(&scriptedFeatureGate{t: t})
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-z", Address: "10.0.0.5", State: "active", CertSerial: "zz01"}); err != nil {
		t.Fatal(err)
	}
	var successorSerial string
	s.removeHostBeforeDeleteHook = func(name string) {
		s.removeHostBeforeDeleteHook = nil
		// Another removal of the same machine completes, and the name is
		// admitted again with a fresh certificate.
		if _, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: name, Force: true, ExpectedCertSerial: "zz01"}); err != nil {
			t.Fatalf("the other removal: %v", err)
		}
		if _, err := admit(s, name); err != nil {
			t.Fatalf("the re-admission: %v", err)
		}
		h, err := corrosion.GetHost(ctx, s.db, name)
		if err != nil || h == nil {
			t.Fatalf("the successor's row: %v", err)
		}
		successorSerial = h.CertSerial
		if _, err := s.db.DB().Exec(`INSERT INTO host_health (observer, target, status, updated_at) VALUES ('host-z', 'peer-host', 'ok', '2026-10-18T00:00:00Z')`); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "host-z", Force: true, ExpectedCertSerial: "zz01"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("the delayed removal = %v, want FailedPrecondition", err)
	}
	n, deleted := incOf(t, s, "host-z")
	if deleted {
		t.Fatal("the delayed removal deleted the re-admitted successor")
	}
	if n != 1 {
		t.Errorf("the successor's incarnation = %d, want 1", n)
	}
	if h, _ := corrosion.GetHost(ctx, s.db, "host-z"); h == nil || successorSerial == "" || h.CertSerial != successorSerial {
		t.Errorf("the successor's row = %+v, want serial %q", h, successorSerial)
	}
	var live int
	if err := s.db.DB().QueryRow(`SELECT COUNT(*) FROM host_health WHERE observer = 'host-z' AND deleted_at IS NULL`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Errorf("the successor's host_health rows live = %d, want 1", live)
	}
	var logged int
	if err := s.db.DB().QueryRow(`SELECT COUNT(*) FROM mutation_log WHERE stmts LIKE '%UPDATE hosts SET deleted_at%' AND stmts LIKE '%"host-z"%'`).Scan(&logged); err != nil {
		t.Fatal(err)
	}
	if logged != 1 {
		t.Errorf("removals of host-z logged = %d, want only the one that happened", logged)
	}
}

// The same holds for a change of either half of the checked admission alone:
// a certificate renewed in place, or the incarnation advanced under the same
// serial.
func TestRemoveHost_ADelayedRemovalRefusesAChangedAdmission(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"certificate renewed", `UPDATE hosts SET cert_serial = 'zz02' WHERE name = 'host-z'`},
		{"incarnation advanced", `UPDATE hosts SET incarnation = 1 WHERE name = 'host-z'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := incServer(t, 0)
			if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "host-z", Address: "10.0.0.5", State: "active", CertSerial: "zz01"}); err != nil {
				t.Fatal(err)
			}
			s.removeHostBeforeDeleteHook = func(string) {
				if _, err := s.db.DB().Exec(tc.sql); err != nil {
					t.Fatal(err)
				}
			}
			_, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "host-z", Force: true, ExpectedCertSerial: "zz01"})
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("the delayed removal = %v, want FailedPrecondition", err)
			}
			if _, deleted := incOf(t, s, "host-z"); deleted {
				t.Error("the delayed removal deleted a row whose admission changed")
			}
		})
	}
	t.Run("unchanged, the removal goes through", func(t *testing.T) {
		s := incServer(t, 0)
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "host-z", Address: "10.0.0.5", State: "active", CertSerial: "zz01"}); err != nil {
			t.Fatal(err)
		}
		s.removeHostBeforeDeleteHook = func(string) {}
		if _, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "host-z", Force: true}); err != nil {
			t.Fatalf("a removal with no expected serial whose row did not change: %v", err)
		}
		if _, deleted := incOf(t, s, "host-z"); !deleted {
			t.Error("the removal deleted nothing")
		}
	})
}
