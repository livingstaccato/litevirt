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

// readmitSameKeySQL is corrosion's readmitHostV2SQL, verbatim: a test-side
// copy so a duplicate admission can be written as a peer would write it.
const readmitSameKeySQL = `UPDATE hosts SET address = ?, ssh_user = ?, ssh_port = ?, grpc_port = ?,
			state = ?, cert_serial = ?, incarnation = ?, created_at = ?, deleted_at = NULL, updated_at = ?
		 WHERE name = ? AND (incarnation < ? OR (incarnation = ? AND created_at < ?))`

// The checked admission is its whole key, (incarnation, created_at), and its
// serial. Two admissions of one staged certificate at one incarnation are a
// supported input (host_incarnation.go: the later stamp replaces the row
// whole): a removal that checked the first and was delayed while the second
// committed — same serial, same incarnation, a later stamp — deletes nothing.
// The later admission stays live with its related rows, and no removal of the
// name is logged, under its stamp or any other.
//
// Mutation: leave created_at out of DeleteHostIf's guard — the later
// admission is tombstoned under the removal that never checked it, red.
func TestRemoveHost_ADelayedRemovalRefusesALaterAdmissionAtTheSameIncarnation(t *testing.T) {
	ctx := context.Background()
	s := incServer(t, 0)
	s.SetReleaseFeatureGate(&scriptedFeatureGate{t: t})
	if _, err := admit(s, "host-x"); err != nil {
		t.Fatalf("admission A: %v", err)
	}
	n, atA, serial, deleted, _, err := corrosion.HostIncarnationOf(ctx, s.db, "host-x")
	if err != nil || deleted || n != 1 || atA == "" {
		t.Fatalf("admission A = (%d, %q, deleted %v), %v; want live at 1", n, atA, deleted, err)
	}
	removals := func() int {
		var c int
		if err := s.db.DB().QueryRow(`SELECT COUNT(*) FROM mutation_log WHERE stmts LIKE '%UPDATE hosts SET deleted_at%' AND stmts LIKE '%"host-x"%'`).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	before := removals()
	var atB string
	s.removeHostBeforeDeleteHook = func(name string) {
		uts := s.db.NowTS()
		stamp, ok := corrosion.ReadmitStamp(uts)
		if !ok || stamp <= atA {
			t.Fatalf("admission B's stamp %q is not after A's %q", stamp, atA)
		}
		atB = stamp
		if err := s.db.ExecuteBatch(ctx, []corrosion.Statement{{SQL: readmitSameKeySQL, Params: []interface{}{
			"10.0.0.9", "root", 22, 9443, "joining", serial, int64(1), atB, uts, name, int64(1), int64(1), atB,
		}}}); err != nil {
			t.Fatalf("admission B: %v", err)
		}
		if _, err := s.db.DB().Exec(`INSERT INTO host_health (observer, target, status, updated_at) VALUES ('host-x', 'peer-host', 'ok', '2026-10-18T00:00:00Z')`); err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "host-x", Force: true, ExpectedCertSerial: serial})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("the delayed removal = %v, want FailedPrecondition", err)
	}
	n, at, gotSerial, deleted, _, err := corrosion.HostIncarnationOf(ctx, s.db, "host-x")
	if err != nil || deleted || n != 1 || at != atB || gotSerial != serial {
		t.Errorf("admission B's row = (%d, %q, %q, deleted %v), %v; want live (1, %q, %q)", n, at, gotSerial, deleted, err, atB, serial)
	}
	var live int
	if err := s.db.DB().QueryRow(`SELECT COUNT(*) FROM host_health WHERE observer = 'host-x' AND deleted_at IS NULL`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Errorf("admission B's host_health rows live = %d, want 1", live)
	}
	if got := removals(); got != before {
		t.Errorf("removals of host-x logged = %d, want %d (none by the delayed removal)", got, before)
	}
}
