package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A resource mapping decides which host PCI device a VM asking for it by name
// is handed. AddMappingDevice and RemoveMappingDevice wrote no audit row, and
// create and delete wrote one with no before-state, so repointing a mapping at
// a different device left nothing in the signed chain to say who did it or
// which device it used to name. Every mutation now writes exactly one row: the
// caller, the mapping, and the state before and after.

type mapAuditRow struct{ user, target, detail, result string }

func mapAuditRows(t *testing.T, s *Server, action string) []mapAuditRow {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT username, target, detail, result FROM audit_log WHERE action = ? ORDER BY seq`, action)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	out := make([]mapAuditRow, len(rows))
	for i, r := range rows {
		out[i] = mapAuditRow{r.String("username"), r.String("target"), r.String("detail"), r.String("result")}
	}
	return out
}

func wantOneMapAudit(t *testing.T, s *Server, action string, want mapAuditRow) {
	t.Helper()
	rows := mapAuditRows(t, s, action)
	if len(rows) != 1 {
		t.Fatalf("%s: %d audit rows, want exactly 1: %+v", action, len(rows), rows)
	}
	if rows[0] != want {
		t.Errorf("%s audit row = %+v\n               want %+v", action, rows[0], want)
	}
}

func TestResourceMappingRPCs_AuditWhoWhatBeforeAfter(t *testing.T) {
	s := testServer(t)
	ctx := userCtx("alice", "admin")

	if _, err := s.CreateResourceMapping(ctx, &pb.CreateResourceMappingRequest{Name: "gpu", Description: "a100s"}); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	wantOneMapAudit(t, s, "resourcemap.add", mapAuditRow{"alice", "gpu",
		`before=none after={name=gpu description="a100s" devices=[]}`, "ok"})

	if _, err := s.AddMappingDevice(ctx, &pb.AddMappingDeviceRequest{
		Mapping: "gpu", Host: "h1", Address: "0000:01:00.0", Vendor: "10de", Device: "20b0",
	}); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}
	wantOneMapAudit(t, s, "resourcemap.device.add", mapAuditRow{"alice", "gpu",
		`before=none after={host=h1 address=0000:01:00.0 vendor="10de" device="20b0"}`, "ok"})

	// Re-adding the same (mapping, host, address) rewrites vendor/device: the
	// row has to say what it replaced.
	if _, err := s.AddMappingDevice(ctx, &pb.AddMappingDeviceRequest{
		Mapping: "gpu", Host: "h1", Address: "0000:01:00.0", Vendor: "10de", Device: "2330",
	}); err != nil {
		t.Fatalf("AddMappingDevice (re-add): %v", err)
	}
	if rows := mapAuditRows(t, s, "resourcemap.device.add"); len(rows) != 2 ||
		rows[1].detail != `before={host=h1 address=0000:01:00.0 vendor="10de" device="20b0"} after={host=h1 address=0000:01:00.0 vendor="10de" device="2330"}` {
		t.Errorf("re-add rows = %+v, want the second to carry the replaced device as before", rows)
	}

	// An empty host means the connected daemon's own host, and the row says so.
	if _, err := s.AddMappingDevice(ctx, &pb.AddMappingDeviceRequest{Mapping: "gpu", Address: "0000:02:00.0"}); err != nil {
		t.Fatalf("AddMappingDevice (local host): %v", err)
	}
	if rows := mapAuditRows(t, s, "resourcemap.device.add"); len(rows) != 3 ||
		rows[2].detail != `before=none after={host=test-host address=0000:02:00.0}` {
		t.Errorf("local-host add rows = %+v", rows)
	}

	if _, err := s.RemoveMappingDevice(ctx, &pb.RemoveMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"}); err != nil {
		t.Fatalf("RemoveMappingDevice: %v", err)
	}
	wantOneMapAudit(t, s, "resourcemap.device.rm", mapAuditRow{"alice", "gpu",
		`before={host=h1 address=0000:01:00.0 vendor="10de" device="2330"} after=none`, "ok"})

	if _, err := s.DeleteResourceMapping(ctx, &pb.DeleteResourceMappingRequest{Name: "gpu"}); err != nil {
		t.Fatalf("DeleteResourceMapping: %v", err)
	}
	wantOneMapAudit(t, s, "resourcemap.rm", mapAuditRow{"alice", "gpu",
		`before={name=gpu description="a100s" devices=[{host=test-host address=0000:02:00.0}]} after=none`, "ok"})
}

// A removal that names nothing live tombstones nothing. It used to report
// success; it is now NotFound, and the attempt is still a row.
func TestResourceMappingRPCs_RemoveMissingIsNotFoundAndAudited(t *testing.T) {
	s := testServer(t)
	ctx := userCtx("alice", "admin")
	if _, err := s.CreateResourceMapping(ctx, &pb.CreateResourceMappingRequest{Name: "gpu"}); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}

	_, err := s.RemoveMappingDevice(ctx, &pb.RemoveMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:09:00.0"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("RemoveMappingDevice of an absent device: err = %v, want NotFound", err)
	}
	wantOneMapAudit(t, s, "resourcemap.device.rm", mapAuditRow{"alice", "gpu",
		`before=none after=none device={host=h1 address=0000:09:00.0} (no such device)`, "error"})

	_, err = s.DeleteResourceMapping(ctx, &pb.DeleteResourceMappingRequest{Name: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("DeleteResourceMapping of an absent mapping: err = %v, want NotFound", err)
	}
	wantOneMapAudit(t, s, "resourcemap.rm", mapAuditRow{"alice", "nope",
		`before=none after=none (no such mapping)`, "error"})
}

// A caller without resourcemap.write is refused, changes nothing, and leaves a
// "denied" row naming them and what they tried — the backup-repo convention.
func TestResourceMappingRPCs_RefusedCallerWritesDeniedRow(t *testing.T) {
	s := testServer(t)
	admin := userCtx("alice", "admin")
	if _, err := s.CreateResourceMapping(admin, &pb.CreateResourceMappingRequest{Name: "gpu", Description: "seed"}); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if _, err := s.AddMappingDevice(admin, &pb.AddMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"}); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}
	before := corrosion.ResourceMappingAuditState(context.Background(), s.db, "gpu")

	vic := userCtx("vic", "viewer")
	calls := map[string]struct {
		call   func() error
		target string
		detail string
	}{
		"resourcemap.add": {func() error {
			_, err := s.CreateResourceMapping(vic, &pb.CreateResourceMappingRequest{Name: "sneaky", Description: "x"})
			return err
		}, "sneaky", `requested={name=sneaky description="x" devices=[]}`},
		"resourcemap.rm": {func() error {
			_, err := s.DeleteResourceMapping(vic, &pb.DeleteResourceMappingRequest{Name: "gpu"})
			return err
		}, "gpu", `requested=none`},
		"resourcemap.device.add": {func() error {
			_, err := s.AddMappingDevice(vic, &pb.AddMappingDeviceRequest{Mapping: "gpu", Host: "h2", Address: "0000:02:00.0"})
			return err
		}, "gpu", `requested={host=h2 address=0000:02:00.0}`},
		"resourcemap.device.rm": {func() error {
			_, err := s.RemoveMappingDevice(vic, &pb.RemoveMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"})
			return err
		}, "gpu", `device={host=h1 address=0000:01:00.0} requested=none`},
	}
	for action, c := range calls {
		t.Run(action, func(t *testing.T) {
			err := c.call()
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err = %v, want PermissionDenied", err)
			}
			var denied []mapAuditRow
			for _, r := range mapAuditRows(t, s, action) {
				if r.user == "vic" {
					denied = append(denied, r)
				}
			}
			if len(denied) != 1 {
				t.Fatalf("%d rows for vic, want exactly 1: %+v", len(denied), denied)
			}
			r := denied[0]
			if r.result != "denied" || r.target != c.target || !strings.HasPrefix(r.detail, c.detail+" ") ||
				!strings.Contains(r.detail, "PermissionDenied") {
				t.Errorf("denied row = %+v, want result=denied target=%q detail=%q + the refusal", r, c.target, c.detail)
			}
		})
	}
	if got := corrosion.ResourceMappingAuditState(context.Background(), s.db, "gpu"); got != before {
		t.Errorf("a refused caller changed the mapping:\n before %s\n after  %s", before, got)
	}
	if got := corrosion.ResourceMappingAuditState(context.Background(), s.db, "sneaky"); got != corrosion.AuditStateNone {
		t.Errorf("a refused caller created a mapping: %s", got)
	}
}

// A write that fails still leaves a row: the before-state read ahead of it,
// and an after-state that claims nothing.
func TestResourceMappingRPCs_FailedWriteIsAuditedAsError(t *testing.T) {
	s := testServer(t)
	ctx := userCtx("alice", "admin")
	if _, err := s.CreateResourceMapping(ctx, &pb.CreateResourceMappingRequest{Name: "gpu"}); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if _, err := s.AddMappingDevice(ctx, &pb.AddMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"}); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}
	for _, trig := range []string{
		`CREATE TRIGGER mapaud_no_insert BEFORE INSERT ON resource_mappings BEGIN SELECT RAISE(ABORT, 'mapaud boom'); END`,
		`CREATE TRIGGER mapaud_no_update BEFORE UPDATE ON resource_mappings BEGIN SELECT RAISE(ABORT, 'mapaud boom'); END`,
	} {
		if err := s.db.Execute(context.Background(), trig); err != nil {
			t.Fatalf("install failing trigger: %v", err)
		}
	}

	if _, err := s.AddMappingDevice(ctx, &pb.AddMappingDeviceRequest{Mapping: "gpu", Host: "h2", Address: "0000:02:00.0"}); err == nil {
		t.Fatal("AddMappingDevice succeeded through a failing trigger")
	}
	if _, err := s.RemoveMappingDevice(ctx, &pb.RemoveMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"}); err == nil {
		t.Fatal("RemoveMappingDevice succeeded through a failing trigger")
	}
	if _, err := s.CreateResourceMapping(ctx, &pb.CreateResourceMappingRequest{Name: "gpu", Description: "new"}); err == nil {
		t.Fatal("CreateResourceMapping succeeded through a failing trigger")
	}
	if _, err := s.DeleteResourceMapping(ctx, &pb.DeleteResourceMappingRequest{Name: "gpu"}); err == nil {
		t.Fatal("DeleteResourceMapping succeeded through a failing trigger")
	}

	want := map[string]string{
		"resourcemap.device.add": `before=none after=unknown(`,
		"resourcemap.device.rm":  `before={host=h1 address=0000:01:00.0} after=unknown(`,
		"resourcemap.add":        `before={name=gpu devices=[{host=h1 address=0000:01:00.0}]} after=unknown(`,
		"resourcemap.rm":         `before={name=gpu devices=[{host=h1 address=0000:01:00.0}]} after=unknown(`,
	}
	for action, prefix := range want {
		var errs []mapAuditRow
		for _, r := range mapAuditRows(t, s, action) {
			if r.result == "error" {
				errs = append(errs, r)
			}
		}
		if len(errs) != 1 {
			t.Errorf("%s: %d error rows, want exactly 1: %+v", action, len(errs), mapAuditRows(t, s, action))
			continue
		}
		if errs[0].user != "alice" || errs[0].target != "gpu" ||
			!strings.HasPrefix(errs[0].detail, prefix) || !strings.Contains(errs[0].detail, "mapaud boom") {
			t.Errorf("%s error row = %+v, want detail starting %q and naming the failure", action, errs[0], prefix)
		}
	}
}

// Rows from these RPCs are signed when the daemon's client carries a signing
// keyring (on by default): they go through auditAs, the registered writer.
func TestResourceMappingRPCs_RowsAreSigned(t *testing.T) {
	s := testServer(t)
	corrosion.SignAuditRowsForTest(t, s.db, s.hostName)
	ctx := userCtx("alice", "admin")
	if _, err := s.CreateResourceMapping(ctx, &pb.CreateResourceMappingRequest{Name: "gpu"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddMappingDevice(ctx, &pb.AddMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveMappingDevice(ctx, &pb.RemoveMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteResourceMapping(ctx, &pb.DeleteResourceMappingRequest{Name: "gpu"}); err != nil {
		t.Fatal(err)
	}
	_, _ = s.AddMappingDevice(userCtx("vic", "viewer"), &pb.AddMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"})

	for _, action := range []string{"resourcemap.add", "resourcemap.device.add", "resourcemap.device.rm", "resourcemap.rm"} {
		if n := len(mapAuditRows(t, s, action)); n < 1 {
			t.Fatalf("%s: no audit row", action)
		}
	}
	corrosion.AssertAuditRowsSignedForTest(t, s.db, 5)
}

// Nothing about the caller's credential reaches a row: not the bearer the
// request carried, not the session it resolved to.
func TestResourceMappingRPCs_NoSecretInRows(t *testing.T) {
	const bearer = "lvt_mapaud-SECRET-bearer-0123456789"
	const session = "mapaud-SECRET-session-id"
	s := testServer(t)
	withCred := func(user, role string) context.Context {
		ctx := userCtx(user, role)
		ctx = context.WithValue(ctx, ctxKeySessionID, session)
		return metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+bearer))
	}
	ctx := withCred("alice", "admin")
	_, _ = s.CreateResourceMapping(ctx, &pb.CreateResourceMappingRequest{Name: "gpu", Description: "d"})
	_, _ = s.AddMappingDevice(ctx, &pb.AddMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0", Vendor: "v", Device: "d"})
	_, _ = s.RemoveMappingDevice(ctx, &pb.RemoveMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"})
	_, _ = s.RemoveMappingDevice(ctx, &pb.RemoveMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"})
	_, _ = s.DeleteResourceMapping(ctx, &pb.DeleteResourceMappingRequest{Name: "gpu"})
	vic := withCred("vic", "viewer")
	_, _ = s.CreateResourceMapping(vic, &pb.CreateResourceMappingRequest{Name: "x"})
	_, _ = s.AddMappingDevice(vic, &pb.AddMappingDeviceRequest{Mapping: "gpu", Host: "h1", Address: "0000:01:00.0"})

	rows, err := s.db.Query(context.Background(), `SELECT * FROM audit_log WHERE action LIKE 'resourcemap.%'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 7 {
		t.Fatalf("%d resourcemap rows, want at least 7", len(rows))
	}
	for _, r := range rows {
		for _, col := range r.Columns {
			v := r.String(col)
			if strings.Contains(v, "SECRET") {
				t.Errorf("audit row %s column %s carries a credential: %q", r.String("id"), col, v)
			}
		}
	}
}
