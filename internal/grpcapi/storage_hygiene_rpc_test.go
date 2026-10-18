package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

func hygieneAuditCount(t *testing.T, s *Server, action, result string) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT 1 FROM audit_log WHERE action = ? AND result = ?`, action, result)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// lv replication checkpoints rm removes a row no live schedule uses, as an
// admin, audited; it refuses a row a live schedule uses, and a non-admin.
//
// Mutation "no in-use refusal" (DeleteReplicationCheckpoint skips
// checkpointInUse): the used row is retired; red.
func TestDeleteReplicationCheckpoint_RefusesARowInUseAndNonAdmins(t *testing.T) {
	s := multiPoolServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "running", Spec: `{"name":"web"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr",
	}); err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{"dr", "p1"} {
		if err := corrosion.SetReplicationCheckpoint(ctx, s.db, "web", repo, "lvrepl-root-20261018-000000"); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := s.ListReplicationCheckpoints(adminCtx(), &pb.ListReplicationCheckpointsRequest{VmName: "web"})
	if err != nil || len(resp.GetCheckpoints()) != 2 {
		t.Fatalf("list = %v, %v; want 2 rows", resp, err)
	}
	for _, r := range resp.GetCheckpoints() {
		if r.GetInUse() != (r.GetTargetPool() == "dr") {
			t.Errorf("row %s in_use = %v", r.GetTargetPool(), r.GetInUse())
		}
	}
	if _, err := s.DeleteReplicationCheckpoint(viewerCtx(), &pb.DeleteReplicationCheckpointRequest{VmName: "web", TargetPool: "p1"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a viewer's delete = %v, want PermissionDenied", err)
	}
	if _, err := s.DeleteReplicationCheckpoint(adminCtx(), &pb.DeleteReplicationCheckpointRequest{VmName: "web", TargetPool: "dr"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("delete of the row a live schedule uses = %v, want FailedPrecondition", err)
	}
	if _, err := s.DeleteReplicationCheckpoint(adminCtx(), &pb.DeleteReplicationCheckpointRequest{VmName: "web", TargetPool: "p1"}); err != nil {
		t.Fatalf("delete of an unused row: %v", err)
	}
	rows, _ := corrosion.LiveReplicationCheckpoints(ctx, s.db, "web")
	if len(rows) != 1 || rows[0].Repo != "dr" {
		t.Errorf("live rows = %+v, want only dr", rows)
	}
	if hygieneAuditCount(t, s, "replication.checkpoint.delete", "ok") != 1 || hygieneAuditCount(t, s, "replication.checkpoint.delete", "denied") != 1 {
		t.Error("the removal and the refusal are not both audited")
	}
}

// setAsideServer is lockTestServer with VM web here, disk root at a file, and two
// set-aside overlays of it: one of the disk's current window (its binding
// records the disk's token), one of an older window.
func setAsideServer(t *testing.T) (s *Server, current, older string) {
	t.Helper()
	s = lockTestServer(t)
	ctx := context.Background()
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := os.WriteFile(disk, []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(disk, "user.litevirt.pit_window", []byte("tok-now"), 0); err != nil {
		t.Skipf("no user xattrs here: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "stopped", Spec: `{"name":"web"}`}, nil,
		[]corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: s.hostName, StorageType: "local", Path: disk}}); err != nil {
		t.Fatal(err)
	}
	mk := func(token, stamp string) string {
		if err := os.WriteFile(pitoverlay.Path(disk), []byte("overlay-"+token), 0o600); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(pitoverlay.Binding{State: pitoverlay.StateWindow, Token: token})
		if err := os.WriteFile(pitoverlay.SidecarPath(disk), b, 0o600); err != nil {
			t.Fatal(err)
		}
		to, err := pitoverlay.SetAside(disk, stamp)
		if err != nil {
			t.Fatal(err)
		}
		return to
	}
	return s, mk("tok-now", "20261018-120000"), mk("tok-old", "20261017-120000")
}

func hygieneFileThere(p string) bool { _, err := os.Lstat(p); return !errors.Is(err, os.ErrNotExist) }

// lv pit-overlays ls lists both, with the current window's marked in use;
// lv pit-overlays rm removes the older one and its binding (admin, audited),
// and refuses the current window's evidence, a held disk, a name that is not
// a set-aside overlay of the disk, and a non-admin.
//
// Mutation "evidence not judged" (setAsideOverlayInUse skips
// OrphanIsEvidence): the evidence is removed; red. Mutation "hold not
// judged": the held disk's overlay is removed; red.
func TestSetAsideOverlays_ListAndRemoveRefusesWhatIsInUse(t *testing.T) {
	s, current, older := setAsideServer(t)
	ctx := adminCtx()
	resp, err := s.ListSetAsideOverlays(ctx, &pb.ListSetAsideOverlaysRequest{VmName: "web"})
	if err != nil || len(resp.GetOverlays()) != 2 {
		t.Fatalf("list = %v, %v; want 2", resp, err)
	}
	for _, o := range resp.GetOverlays() {
		if (o.GetPath() == current) != (o.GetInUse() != "") {
			t.Errorf("%s in_use = %q", o.GetName(), o.GetInUse())
		}
		if o.GetSetAsideAt() == "" || o.GetSizeBytes() == 0 {
			t.Errorf("%s: set_aside_at %q size %d", o.GetName(), o.GetSetAsideAt(), o.GetSizeBytes())
		}
	}
	rm := func(ctx context.Context, name string) error {
		_, err := s.RemoveSetAsideOverlay(ctx, &pb.RemoveSetAsideOverlayRequest{VmName: "web", DiskName: "root", Name: name})
		return err
	}
	if err := rm(userCtx("op", "operator"), filepath.Base(older)); status.Code(err) != codes.PermissionDenied {
		t.Errorf("an operator's remove = %v, want PermissionDenied", err)
	}
	if err := rm(ctx, filepath.Base(current)); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("remove of the current window's evidence = %v, want FailedPrecondition", err)
	}
	if err := rm(ctx, "../../etc/passwd"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("remove of a path = %v, want InvalidArgument", err)
	}
	s.ReportPITOverlayHeld(context.Background(), "web", "root", "held for the test")
	if err := rm(ctx, filepath.Base(older)); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("remove while the disk is held = %v, want FailedPrecondition", err)
	}
	s.ClearPITOverlayHold(context.Background(), "web", "root")
	if err := rm(ctx, filepath.Base(older)); err != nil {
		t.Fatalf("remove of the older window's overlay: %v", err)
	}
	if hygieneFileThere(older) || hygieneFileThere(older+".id") {
		t.Error("the removed overlay or its binding is still there")
	}
	if !hygieneFileThere(current) || !hygieneFileThere(current+".id") {
		t.Error("the current window's evidence was touched")
	}
	if hygieneAuditCount(t, s, "pit.overlay.remove", "ok") != 1 || hygieneAuditCount(t, s, "pit.overlay.remove", "denied") < 2 {
		t.Error("removals and refusals are not audited")
	}
}
