package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/storage"
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
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "stopped", Spec: `{"name":"web","uuid":"u-web"}`}, nil,
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

func rmOverlay(s *Server, ctx context.Context, name string) error {
	_, err := s.RemoveSetAsideOverlay(ctx, &pb.RemoveSetAsideOverlayRequest{VmName: "web", DiskName: "root", Name: filepath.Base(name)})
	return err
}

// m-2, m-4. Removal is refused while another VM's disk references the
// overlay, while web's domain names it, and while whether it does cannot be
// told (a libvirt error is never read as "no domain").
//
// Mutations, each red: "disk reference not judged" (the boundedRefs check
// skipped); "domain not judged" (domainNamesFile's `if used` made false);
// "libvirt error read as no domain" (domainNamesFile returns "" on any
// DomainIsActive error).
func TestSetAsideOverlays_RefusesWhatADiskOrADomainNames(t *testing.T) {
	s, _, older := setAsideServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "clone", HostName: s.hostName, State: "stopped", Spec: `{"name":"clone"}`}, nil,
		[]corrosion.DiskRecord{{VMName: "clone", DiskName: "root", HostName: s.hostName, StorageType: "local", Path: older}}); err != nil {
		t.Fatal(err)
	}
	if err := rmOverlay(s, ctx, older); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remove while clone's disk references it = %v, want FailedPrecondition", err)
	}
	if err := corrosion.DeleteVM(context.Background(), s.db, "clone"); err != nil {
		t.Fatal(err)
	}
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateDefined)
	snap := &fakePITSnapshotter{onOverlay: map[string]bool{older: true}}
	s.SetPointInTimeSnapshotter(snap)
	if err := rmOverlay(s, ctx, older); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remove while web's domain names it = %v, want FailedPrecondition", err)
	}
	snap.onOverlay = map[string]bool{}
	s.virt.(*libvirtfake.Fake).FailDomainState = func(string) error { return errors.New("libvirt: connection dropped") }
	if err := rmOverlay(s, ctx, older); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remove while libvirt cannot answer = %v, want FailedPrecondition", err)
	}
	s.virt.(*libvirtfake.Fake).FailDomainState = nil
	if err := rmOverlay(s, ctx, older); err != nil {
		t.Fatalf("remove once nothing names it: %v", err)
	}
}

// m-3. A binding that cannot be read keeps the overlay: removal needs a
// positive answer that it is not the disk's evidence.
//
// Mutation "an unreadable binding is no evidence" (OrphanInUse returns ""
// on a read error other than ENOENT): it is removed; red.
func TestSetAsideOverlays_AnUnreadableBindingKeepsIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	s, _, older := setAsideServer(t)
	if err := os.Chmod(older+".id", 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(older+".id", 0o600) })
	if err := rmOverlay(s, adminCtx(), older); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remove with its binding unreadable = %v, want FailedPrecondition", err)
	}
	if !hygieneFileThere(older) {
		t.Fatal("removed")
	}
}

// I-2. A disk with no window token (a VM re-created at the same path) does
// not count an EARLIER VM's orphans as its evidence: one whose binding
// records another VM's uuid is removable, while one recording web's own
// uuid, or none, is still evidence.
//
// Mutation "uuid not judged" (otherVM always false): the earlier VM's orphan
// is kept as evidence; red.
func TestSetAsideOverlays_AnEarlierVMsOrphanIsNotEvidence(t *testing.T) {
	s, current, _ := setAsideServer(t)
	disk, _ := pitoverlay.DiskOfOrphan(current)
	if err := unix.Removexattr(disk, "user.litevirt.pit_window"); err != nil {
		t.Fatal(err)
	}
	mk := func(uuid, stamp string) string {
		o := pitoverlay.Path(disk) + ".orphan-" + stamp
		b, _ := json.Marshal(pitoverlay.Binding{Owner: pitoverlay.Owner{VM: "web", VMUUID: uuid, Disk: "root"}, State: pitoverlay.StateWindow, Token: "x"})
		if err := os.WriteFile(o, []byte("o"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(o+".id", b, 0o600); err != nil {
			t.Fatal(err)
		}
		return o
	}
	earlier, own, unknown := mk("u-old", "20261001-000000"), mk("u-web", "20261002-000000"), mk("", "20261003-000000")
	ctx := adminCtx()
	for _, o := range []string{own, unknown} {
		if err := rmOverlay(s, ctx, o); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("remove of %s = %v, want FailedPrecondition (evidence)", filepath.Base(o), err)
		}
	}
	if err := rmOverlay(s, ctx, earlier); err != nil {
		t.Fatalf("remove of the earlier VM's orphan: %v", err)
	}
	if pitoverlay.SetAsideEvidenceFor(disk, "u-web") != true || pitoverlay.SetAsideEvidenceFor(filepath.Join(filepath.Dir(disk), "none.qcow2"), "u-web") {
		t.Error("SetAsideEvidenceFor disagrees")
	}
}

// m-2. A listing whose storage does not answer is refused, bounded.
func TestSetAsideOverlays_ListingRefusesStorageThatDoesNotAnswer(t *testing.T) {
	s, _, _ := setAsideServer(t)
	t.Cleanup(storage.OverrideFSCallBoundForTest(50 * time.Millisecond))
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	t.Cleanup(pitoverlay.SetGlobForTest(func(string) ([]string, error) { <-block; return nil, nil }))
	_, err := s.ListSetAsideOverlays(adminCtx(), &pb.ListSetAsideOverlaysRequest{VmName: "web"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("listing on storage that does not answer = %v, want Unavailable", err)
	}
}

// I-2. A detached overlay (no live disk where it was set aside) is listed on
// the host with its owner from the binding, and removed by path, admin only;
// refused outside a pool directory, for a name that is not an overlay's,
// while a live disk is at its base path, while a VM disk references it, and
// while a domain on the host names it.
//
// Mutations, each red: "pool directory not required"; "live base not
// judged"; "no domain check for detached".
func TestDetachedPITOverlay_ListedAndRemovedByPathWithItsGuards(t *testing.T) {
	s, _, _ := setAsideServer(t)
	ctx := adminCtx()
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "gone-root.qcow2")
	o := pitoverlay.Path(base) + ".orphan-20261001-000000"
	b, _ := json.Marshal(pitoverlay.Binding{Owner: pitoverlay.Owner{VM: "gone", VMUUID: "u-gone", Disk: "root"}})
	if err := os.WriteFile(o, []byte("o"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o+".id", b, 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListSetAsideOverlays(ctx, &pb.ListSetAsideOverlaysRequest{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ov := range resp.GetOverlays() {
		if ov.GetPath() == o {
			found = ov.GetDetached() && ov.GetVmName() == "gone" && ov.GetOwnerVmUuid() == "u-gone" && ov.GetDiskPath() == base
		}
	}
	if !found {
		t.Fatalf("detached overlay not listed as such: %+v", resp.GetOverlays())
	}
	rm := func(ctx context.Context, p string) error {
		_, err := s.RemoveSetAsideOverlay(ctx, &pb.RemoveSetAsideOverlayRequest{Path: p})
		return err
	}
	if err := rm(userCtx("op", "operator"), o); status.Code(err) != codes.PermissionDenied {
		t.Errorf("an operator's remove = %v, want PermissionDenied", err)
	}
	outside := filepath.Join(t.TempDir(), filepath.Base(o))
	_ = os.WriteFile(outside, []byte("x"), 0o600)
	if err := rm(ctx, outside); status.Code(err) != codes.InvalidArgument {
		t.Errorf("remove outside a pool directory = %v, want InvalidArgument", err)
	}
	if err := rm(ctx, filepath.Join(dir, "gone-root.qcow2")); status.Code(err) != codes.InvalidArgument {
		t.Errorf("remove of a disk by path = %v, want InvalidArgument", err)
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "gone", HostName: s.hostName, State: "stopped", Spec: `{"name":"gone"}`}, nil,
		[]corrosion.DiskRecord{{VMName: "gone", DiskName: "root", HostName: s.hostName, StorageType: "local", Path: base}}); err != nil {
		t.Fatal(err)
	}
	if err := rm(ctx, o); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("remove while a live disk is at its base path = %v, want FailedPrecondition", err)
	}
	if err := corrosion.DeleteVM(context.Background(), s.db, "gone"); err != nil {
		t.Fatal(err)
	}
	s.virt.(*libvirtfake.Fake).SetState("web", libvirtfake.StateDefined)
	snap := &fakePITSnapshotter{onOverlay: map[string]bool{o: true}}
	s.SetPointInTimeSnapshotter(snap)
	if err := rm(ctx, o); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("remove while web's domain names it = %v, want FailedPrecondition", err)
	}
	snap.onOverlay = map[string]bool{}
	if err := rm(ctx, o); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if hygieneFileThere(o) || hygieneFileThere(o+".id") {
		t.Error("the detached overlay or its binding is still there")
	}
}

// R2 I-1, the reviewer's probe. VM "w.lv-pit.orphan-1" (a legal name) runs
// on another host from a disk in this host's <data_dir>/disks; its LIVE
// overlay and binding are beside the disk. The overlay is never listed as a
// detached orphan, and removal by path is refused: it holds the guest's
// newest writes.
//
// Mutation "prefix-only shape": it is listed detached and removed; red.
func TestDetachedPITOverlay_ADottedVMsLiveOverlayIsNeverAnOrphan(t *testing.T) {
	s, _, _ := setAsideServer(t)
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(dir, "w.lv-pit.orphan-1-root.qcow2")
	if err := os.WriteFile(disk, []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "w.lv-pit.orphan-1", HostName: "other-host", State: "running", Spec: `{"name":"w.lv-pit.orphan-1"}`}, nil,
		[]corrosion.DiskRecord{{VMName: "w.lv-pit.orphan-1", DiskName: "root", HostName: "other-host", StorageType: "local", Path: disk}}); err != nil {
		t.Fatal(err)
	}
	live := pitoverlay.Path(disk)
	b, _ := json.Marshal(pitoverlay.Binding{Owner: pitoverlay.Owner{VM: "w.lv-pit.orphan-1", Disk: "root"}, State: pitoverlay.StateWindow, Token: "t"})
	if err := os.WriteFile(live, []byte("the guest's newest writes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pitoverlay.SidecarPath(disk), b, 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListSetAsideOverlays(adminCtx(), &pb.ListSetAsideOverlaysRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range resp.GetOverlays() {
		if o.GetPath() == live {
			t.Errorf("the live overlay is listed as a set-aside one: %+v", o)
		}
	}
	if _, err := s.RemoveSetAsideOverlay(adminCtx(), &pb.RemoveSetAsideOverlayRequest{Path: live}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("remove of the live overlay by path = %v, want InvalidArgument", err)
	}
	if !hygieneFileThere(live) || !hygieneFileThere(pitoverlay.SidecarPath(disk)) {
		t.Fatal("the live overlay or its binding was deleted")
	}
}

// R2 m-1. A detached overlay a domain names is kept whatever the database
// says: every domain libvirt has defined is asked, a stray one with no VM
// row included, and a domain list that cannot be read refuses.
//
// Mutation "only recorded VMs asked" (anyDomainNamesFile walks VMsOnHost):
// the stray domain's reference is missed; red.
func TestDetachedPITOverlay_EveryDefinedDomainIsAsked(t *testing.T) {
	s, _, _ := setAsideServer(t)
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	o := pitoverlay.Path(filepath.Join(dir, "gone-root.qcow2")) + ".orphan-20261001-000000"
	if err := os.WriteFile(o, []byte("o"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("inspect-by-hand", libvirtfake.StateDefined) // no VM row
	snap := &fakePITSnapshotter{onOverlay: map[string]bool{o: true}}
	s.SetPointInTimeSnapshotter(snap)
	rm := func() error {
		_, err := s.RemoveSetAsideOverlay(adminCtx(), &pb.RemoveSetAsideOverlayRequest{Path: o})
		return err
	}
	if err := rm(); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("remove while a stray domain names it = %v, want FailedPrecondition", err)
	}
	snap.onOverlay = map[string]bool{}
	fake.FailListDomains = func() error { return errors.New("libvirt: connection dropped") }
	if err := rm(); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("remove while the domain list cannot be read = %v, want FailedPrecondition", err)
	}
	fake.FailListDomains = nil
	if err := rm(); err != nil {
		t.Fatalf("remove: %v", err)
	}
}

// R2 N-2. A request a peer already forwarded is never forwarded again: a
// host whose replica names yet another host for the VM answers Aborted
// rather than passing it on, so two replicas that disagree cannot ping-pong.
//
// Mutation "no hop guard": it forwards (and fails to dial: Unavailable); red.
func TestSetAsideAndCheckpointForwards_AreNeverForwardedTwice(t *testing.T) {
	s, _, _ := setAsideServer(t)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "away", HostName: "third-host", State: "running", Spec: `{"name":"away"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx := peerCtxFor(t, s, "node-x")
	ctx = context.WithValue(context.WithValue(ctx, ctxKeyUsername, "admin"), ctxKeyRole, "admin")
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(forwardedHopMDKey, "node-x"))
	if _, err := s.RemoveSetAsideOverlay(ctx, &pb.RemoveSetAsideOverlayRequest{VmName: "away", DiskName: "root", Name: ".x.lv-pit.orphan-20261018-120000"}); status.Code(err) != codes.Aborted {
		t.Errorf("a forwarded remove for a VM on a third host = %v, want Aborted", err)
	}
	if _, err := s.DeleteReplicationCheckpoint(ctx, &pb.DeleteReplicationCheckpointRequest{VmName: "away", TargetPool: "dr"}); status.Code(err) != codes.Aborted {
		t.Errorf("a forwarded checkpoint rm for a VM on a third host = %v, want Aborted", err)
	}
	if _, err := s.ListSetAsideOverlays(ctx, &pb.ListSetAsideOverlaysRequest{VmName: "away"}); status.Code(err) != codes.Aborted {
		t.Errorf("a forwarded listing for a VM on a third host = %v, want Aborted", err)
	}
}

// R2 N-2. A detached overlay's removal holds the VM lock of the owner its
// binding records from its checks to the unlink, so a re-create of that VM,
// or an attach or a set-aside on its disk, cannot slip in between.
//
// Mutation "no lock": the removal completes while the lock is held; red.
func TestDetachedPITOverlay_RemovalHoldsTheOwnersVMLock(t *testing.T) {
	s, _, _ := setAsideServer(t)
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	o := pitoverlay.Path(filepath.Join(dir, "gone-root.qcow2")) + ".orphan-20261001-000000"
	b, _ := json.Marshal(pitoverlay.Binding{Owner: pitoverlay.Owner{VM: "gone", Disk: "root"}})
	if err := os.WriteFile(o, []byte("o"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o+".id", b, 0o600); err != nil {
		t.Fatal(err)
	}
	assertSerializedByVMLock(t, s, "gone", func() {
		_, _ = s.RemoveSetAsideOverlay(adminCtx(), &pb.RemoveSetAsideOverlayRequest{Path: o})
	})
	if hygieneFileThere(o) {
		t.Fatal("not removed once the lock was free")
	}
}

// R3 n-1. A detached overlay whose binding exists but cannot be read is
// kept: whose it is cannot be told, so its owner's lock cannot be taken.
//
// Mutation "unreadable binding skips the owner lock" (only ENOENT refused
// dropped: any error goes on unlocked): it is removed; red.
func TestDetachedPITOverlay_AnUnreadableBindingKeepsIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	s, _, _ := setAsideServer(t)
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	o := pitoverlay.Path(filepath.Join(dir, "gone-root.qcow2")) + ".orphan-20261001-000000"
	if err := os.WriteFile(o, []byte("o"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o+".id", []byte(`{"vm":"gone"}`), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(o+".id", 0o600) })
	_, err := s.RemoveSetAsideOverlay(adminCtx(), &pb.RemoveSetAsideOverlayRequest{Path: o})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remove with its binding unreadable = %v, want FailedPrecondition", err)
	}
	if !hygieneFileThere(o) {
		t.Fatal("removed")
	}
}

// R3 n-1. Both removal paths, by VM and by path, take the lock of the disk
// path the overlay was set aside beside, so a removal of either kind never
// runs beside another of the same file.
//
// Mutation "no base lock on the VM path": the VM-path removal completes
// while that lock is held; red.
func TestSetAsideOverlays_BothRemovalPathsTakeTheBaseLock(t *testing.T) {
	s, _, older := setAsideServer(t)
	disk, _ := pitoverlay.DiskOfOrphan(older)
	assertSerializedByVMLock(t, s, pitOrphanBaseLock(disk), func() {
		_, _ = s.RemoveSetAsideOverlay(adminCtx(), &pb.RemoveSetAsideOverlayRequest{VmName: "web", DiskName: "root", Name: filepath.Base(older)})
	})
	if hygieneFileThere(older) {
		t.Fatal("not removed once the lock was free")
	}
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "gone-root.qcow2")
	o := pitoverlay.Path(base) + ".orphan-20261001-000000"
	if err := os.WriteFile(o, []byte("o"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertSerializedByVMLock(t, s, pitOrphanBaseLock(base), func() {
		_, _ = s.RemoveSetAsideOverlay(adminCtx(), &pb.RemoveSetAsideOverlayRequest{Path: o})
	})
}

// R3 n-2. The forward-once marker is honoured only from a cluster peer: a
// client (a bearer, an operator's own mTLS) that sends it has it ignored, so
// its request is forwarded as any other (here: the third host cannot be
// dialled, Unavailable), never refused as a second hop.
//
// Mutation "marker from any caller": Aborted; red.
func TestForwardOnce_AClientsForgedMarkerIsIgnored(t *testing.T) {
	s, _, _ := setAsideServer(t)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "away", HostName: "third-host", State: "running", Spec: `{"name":"away"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(adminCtx(), metadata.Pairs(forwardedHopMDKey, "forged"))
	_, err := s.RemoveSetAsideOverlay(ctx, &pb.RemoveSetAsideOverlayRequest{VmName: "away", DiskName: "root", Name: ".x.lv-pit.orphan-20261018-120000"})
	if status.Code(err) == codes.Aborted {
		t.Fatalf("a client's forged marker was honoured: %v", err)
	}
}

// R3 n-2, the sending side. A forward carries the marker and the operator.
//
// Mutation "forwardOnce does not mark": red.
func TestForwardOnce_MarksTheForward(t *testing.T) {
	s := &Server{hostName: "node-a"}
	md, ok := metadata.FromOutgoingContext(s.forwardOnce(context.Background(), "alice"))
	if !ok || len(md.Get(forwardedHopMDKey)) != 1 || md.Get(forwardedHopMDKey)[0] != "node-a" || len(md.Get(repairActorMDKey)) != 1 {
		t.Fatalf("outgoing metadata %v: want the forward-once marker naming node-a and the actor", md)
	}
}

// R3 n-3. A host told to remove a detached overlay by path is never asked to
// pass it on: the refusal names the path and the host it was sent to, not a
// VM or a replica's placement.
func TestForwardOnce_APathForwardIsRefusedByPath(t *testing.T) {
	s, _, _ := setAsideServer(t)
	ctx := peerCtxFor(t, s, "node-x")
	ctx = context.WithValue(context.WithValue(ctx, ctxKeyUsername, "admin"), ctxKeyRole, "admin")
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(forwardedHopMDKey, "node-x"))
	_, err := s.RemoveSetAsideOverlay(ctx, &pb.RemoveSetAsideOverlayRequest{Host: "third-host", Path: "/srv/p/.x.lv-pit.orphan-20261018-120000"})
	if status.Code(err) != codes.Aborted || strings.Contains(err.Error(), "vm \"") || !strings.Contains(err.Error(), "/srv/p/.x.lv-pit.orphan-20261018-120000") {
		t.Fatalf("a forwarded path removal for another host = %v; want Aborted naming the path, not a vm", err)
	}
}
