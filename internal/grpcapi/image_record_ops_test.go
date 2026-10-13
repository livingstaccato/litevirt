package grpcapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
)

// rmOnRecord deletes image name's row when an operation begins recording its
// copy (recordImage): lv image rm landing while the operation ran.
func rmOnRecord(t *testing.T, s *Server, name string) {
	t.Helper()
	s.SetImageRecordHookForTest(func(n string) {
		if n == name {
			if err := corrosion.DeleteImage(context.Background(), s.db, name); err != nil {
				t.Errorf("delete %s: %v", name, err)
			}
		}
	})
	t.Cleanup(func() { s.SetImageRecordHookForTest(nil) })
}

func rowDeleted(t *testing.T, s *Server, name string) bool {
	t.Helper()
	d, err := corrosion.ImageDeletedAt(context.Background(), s.db, name)
	if err != nil {
		t.Fatal(err)
	}
	return d != ""
}

// lv image build (review round 2): a build whose row is deleted while it runs
// records nothing (Aborted), and a build under a deleted name brings it back,
// as on main.
func TestBuildImage_RevivesADeletedNameUnlessDeletedWhileItRan(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	src, err := s.images.CreateEmptyDisk("vm1", "root", "1M")
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "stopped", Spec: `{}`}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: s.hostName, Path: src, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	build := func() error {
		_, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "vm1", ImageName: "golden"})
		return err
	}
	if err := build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	rmOnRecord(t, s, "golden")
	if err := build(); status.Code(err) != codes.Aborted {
		t.Fatalf("a build lv image rm landed in: %v, want Aborted", err)
	}
	if !rowDeleted(t, s, "golden") {
		t.Fatal("a build lv image rm landed in brought the image back")
	}
	s.SetImageRecordHookForTest(nil)
	before := streamLen(t, s)
	if err := build(); err != nil {
		t.Fatalf("a build under a deleted name: %v, want it to bring the image back", err)
	}
	if rowDeleted(t, s, "golden") {
		t.Fatal("a build under a deleted name left it deleted")
	}
	if !streamHas(t, s, before, reviveStmt) {
		t.Fatal("a build under a deleted name revived it here only: the catalog revive is not on the stream")
	}
}

// A compose deploy's download (review round 2): one whose row is deleted
// while it downloads records nothing (Aborted), and a deploy naming a deleted
// image downloads it and brings it back, as on main.
func TestAutoPullImages_RevivesADeletedNameUnlessDeletedWhileItRan(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("fake-qcow2-data"))
	}))
	defer ts.Close()
	s := testServer(t)
	s.images = image.NewStore(t.TempDir())
	if err := s.images.Init(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// The image is in the catalog but held by no host: the deploy downloads it.
	if err := corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{Name: "myimg", Format: "qcow2"}); err != nil {
		t.Fatal(err)
	}
	f := &compose.File{
		Images: map[string]compose.ImageDef{"myimg": {Source: ts.URL + "/myimg.qcow2", Format: "qcow2"}},
		VMs:    map[string]compose.VMDef{"web": {Image: "myimg"}},
	}
	rmOnRecord(t, s, "myimg")
	if err := s.autoPullImages(ctx, f, &mockDeployStream{ctx: ctx}); status.Code(err) != codes.Aborted {
		t.Fatalf("a compose download lv image rm landed in: %v, want Aborted", err)
	}
	if !rowDeleted(t, s, "myimg") {
		t.Fatal("a compose download lv image rm landed in brought the image back")
	}
	s.SetImageRecordHookForTest(nil)
	if err := s.images.RemoveDeletedImageFile("myimg", s.images.ImagePath("myimg")); err != nil {
		t.Fatal(err)
	}
	before, hitsBefore := streamLen(t, s), hits.Load()
	if err := s.autoPullImages(ctx, f, &mockDeployStream{ctx: ctx}); err != nil {
		t.Fatalf("a compose deploy naming a deleted image: %v, want it downloaded and brought back", err)
	}
	if hits.Load() == hitsBefore {
		t.Fatal("a compose deploy naming a deleted image did not download it")
	}
	if rowDeleted(t, s, "myimg") {
		t.Fatal("a compose download under a deleted name left it deleted")
	}
	if !streamHas(t, s, before, reviveStmt) {
		t.Fatal("a compose download under a deleted name revived it here only: the catalog revive is not on the stream")
	}
}

// streamHas reports whether an entry this node put on its stream after the
// first `after` entries contains stmt.
func streamHas(t *testing.T, s *Server, after int, stmt string) bool {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq LIMIT -1 OFFSET ?`, after)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if strings.Contains(r.String("stmts"), stmt) {
			return true
		}
	}
	return false
}

// A compose deploy naming a deleted image downloads it even when another
// host's record of a copy reads live under the deleted catalog row (review
// re-review 1, R-m5): that copy names no source.
func TestAutoPullImages_AHostRecordUnderADeletedImageIsNoSource(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("fake-qcow2-data"))
	}))
	defer ts.Close()
	s := testServer(t)
	s.images = image.NewStore(t.TempDir())
	if err := s.images.Init(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{Name: "myimg", Format: "qcow2"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteImage(ctx, s.db, "myimg"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.ReviveImageHost(ctx, s.db, corrosion.ImageHostRecord{ImageName: "myimg", HostName: "node-2", Path: "/x", Status: "ready", PulledAt: "2026-10-13T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	f := &compose.File{
		Images: map[string]compose.ImageDef{"myimg": {Source: ts.URL + "/myimg.qcow2", Format: "qcow2"}},
		VMs:    map[string]compose.VMDef{"web": {Image: "myimg"}},
	}
	if err := s.autoPullImages(ctx, f, &mockDeployStream{ctx: ctx}); err != nil {
		t.Fatalf("compose deploy: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatal("the deploy took a host record under a deleted image as a source and did not download it")
	}
	if rowDeleted(t, s, "myimg") {
		t.Fatal("the deploy's download did not bring the image back")
	}
}
