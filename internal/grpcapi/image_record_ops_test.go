package grpcapi

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// lv image build (review round 1, I-1): a build whose row is deleted while it
// runs records nothing, and a build under a deleted name is refused before it
// reads the VM's disk.
func TestBuildImage_NeverRevivesADeletedName(t *testing.T) {
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
		t.Fatal("the build brought the deleted image back")
	}
	s.SetImageRecordHookForTest(nil)
	if err := build(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a build under a deleted name: %v, want FailedPrecondition", err)
	}
	if !rowDeleted(t, s, "golden") {
		t.Fatal("a build under a deleted name brought it back")
	}
}

// A compose deploy's download (review round 1, I-1): one whose row is deleted
// while it downloads records nothing, and a deleted name is not downloaded.
func TestAutoPullImages_NeverRevivesADeletedName(t *testing.T) {
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
		t.Fatal("the compose download brought the deleted image back")
	}
	s.SetImageRecordHookForTest(nil)
	if err := s.images.RemoveDeletedImageFile("myimg", s.images.ImagePath("myimg")); err != nil {
		t.Fatal(err)
	}
	before := hits.Load()
	if err := s.autoPullImages(ctx, f, &mockDeployStream{ctx: ctx}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a compose download of a deleted name: %v, want FailedPrecondition", err)
	}
	if hits.Load() != before {
		t.Error("a compose deploy downloaded a deleted name")
	}
	if !rowDeleted(t, s, "myimg") {
		t.Fatal("a compose download of a deleted name brought it back")
	}
}
