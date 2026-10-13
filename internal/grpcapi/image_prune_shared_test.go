package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/notify"
)

// Review round 1, I-2: on an image store other hosts may share, versions no
// disk here is built on are kept (lab 2 N-7). The operator gets an explicit
// way to remove one they know no other host uses, and the growth is not
// silent.

// --version removes the one named file on a shared store; every other rule
// still keeps a version, saying why; a name that matches nothing is refused.
//
// Mutations, each red: "--version does not lift the shared-store keep" (the
// old version stays); "--version judges every file" (the other unused
// version goes too); "the in-use version named is removed".
func TestPruneImages_VersionRemovesOneFileOnASharedStore(t *testing.T) {
	s, old, used := prunableStore(t)
	other := publishVersion(t, s, "ubuntu", "OTHER ", "")
	publishVersion(t, s, "ubuntu", "NEWEST ", "")
	s.imagePrune.storeFS = func(string) (string, error) { return "nfs", nil }

	// Kept without --version, each with the way to remove it.
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil || len(resp.Removed) != 0 {
		t.Fatalf("plain prune on a shared store: removed %v, %v", resp.GetRemoved(), err)
	}
	if why := keptFor(resp, old); !strings.Contains(why, "--version "+filepath.Base(old)) {
		t.Fatalf("kept reason %q does not say how to remove it", why)
	}

	// The digest after '@' names it as well as the file name.
	_, digest, _ := strings.Cut(strings.TrimSuffix(filepath.Base(old), ".qcow2"), "@")
	resp, err = s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu", Version: digest[:8]})
	if err != nil {
		t.Fatalf("prune --version: %v", err)
	}
	if len(resp.Removed) != 1 || resp.Removed[0] != old || resp.Version != digest[:8] {
		t.Fatalf("prune --version removed %v (version echoed %q); want only %s", resp.Removed, resp.Version, old)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("%s is still there: %v", old, err)
	}
	for _, f := range []string{other, used} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s is gone: %v", f, err)
		}
	}

	// A version a disk here is built on is kept, saying so.
	resp, err = s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu", Version: filepath.Base(used)})
	if err != nil || len(resp.Removed) != 0 {
		t.Fatalf("prune --version of the used version: removed %v, %v", resp.GetRemoved(), err)
	}
	if why := keptFor(resp, used); !strings.Contains(why, "built on it") {
		t.Fatalf("the used version's kept reason %q; want the disk built on it", why)
	}

	// No such file.
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu", Version: "ubuntu@0000000000000000.qcow2"}); err == nil {
		t.Fatal("a version that names no file was not refused")
	}
	// A version without its image.
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Version: filepath.Base(other)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a version without its image: %v; want InvalidArgument", err)
	}
}

// A refresh's background prune reports what it keeps only because the store
// may be shared: a notification, at most daily per image, with the count and
// bytes. It used to drop the kept list.
//
// Mutation "the background prune does not report" — red.
func TestPruneAfterRefresh_ReportsVersionsKeptOnASharedStore(t *testing.T) {
	s, old, _ := prunableStore(t)
	s.imagePrune.storeFS = func(string) (string, error) { return "nfs", nil }
	var mu sync.Mutex
	var seen []notify.Notification
	s.notifySeen = func(n notify.Notification) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, n)
	}
	for i := 0; i < 2; i++ {
		s.pruneAfterRefresh("ubuntu")
		s.waitImagePrunes()
	}
	mu.Lock()
	defer mu.Unlock()
	var kept []notify.Notification
	for _, n := range seen {
		if n.Kind == "image.versions_kept" {
			kept = append(kept, n)
		}
	}
	if len(kept) != 1 {
		t.Fatalf("image.versions_kept sent %d times over two refreshes; want once a day: %v", len(kept), seen)
	}
	if !strings.Contains(kept[0].Detail, "bytes") || !strings.Contains(kept[0].Detail, "--version") {
		t.Fatalf("notification %q does not give the bytes and the way to remove one", kept[0].Detail)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("the background prune removed %s from a shared store: %v", old, err)
	}
}

// olderPeer answers PruneImages as a build without --version does: it does
// not echo the version (and would prune the whole image).
type olderPeer struct {
	pb.LiteVirtClient
	calls []*pb.PruneImagesRequest
}

func (p *olderPeer) PruneImages(_ context.Context, req *pb.PruneImagesRequest, _ ...grpc.CallOption) (*pb.PruneImagesResponse, error) {
	p.calls = append(p.calls, req)
	return &pb.PruneImagesResponse{HostName: "old-host"}, nil
}

// A host that does not honour --version is found with a dry run, which
// removes nothing on any build, and the real call is never sent.
//
// Mutation "no probe" — the removing call reaches the older peer: red.
func TestProbePruneVersion_AnOlderPeerIsNeverAskedToRemove(t *testing.T) {
	p := &olderPeer{}
	err := probePruneVersion(context.Background(), p, &pb.PruneImagesRequest{Name: "ubuntu", HostName: "old-host", Version: "ubuntu@0123456789abcdef.qcow2"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("probe of an older peer: %v; want FailedPrecondition", err)
	}
	for _, c := range p.calls {
		if !c.DryRun {
			t.Fatalf("a removing call was sent to the older peer: %+v", c)
		}
	}
}
