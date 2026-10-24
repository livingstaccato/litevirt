package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// While kept-disks.json cannot be read, a symlink below a directory the scan
// lists is followed: a kept overlay in a symlinked subdirectory of a pool is
// on this host as much as one in the pool itself, and refuses the create
// that would write its missing base. A link back to a directory already
// listed ends there, a link naming nothing holds nothing, and a link that
// cannot be followed refuses, naming it, as a directory that cannot be
// listed does.
//
// Red on ac354d1a6: "an overlay below a symlinked subdirectory" and "an
// overlay a symlinked file names" (the create goes ahead and writes the
// base), and "a link that cannot be followed" (skipped). Mutation: skip
// symlinks again in keptCollisionScan (drop the ModeSymlink case): the same
// three red; list a followed directory by its link path instead of its
// resolved one: "a link back to the pool" red (the walk descends the loop
// until the path cannot be listed, and refuses).
func TestCreateVM_KeptScanFollowsASymlinkBelowARoot(t *testing.T) {
	pool := func(t *testing.T) (*Server, string) {
		s, _ := provableCreateServer(t)
		dir := filepath.Join(t.TempDir(), "ssd")
		writePathsDirPool(t, s, "ssd", dir)
		return s, dir
	}
	link := func(t *testing.T, target, at string) {
		t.Helper()
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("an overlay below a symlinked subdirectory", func(t *testing.T) {
		s, dir := pool(t)
		real := filepath.Join(t.TempDir(), "real")
		ov := filepath.Join(real, "deeper", "db-snap1.qcow2")
		base := filepath.Join(dir, "web-root.qcow2")
		overlayOn(t, ov, base)
		link(t, real, filepath.Join(dir, "sub"))
		named := unreadableKeptRegistry(t, s)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd"))
		wantMissingBaseRefusal(t, "create with an overlay below a symlinked subdirectory", err, "db-snap1.qcow2", base)
		if !strings.Contains(err.Error(), named) {
			t.Fatalf("create web = %v; want it naming %s", err, named)
		}
	})
	t.Run("an overlay a symlinked file names", func(t *testing.T) {
		s, dir := pool(t)
		ov := filepath.Join(t.TempDir(), "db-snap1.qcow2")
		base := filepath.Join(dir, "web-root.qcow2")
		overlayOn(t, ov, base)
		link(t, ov, filepath.Join(dir, "db-snap1.qcow2"))
		unreadableKeptRegistry(t, s)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd"))
		wantMissingBaseRefusal(t, "create with an overlay a symlink in the pool names", err, ov, base)
	})
	t.Run("a link back to the pool, and one naming nothing, go ahead", func(t *testing.T) {
		s, dir := pool(t)
		link(t, dir, filepath.Join(dir, "loop"))
		link(t, filepath.Join(t.TempDir(), "gone"), filepath.Join(dir, "dangling"))
		unreadableKeptRegistry(t, s)
		if _, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd")); err != nil {
			t.Fatalf("create on a pool no file on this host names, while kept-disks.json cannot be read: %v", err)
		}
		if !exists(filepath.Join(dir, "web-root.qcow2")) {
			t.Fatal("the create did not write its disk in the pool: this proves nothing")
		}
	})
	t.Run("a link that cannot be followed", func(t *testing.T) {
		s, dir := pool(t)
		a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
		link(t, b, a)
		link(t, a, b)
		named := unreadableKeptRegistry(t, s)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd"))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) ||
			!(strings.Contains(err.Error(), a) || strings.Contains(err.Error(), b)) {
			t.Fatalf("create web = %v; want FailedPrecondition naming %s and the link", err, named)
		}
		if exists(filepath.Join(dir, "web-root.qcow2")) {
			t.Fatal("a refused create wrote its disk")
		}
	})
}
