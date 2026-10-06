package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Fix round 3 follow-up.

// flattenedSinceBackup is project a's VM "im" on an image, with an overlay
// backup pushed at ts recording its base; the disk has since been flattened
// by a move (its file is standalone, its record names no backing). Returns
// the disk, the image and what the guest saw at backup time.
func flattenedSinceBackup(t *testing.T, f *restoreFixture, ts string) (disk, img string, want []byte) {
	t.Helper()
	images := filepath.Join(f.s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	img = filepath.Join(images, "ubuntu.qcow2")
	baseRaw := filepath.Join(t.TempDir(), "base.raw")
	if err := os.WriteFile(baseRaw, bytes.Repeat([]byte("BASE "), 1<<20/5+1)[:1<<20], 0o600); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "convert", "-q", "-f", "raw", "-O", "qcow2", baseRaw, img)
	disk = filepath.Join(f.s.dataDir, "disks", "im-root.qcow2")
	base := bytes.Repeat([]byte("BASE "), 1<<20/5+1)[:1<<20]
	content := append(bytes.Repeat([]byte("DELTA"), 65536/5+1)[:65536], base[65536:]...)
	overlayWithData(t, disk, img, "qcow2", content) // an overlay holding only the changed cluster
	if info, err := qcow2.Info(disk); err != nil || info.BackingFile == "" {
		t.Fatalf("fixture: the disk is not an overlay (%v)", err)
	}
	want = guestView(t, disk)
	backedVM(t, f, "im", disk, corrosion.DiskRecord{StorageType: "local"})
	pushVM(t, f, "im", disk, ts, pbsstore.ContentDiskFile, "")
	// Flattened by a move since.
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "create", "-q", "-f", "qcow2", disk, "1M")
	return disk, img, want
}

// An overlay backup of a disk flattened since is rebuilt FLAT from the backup
// and the base it recorded, when that base is still there and unchanged.
func TestRestoreInPlace_FlattenedDiskIsRebuiltFlatOnTheRecordedBase(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	const ts = "2026-10-09T10:00:00Z"
	disk, _, want := flattenedSinceBackup(t, f, ts)
	if err := inPlace(f, "im", ts); err != nil {
		t.Fatalf("in-place restore of an overlay backup onto a flattened disk: %v", err)
	}
	if err := qcow2.AssertStandalone(disk); err != nil {
		t.Errorf("the restored disk is not flat: %v", err)
	}
	if got := guestView(t, disk); !bytes.Equal(got, want) {
		t.Error("the flat restore does not show what the guest saw at backup time")
	}
}

// ... and refused, saying why and that a new file still works, when the
// recorded base has changed.
func TestRestoreInPlace_FlattenedDiskOnAChangedBaseIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	const ts = "2026-10-09T11:00:00Z"
	disk, img, _ := flattenedSinceBackup(t, f, ts)
	if err := os.Remove(img); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "create", "-q", "-f", "qcow2", img, "1M") // re-pulled, different
	before, _ := os.ReadFile(disk)
	err := inPlace(f, "im", ts)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "has changed") || !strings.Contains(err.Error(), "new file") {
		t.Errorf("flattened disk on a changed base: got %v, want FailedPrecondition naming the change and the new-file route", err)
	}
	if after, _ := os.ReadFile(disk); !bytes.Equal(before, after) {
		t.Error("the disk was replaced")
	}
}

// countingPushPeer counts the PushImage calls a heal makes and fails them.
type countingPushPeer struct {
	pb.LiteVirtClient
	pushes int
}

func (c *countingPushPeer) PushImage(context.Context, *pb.PushImageRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PushImageProgress], error) {
	c.pushes++
	return nil, status.Error(codes.Unavailable, "test peer")
}

// ... and refused when the recorded base lies outside every place the disk's
// chain may read from, unchanged or not.
func TestRestoreInPlace_FlattenedDiskOnABaseOutsideTheRootsIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	outside := filepath.Join(t.TempDir(), "elsewhere.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", outside, "1M")
	disk := filepath.Join(f.s.dataDir, "disks", "im-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-b", outside, "-F", "qcow2", disk)
	backedVM(t, f, "im", disk, corrosion.DiskRecord{StorageType: "local"})
	const ts = "2026-10-09T12:00:00Z"
	pushVM(t, f, "im", disk, ts, pbsstore.ContentDiskFile, "") // records the outside base
	if err := os.Remove(disk); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "create", "-q", "-f", "qcow2", disk, "1M")
	if err := inPlace(f, "im", ts); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "outside") {
		t.Errorf("flattened disk on a base outside the roots: got %v, want FailedPrecondition naming it", err)
	}
}
