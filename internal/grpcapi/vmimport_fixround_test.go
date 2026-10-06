package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// uploadImportServer's import filesystem has room bytes free above its
// headroom, less what the files under its imports directory occupy.
func uploadImportServer(t *testing.T, room uint64) *Server {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	imports := filepath.Join(s.dataDir, "imports")
	s.diskSpaceOverride = func(string) (uint64, uint64, error) {
		var used uint64
		_ = filepath.Walk(imports, func(p string, fi os.FileInfo, err error) error {
			if err == nil && fi.Mode().IsRegular() {
				n, _ := fileAllocated(p)
				used += n
			}
			return nil
		})
		return coldDiskHeadroom(spaceTestTotal) + room - min(room, used), spaceTestTotal, nil
	}
	return s
}

// uploadFrames is an upload of n chunks of 1 MiB of data (no holes).
func uploadFrames(name string, n int) []*pb.ImportVMRequest {
	chunk := bytes.Repeat([]byte{0xa5}, 1<<20)
	frames := []*pb.ImportVMRequest{{Name: name, SourceFormat: "ova", Chunk: chunk}}
	for range n - 1 {
		frames = append(frames, &pb.ImportVMRequest{Chunk: chunk})
	}
	return frames
}

// An upload is a write like any other: one larger than the room is refused
// as it arrives, before it fills the filesystem state.db is on.
func TestImportVM_AnUploadLargerThanTheRoomIsRefusedMidStream(t *testing.T) {
	s := uploadImportServer(t, 4<<20)
	st := &fakeImportStream{ctx: adminCtx(), frames: uploadFrames("imp-up", 8)}
	err := s.ImportVM(st)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "uploading") {
		t.Fatalf("an 8 MiB upload into 4 MiB of room: %v, want a refusal of the upload", err)
	}
	if st.i >= len(st.frames) {
		t.Fatal("the whole upload was read before it was refused")
	}
	if left, _ := filepath.Glob(filepath.Join(s.dataDir, "imports", "imp-up-*")); len(left) != 0 {
		t.Fatalf("a refused upload left %v", left)
	}
}

// An upload does not take room another import has reserved.
func TestImportVM_AnUploadDoesNotTakeAnotherImportsReservation(t *testing.T) {
	s := uploadImportServer(t, 4<<20)
	other := s.reserveImportSpace(t.TempDir())
	defer other.release()
	if err := other.reserve(filepath.Join(s.dataDir), 3<<20, "another import"); err != nil {
		t.Fatal(err)
	}
	err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: uploadFrames("imp-up", 2)})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("a 2 MiB upload beside 3 MiB reserved of 4: %v, want a refusal naming the reservation", err)
	}
}

// Where a filesystem counts a file's blocks before it takes them from its
// free space (btrfs counts dirty data in st_blocks at once), what an import
// has allocated is not yet gone from the free space: its reservation must not
// shrink until the free space shows the bytes gone.
func TestImportSpace_AllocatedBytesTheFreeSpaceDoesNotShowYetStayReserved(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	s := &Server{hostName: "test-host"}
	s.diskSpaceOverride = func(string) (uint64, uint64, error) {
		return coldDiskHeadroom(spaceTestTotal) + 10<<20, spaceTestTotal, nil // never drops
	}
	ra := s.reserveImportSpace(a)
	defer ra.release()
	if err := ra.reserve(a, 8<<20, "a"); err != nil {
		t.Fatal(err)
	}
	writeAllocated(t, a, 4<<20)
	ra.refresh()
	rb := s.reserveImportSpace(b)
	defer rb.release()
	refusedForReservation(t, rb.reserve(b, 3<<20, "b"))
}

// Imports writing to different filesystems do not count against each other;
// on one filesystem they still do, and a filesystem that cannot be told
// apart counts as the same as every other.
func TestImportSpace_ReservationsCountOnlyOnTheirOwnFilesystem(t *testing.T) {
	a, a2, b, unknown := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	s := &Server{hostName: "test-host"}
	s.diskSpaceOverride = func(string) (uint64, uint64, error) {
		return coldDiskHeadroom(spaceTestTotal) + 10<<20, spaceTestTotal, nil
	}
	s.fsKeyOverride = func(dir string) string {
		switch dir {
		case a, a2:
			return "fs-a"
		case b:
			return "fs-b"
		}
		return ""
	}
	ra := s.reserveImportSpace(a)
	defer ra.release()
	if err := ra.reserve(a, 8<<20, "a"); err != nil {
		t.Fatal(err)
	}
	rb := s.reserveImportSpace(b)
	defer rb.release()
	if err := rb.reserve(b, 8<<20, "b"); err != nil {
		t.Fatalf("an import on another filesystem: %v", err)
	}
	rc := s.reserveImportSpace(a2)
	defer rc.release()
	refusedForReservation(t, rc.reserve(a2, 4<<20, "c"))
	rd := s.reserveImportSpace(unknown)
	defer rd.release()
	refusedForReservation(t, rd.reserve(unknown, 4<<20, "d"))
}

// A released reservation admits nothing: a write admitted by it would be
// counted by no one.
func TestImportSpace_AReleasedReservationAdmitsNothing(t *testing.T) {
	a := t.TempDir()
	s := spaceTestServer(t, 10<<20)
	r := s.reserveImportSpace(a)
	r.release()
	if err := r.reserve(a, 1<<20, "a"); err == nil {
		t.Fatal("a released reservation admitted a write")
	}
}

// Two imports of one VM name at once would write the same file in the pool:
// the second is refused while the first is in flight.
func TestImportVM_ASecondImportOfTheSameNameIsRefused(t *testing.T) {
	gate := t.TempDir()
	gatedQemuImg(t, gate)
	s := concurrentImportServer(t, 10*oneDiskNeed())
	errA := make(chan error, 1)
	go func() {
		errA <- s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "web", false)}})
	}()
	opened := false
	t.Cleanup(func() {
		if !opened {
			openGate(t, gate)
			<-errA
		}
	})
	if !waitArrivals(t, gate, 1) {
		t.Fatal("the first import never reached its conversion")
	}
	ctx, cancel := context.WithTimeout(adminCtx(), 10*time.Second)
	defer cancel()
	err := s.ImportVM(&fakeImportStream{ctx: ctx, frames: []*pb.ImportVMRequest{smallImportFrame(t, "web", false)}})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a second import of a name in flight: %v, want AlreadyExists", err)
	}
	opened = true
	openGate(t, gate)
	if err := <-errA; err != nil {
		t.Fatalf("the first import: %v", err)
	}
}

// A file already at the converted disk's name in the pool — another VM's
// disk — is never replaced, and the refused import does not remove it.
func TestImportVM_AnExistingDiskInThePoolIsNeverReplaced(t *testing.T) {
	s := concurrentImportServer(t, 10*oneDiskNeed())
	stubQemuImg(t)
	poolDir, err := s.importPoolDir(adminCtx(), "")
	if err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(poolDir, "imp-dst-root.qcow2")
	if err := os.WriteFile(theirs, []byte("another project's disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-dst", false)}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an import onto an existing disk's name: %v, want FailedPrecondition", err)
	}
	if b, _ := os.ReadFile(theirs); string(b) != "another project's disk" {
		t.Fatalf("the existing disk now holds %q", b)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-dst"); rec != nil {
		t.Fatal("a refused import persisted a row")
	}
}

func TestMountOf_FindsTheMountAPathIsOn(t *testing.T) {
	info := `22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
40 22 0:35 /@var /var rw,relatime shared:20 - btrfs /dev/sdb1 rw,subvol=/@var
41 22 0:36 /@srv /srv rw,relatime shared:21 - btrfs /dev/sdb1 rw,subvol=/@srv
50 22 0:50 / /tank/vm\040disks rw shared:30 - zfs tank/vm rw
51 22 0:51 / /mnt/nfs rw shared:31 - nfs4 10.0.0.5:/export/a rw
52 51 0:52 / /mnt/nfs rw shared:32 - nfs4 10.0.0.6:/export/b rw
53 22 0:53 / /var/lib/litevirtx rw - ext4 /dev/sdc1 rw
`
	for _, c := range []struct{ p, fstype, source string }{
		{"/var/lib/litevirt", "btrfs", "/dev/sdb1"},
		{"/srv/vms", "btrfs", "/dev/sdb1"},
		{"/tank/vm disks/x", "zfs", "tank/vm"},
		{"/mnt/nfs/pool", "nfs4", "10.0.0.6:/export/b"}, // the later mount hides the earlier
		{"/home", "ext4", "/dev/sda2"},
		{"/var/lib/litevirtx/a", "ext4", "/dev/sdc1"},
	} {
		fstype, source, ok := mountOf(info, c.p)
		if !ok || fstype != c.fstype || source != c.source {
			t.Errorf("%s: %s %s %v, want %s %s", c.p, fstype, source, ok, c.fstype, c.source)
		}
	}
}

func TestFSKeyFor_NamesSharedFreeSpaceOnce(t *testing.T) {
	dev := func() fsKey { return "dev:7" }
	for _, c := range []struct {
		fstype, source string
		want           fsKey
	}{
		{"btrfs", "/dev/sdb1", "btrfs:/dev/sdb1"},
		{"zfs", "rpool/data/vm", "zfs:rpool"},
		{"zfs", "rpool", "zfs:rpool"},
		{"nfs4", "10.0.0.5:/export/a", "nfs:10.0.0.5"},
		{"nfs", "[fd00::1]:/x", "nfs:[fd00::1]"},
		{"ext4", "/dev/sda2", "dev:7"},
		{"xfs", "/dev/sda3", "dev:7"},
		{"overlay", "overlay", ""},
		{"fuse.sshfs", "h:/x", ""},
		{"ceph", "1.2.3.4:/", ""},
		{"btrfs", "none", ""},
	} {
		if got := fsKeyFor(c.fstype, c.source, dev); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.fstype, c.source, got, c.want)
		}
	}
}
