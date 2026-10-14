package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// renameNoReplaceAnswers makes renameat2(RENAME_NOREPLACE) answer errno, as
// the Linux NFS client does (EINVAL) for a rename with flags. link() stays
// the real one. The test fails unless the placement went through it: a
// placement that bypasses the seam (base's direct renameat2) would otherwise
// pass on a filesystem whose renameat2 works.
func renameNoReplaceAnswers(t *testing.T, errno syscall.Errno) {
	t.Helper()
	l, r, n := coldLink, coldRemove, coldRenameNoReplace
	var calls atomic.Int32
	t.Cleanup(func() {
		coldLink, coldRemove, coldRenameNoReplace = l, r, n
		if calls.Load() == 0 {
			t.Errorf("the placement never called renameat2 through its seam")
		}
	})
	coldRenameNoReplace = func(o, nw string) error {
		calls.Add(1)
		return &os.LinkError{Op: "renameat2", Old: o, New: nw, Err: errno}
	}
}

// countLinks wraps link() (as it is now: the real one, or a test's) with a
// counter, and fails the test unless the placement linked at least once.
func countLinks(t *testing.T) {
	t.Helper()
	inner := coldLink
	var calls atomic.Int32
	t.Cleanup(func() {
		if calls.Load() == 0 {
			t.Errorf("the placement never called link() through its seam")
		}
	})
	coldLink = func(o, n string) error {
		calls.Add(1)
		return inner(o, n)
	}
}

func noClobberFixture(t *testing.T) (tmp, dst string) {
	t.Helper()
	dir := t.TempDir()
	tmp, dst = filepath.Join(dir, ".repl-1.tmp"), filepath.Join(dir, "root-1.qcow2")
	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	return tmp, dst
}

// Lab 2: every no-clobber placement on an NFS pool failed with
// "renameat2 ...: invalid argument". A filesystem without RENAME_NOREPLACE
// gets a hard link, which never replaces a file either.
//
// Mutations: drop the link fallback — the placement fails, red. Make the
// fallback a plain os.Rename — the existing file is replaced, red.
func TestPlaceNoClobber_WithoutRenameNoReplaceLinks(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EINVAL, syscall.ENOSYS, syscall.EOPNOTSUPP} {
		t.Run(errno.Error(), func(t *testing.T) {
			renameNoReplaceAnswers(t, errno)
			countLinks(t)

			tmp, dst := noClobberFixture(t)
			if err := placeNoClobber(tmp, dst); err != nil {
				t.Fatalf("placeNoClobber where renameat2 answers %v: %v", errno, err)
			}
			if got, _ := os.ReadFile(dst); string(got) != "new" {
				t.Fatalf("dst holds %q, want the placed file", got)
			}
			if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
				t.Fatalf("the temporary name is still there after the placement (lstat: %v)", err)
			}

			tmp, dst = noClobberFixture(t)
			if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := placeNoClobber(tmp, dst); status.Code(err) != codes.AlreadyExists {
				t.Fatalf("placeNoClobber over a file where renameat2 answers %v: %v, want AlreadyExists", errno, err)
			}
			if got, _ := os.ReadFile(dst); string(got) != "old" {
				t.Fatalf("the existing file now holds %q", got)
			}
		})
	}
}

// A filesystem with neither RENAME_NOREPLACE nor hard links is refused,
// naming the limitation; nothing is placed and the temp keeps its bytes.
//
// Mutations: fall back to os.Rename when link is unsupported — dst appears,
// red. Internal for "neither" — red.
func TestPlaceNoClobber_NeitherRenameNoReplaceNorLinkRefuses(t *testing.T) {
	renameNoReplaceAnswers(t, syscall.EINVAL)
	coldLink = func(o, n string) error { return &os.LinkError{Op: "link", Old: o, New: n, Err: syscall.EPERM} }
	countLinks(t)
	tmp, dst := noClobberFixture(t)
	err := placeNoClobber(tmp, dst)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "supports neither hard links") {
		t.Fatalf("placeNoClobber with neither = %v, want a FailedPrecondition refusal naming the filesystem limitation", err)
	}
	if _, serr := os.Lstat(dst); !os.IsNotExist(serr) {
		t.Fatalf("dst exists after a refused placement (lstat: %v)", serr)
	}
	if got, _ := os.ReadFile(tmp); string(got) != "new" {
		t.Fatalf("the temp holds %q after a refused placement", got)
	}
}

// An NFS link whose reply was lost is retransmitted and answered EEXIST,
// although the first made the link: dst is then the temp itself, placed.
// A dst that is another file is still refused (the test above).
//
// Mutation: drop the same-file check — AlreadyExists over its own copy, red.
func TestPlaceNoClobber_ALinkAnsweredEEXISTForItsOwnLinkIsPlaced(t *testing.T) {
	renameNoReplaceAnswers(t, syscall.EINVAL)
	coldLink = func(o, n string) error {
		if err := os.Link(o, n); err != nil {
			return err
		}
		return &os.LinkError{Op: "link", Old: o, New: n, Err: syscall.EEXIST}
	}
	countLinks(t)
	tmp, dst := noClobberFixture(t)
	if err := placeNoClobber(tmp, dst); err != nil {
		t.Fatalf("placeNoClobber after a retransmitted link: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new" {
		t.Fatalf("dst holds %q", got)
	}
	if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
		t.Fatalf("the temporary name is still there (lstat: %v)", err)
	}
}

// Once the link has placed the file, a temp name that cannot be removed is
// left for the sweep; the placement stands.
//
// Mutation: return the remove's error — red.
func TestPlaceNoClobber_LinkedButTempNotRemovedStillPlaces(t *testing.T) {
	renameNoReplaceAnswers(t, syscall.EINVAL)
	coldRemove = func(string) error { return errors.New("injected remove failure") }
	countLinks(t)
	tmp, dst := noClobberFixture(t)
	if err := placeNoClobber(tmp, dst); err != nil {
		t.Fatalf("placeNoClobber with a failed temp remove = %v, want placed", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new" {
		t.Fatalf("dst holds %q", got)
	}
}

// Lab 2: replication into an NFS pool published nothing, every tick. With
// renameat2 answering EINVAL the replica and its record are published.
func TestReplicateLocal_PublishesWhereRenameNoReplaceIsUnsupported(t *testing.T) {
	renameNoReplaceAnswers(t, syscall.EINVAL)
	countLinks(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "web-1", HostName: s.hostName, State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	dir := replicaPoolDir(t, s, "dr")
	srcPath := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(srcPath, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodCopy := func(_ context.Context, _, dst string, _ func(*pb.MoveVolumeProgress) error) error {
		return os.WriteFile(dst, []byte("a whole replica"), 0o600)
	}
	if err := s.replicateLocalWith(context.Background(),
		corrosion.BackupScheduleRecord{VMName: "web-1", TargetPool: "dr", KeepReplicas: 3},
		&corrosion.VMRecord{Name: "web-1"},
		&corrosion.DiskRecord{DiskName: "root", Path: srcPath, StorageType: "dir"},
		"20260101-000000", goodCopy); err != nil {
		t.Fatalf("replicateLocalWith where renameat2 answers EINVAL: %v", err)
	}
	if got := promotableIn(t, dir, "web-1", "root"); len(got) != 1 || got[0] != "root-20260101-000000.qcow2" {
		t.Fatalf("published %v, want [root-20260101-000000.qcow2]", got)
	}
	for _, f := range filesUnder(t, dir) {
		if strings.HasSuffix(f, ".tmp") {
			t.Errorf("a temp was left in the pool: %s", f)
		}
	}
}

// A restore to a new destination places the same way, and still never over
// a file.
func TestRestorePlace_NewDestinationWhereRenameNoReplaceIsUnsupported(t *testing.T) {
	renameNoReplaceAnswers(t, syscall.EINVAL)
	countLinks(t)
	tmp, dst := noClobberFixture(t)
	if err := (restoreDest{path: dst}).place(tmp); err != nil {
		t.Fatalf("restore place where renameat2 answers EINVAL: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new" {
		t.Fatalf("dst holds %q", got)
	}
	tmp, _ = noClobberFixture(t)
	if err := os.WriteFile(tmp, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (restoreDest{path: dst}).place(tmp); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("restore place over a file: %v, want AlreadyExists", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new" {
		t.Fatalf("the existing file now holds %q", got)
	}
}

// A renameat2 refused for permissions or a cross-mount rename (EPERM, EXDEV)
// is not a filesystem without the flag: it is returned as it is, no link is
// tried, and the refusal does not claim the filesystem supports neither.
//
// Mutation: fall back to link on EPERM/EXDEV too (placementUnsupported) —
// link is called, red.
func TestPlaceNoClobber_ARenameRefusedForPermissionsIsNotUnsupported(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EXDEV} {
		t.Run(errno.Error(), func(t *testing.T) {
			renameNoReplaceAnswers(t, errno)
			var links atomic.Int32
			coldLink = func(o, n string) error { links.Add(1); return os.Link(o, n) }
			tmp, dst := noClobberFixture(t)
			err := placeNoClobber(tmp, dst)
			if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "supports neither") || !errors.Is(err, errno) && !strings.Contains(err.Error(), errno.Error()) {
				t.Fatalf("placeNoClobber where renameat2 answers %v = %v, want that error, Internal, not 'supports neither'", errno, err)
			}
			if links.Load() != 0 {
				t.Fatalf("a link was tried after renameat2 answered %v", errno)
			}
			if _, serr := os.Lstat(dst); !os.IsNotExist(serr) {
				t.Fatalf("dst exists after a refused placement (lstat: %v)", serr)
			}
		})
	}
}

// The link-first placements (a cold migration's received disk, an import's
// converted disk) share the lost-reply check: an NFS link answered EEXIST
// over its own link is placed, and one over another file is still refused.
//
// Mutation: placeColdDisk on its own link-then-rename without the shared
// core's same-file check — red.
func TestPlaceColdDisk_ALinkAnsweredEEXISTForItsOwnLinkIsPlaced(t *testing.T) {
	l := coldLink
	t.Cleanup(func() { coldLink = l })
	coldLink = func(o, n string) error {
		if err := os.Link(o, n); err != nil {
			return err
		}
		return &os.LinkError{Op: "link", Old: o, New: n, Err: syscall.EEXIST}
	}
	countLinks(t)
	tmp, dst := noClobberFixture(t)
	if err := placeColdDisk(tmp, dst); err != nil {
		t.Fatalf("placeColdDisk after a retransmitted link: %v", err)
	}
	if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
		t.Fatalf("the scratch name is still there (lstat: %v)", err)
	}
	tmp, dst = noClobberFixture(t)
	if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := placeColdDisk(tmp, dst); !errors.Is(err, os.ErrExist) {
		t.Fatalf("placeColdDisk over another file = %v, want ErrExist", err)
	}
	if unsupported, err := linkOrRenameNoReplace(tmp, dst); unsupported || !errors.Is(err, os.ErrExist) {
		t.Fatalf("linkOrRenameNoReplace over another file = %v, %v; want ErrExist", unsupported, err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "old" {
		t.Fatalf("the existing file now holds %q", got)
	}
}
