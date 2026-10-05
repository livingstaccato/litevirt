package grpcapi

// Review round 2 of the stopped-VM cold migration: the free-space checks
// reserve what a copy really writes (allocated, not apparent, bytes) and a
// bounded headroom; the scratch sweep matches only the names the copy
// generates; and placement survives a failed scratch removal and a filesystem
// without hard links.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/qcow2"
)

func allocatedOnDisk(t *testing.T, p string) int64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	return st.Blocks * 512
}

// The headroom is bounded: on a large filesystem 5% is far more than any
// guest's slack, and refusing a 10 GB disk with 800 GB free helps no one.
//
// Mutation: drop the 64 GiB cap — the large-filesystem case is refused and
// goes red.
func TestColdDiskHeadroom_IsBounded(t *testing.T) {
	for _, tc := range []struct{ total, want uint64 }{
		{10 << 30, 1 << 30},   // 5% is 512 MiB: the 1 GiB floor
		{400 << 30, 20 << 30}, // 5%
		{100 << 40, 64 << 30}, // 5% is 5 TiB: the 64 GiB cap
	} {
		if got := coldDiskHeadroom(tc.total); got != tc.want {
			t.Errorf("coldDiskHeadroom(%d GiB) = %d GiB, want %d GiB", tc.total>>30, got>>30, tc.want>>30)
		}
	}
	s := testServer(t)
	s.diskSpaceOverride = func(string) (uint64, uint64, error) { return 800 << 30, 100 << 40, nil }
	if err := s.requireDiskSpace("/d", "/d", "copying a 10 GiB disk", 10<<30); err != nil {
		t.Fatalf("a 10 GiB copy onto a 100 TiB filesystem with 800 GiB free was refused: %v", err)
	}
}

// writeOverlay makes a qcow2 overlay of virtual bytes over a qcow2 base at
// the source's copy of the fixture's disk, with extra bytes of data appended
// to the overlay file (allocated, as an overlay that has been written to is).
func writeOverlay(t *testing.T, f *coldDiskFixture, virtual uint64, extra int) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "base.qcow2")
	if err := qcow2.Create(base, virtual, nil); err != nil {
		t.Fatal(err)
	}
	sp := f.src.hostDiskFile(f.path)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(sp, base, virtual, nil); err != nil {
		t.Fatal(err)
	}
	if extra > 0 {
		junk := make([]byte, extra)
		if _, err := rand.Read(junk); err != nil {
			t.Fatal(err)
		}
		fh, err := os.OpenFile(sp, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fh.Write(junk); err != nil {
			t.Fatal(err)
		}
		fh.Close()
	}
}

// A thin overlay of a large virtual disk is flattened on a source whose free
// space is far below the virtual size: the flatten writes only allocated
// clusters.
//
// Mutation: reserve the virtual size again — the flatten is refused and goes red.
func TestStreamColdDisk_ThinOverlayFlattensOnANearlyFullSource(t *testing.T) {
	f := newColdDiskFixture(t)
	writeOverlay(t, f, 50<<30, 0)
	f.src.diskSpaceOverride = func(string) (uint64, uint64, error) { return 20 << 30, 100 << 30, nil }
	if err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "qcow2"); err != nil {
		t.Fatalf("flatten of a thin 50 GiB overlay with 20 GiB free: %v", err)
	}
	info, err := qcow2.Info(f.path)
	if err != nil || info.BackingFile != "" || info.VirtualSize != 50<<30 {
		t.Fatalf("target image = %+v, %v; want a standalone 50 GiB image", info, err)
	}
}

// An overlay whose allocated data does not fit with headroom left is still
// refused.
//
// Mutation: estimate the flatten as zero bytes — it proceeds and goes red.
func TestStreamColdDisk_AllocatedOverlayIsStillRefused(t *testing.T) {
	f := newColdDiskFixture(t)
	writeOverlay(t, f, 1<<30, 100<<20)
	f.src.diskSpaceOverride = func(string) (uint64, uint64, error) { return 1<<30 + 80<<20, 10 << 30, nil }
	err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "qcow2")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "free") {
		t.Fatalf("flatten of 100 MiB of data with 80 MiB above the headroom = %v, want FailedPrecondition", err)
	}
	if len(f.client.up.frames) != 0 {
		t.Error("frames were sent after the refusal")
	}
}

// A sparse raw disk is received on a target whose free space is below its
// apparent size, and stays sparse there: the copy reserves and writes only
// its data.
//
// Mutation: reserve the apparent size again — refused, red. Write whole frames
// instead of their non-zero pages — the target file is not sparse, red.
func TestReceiveMigrationDisk_SparseRawFitsOnANearlyFullTarget(t *testing.T) {
	f := newColdDiskFixture(t)
	sp := f.src.hostDiskFile(f.path)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Create(sp)
	if err != nil {
		t.Fatal(err)
	}
	// One page of data at the start of a 1 MiB chunk, and one at the end of
	// the file: whole frames would allocate two MiB, pages two pages.
	page := make([]byte, 4096)
	for i := range page {
		page[i] = 0xab
	}
	const size = 8 << 30
	if _, err := fh.WriteAt(page, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteAt(page, size-4096); err != nil {
		t.Fatal(err)
	}
	fh.Close()
	f.dst.diskSpaceOverride = func(string) (uint64, uint64, error) { return 10 << 30, 100 << 30, nil }
	if err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "raw"); err != nil {
		t.Fatalf("copy of a sparse 8 GiB raw disk with 10 GiB free: %v", err)
	}
	st, err := os.Stat(f.path)
	if err != nil || st.Size() != size {
		t.Fatalf("target file = %v, %v; want %d bytes", st, err, int64(size))
	}
	if a := allocatedOnDisk(t, f.path); a > 1<<20 {
		t.Errorf("target file allocates %d bytes for two pages of data", a)
	}
}

// A copy whose allocated estimate does not fit with headroom left is refused
// before anything is written.
func TestReceiveMigrationDisk_TooBigAllocationIsRefused(t *testing.T) {
	f := newColdDiskFixture(t)
	f.dst.diskSpaceOverride = func(string) (uint64, uint64, error) { return 10 << 30, 100 << 30, nil }
	srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
		{VmName: "os1", Path: f.path, SizeBytes: 9 << 30, AllocatedBytes: 9 << 30},
		{Sha256: strings.Repeat("0", 64)},
	}}
	err := f.dst.ReceiveMigrationDisk(srv)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "free") {
		t.Fatalf("9 GiB of data onto 10 GiB free = %v, want FailedPrecondition", err)
	}
	if left := scratchLeft(t, filepath.Dir(f.path)); len(left) > 0 {
		t.Fatalf("scratch files left: %v", left)
	}
}

// The estimate is the source's; the target re-checks its own free space as the
// data arrives, so an estimate that was low, or space taken meanwhile, stops
// the copy before the filesystem fills.
//
// Mutation: drop the re-check — the copy completes and goes red.
func TestReceiveMigrationDisk_RechecksFreeSpaceDuringTheCopy(t *testing.T) {
	f := newColdDiskFixture(t)
	defer func(v int64) { coldDiskRecheckEvery = v }(coldDiskRecheckEvery)
	coldDiskRecheckEvery = 1
	calls := 0
	f.dst.diskSpaceOverride = func(string) (uint64, uint64, error) {
		calls++
		if calls == 1 {
			return 50 << 30, 100 << 30, nil
		}
		return 2 << 30, 100 << 30, nil // headroom 5 GiB: now below it
	}
	data := []byte("abcd")
	h := newFrameDigest()
	coldDiskFrameDigest(h, 0, data)
	srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
		{VmName: "os1", Path: f.path, SizeBytes: 4, AllocatedBytes: 4},
		{Offset: 0, Data: data},
		{Sha256: digestHex(h)},
	}}
	err := f.dst.ReceiveMigrationDisk(srv)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "free") {
		t.Fatalf("copy while the filesystem fills = %v, want FailedPrecondition", err)
	}
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Fatalf("the copy was placed (stat: %v)", err)
	}
	if left := scratchLeft(t, filepath.Dir(f.path)); len(left) > 0 {
		t.Fatalf("scratch files left: %v", left)
	}
}

// The sweep removes only the names the copy generates. A file an operator put
// in a disk directory that merely resembles one is kept.
//
// Mutation: match by substring again — the lookalikes are removed, red.
func TestSweepColdMigrationScratch_LeavesLookalikes(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	dir := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := []string{
		".foo.receiving-x",
		".foo.receiving-12x",
		".foo.coldmig-notauuid",
		".foo.coldmig-0b6c1f8e-1f0a-4c55-9d2b-0a3a4c5d6e7f.bak",
		".receiving-123",
	}
	gone := []string{
		".foo.receiving-1234567890",
		".foo.coldmig-0b6c1f8e-1f0a-4c55-9d2b-0a3a4c5d6e7f",
		".foo.coldmig-0b6c1f8e-1f0a-4c55-9d2b-0a3a4c5d6e7f.tmp",
	}
	for _, n := range append(append([]string{}, keep...), gone...) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.SweepColdMigrationScratch()
	for _, n := range keep {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s was removed by the sweep: %v", n, err)
		}
	}
	for _, n := range gone {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Errorf("scratch %s survived the sweep", n)
		}
	}
}

func placeFixture(t *testing.T) (tmp, dst string) {
	t.Helper()
	dir := t.TempDir()
	tmp, dst = filepath.Join(dir, ".d.receiving-1"), filepath.Join(dir, "d")
	if err := os.WriteFile(tmp, []byte("copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	return tmp, dst
}

func restorePlaceCalls(t *testing.T) {
	l, r, n := coldLink, coldRemove, coldRenameNoReplace
	t.Cleanup(func() { coldLink, coldRemove, coldRenameNoReplace = l, r, n })
}

// Once the link has given the copy its name, the copy is placed: a scratch
// name that cannot be removed is a leftover for the sweep, not a failed copy
// that a retry would then be refused over.
//
// Mutation: return the remove's error — red.
func TestPlaceColdDisk_ScratchRemoveFailureStillPlaces(t *testing.T) {
	restorePlaceCalls(t)
	tmp, dst := placeFixture(t)
	coldRemove = func(string) error { return errors.New("injected remove failure") }
	if err := placeColdDisk(tmp, dst); err != nil {
		t.Fatalf("placeColdDisk with a failed scratch remove = %v, want placed", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "copy" {
		t.Fatalf("dst holds %q", got)
	}
}

// On a filesystem without hard links the copy is placed by a rename that
// still never replaces a file; one that can do neither is refused clearly.
//
// Mutation: fall back to os.Rename — the existing file is replaced, red.
// Drop the fallback — the placement fails, red.
func TestPlaceColdDisk_NoHardLinks(t *testing.T) {
	restorePlaceCalls(t)
	coldLink = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} }

	tmp, dst := placeFixture(t)
	if err := placeColdDisk(tmp, dst); err != nil {
		t.Fatalf("placeColdDisk without hard links: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "copy" {
		t.Fatalf("dst holds %q", got)
	}

	tmp, dst = placeFixture(t)
	if err := os.WriteFile(dst, []byte("there first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := placeColdDisk(tmp, dst); !errors.Is(err, os.ErrExist) {
		t.Fatalf("fallback placement onto an existing file = %v, want ErrExist", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "there first" {
		t.Fatalf("existing file now holds %q", got)
	}

	coldRenameNoReplace = func(string, string) error { return syscall.EINVAL }
	tmp, dst = placeFixture(t)
	err := placeColdDisk(tmp, dst)
	if err == nil || errors.Is(err, os.ErrExist) || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("placement with neither = %v, want a refusal naming hard links", err)
	}
	if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
		t.Fatalf("dst exists after a refused placement (stat: %v)", serr)
	}
}

// A frame whose zero pages lie between non-zero ones is written back exactly:
// the receive skips each zero page and resumes at the next page's own offset.
//
// Mutation: resume one byte past the skipped page (i = end + 1) — the bytes
// shift and this goes red.
func TestReceiveMigrationDisk_ZeroPageBetweenDataPages(t *testing.T) {
	f := newColdDiskFixture(t)
	const page = 4096
	data := make([]byte, 5*page+100)
	fill := func(from, to int, b byte) {
		for i := from; i < to; i++ {
			data[i] = b + byte(i%7)
		}
	}
	fill(0, page, 1)           // data
	fill(2*page, 3*page, 2)    // data after one zero page
	fill(4*page+3, 5*page, 3)  // a page that is non-zero only after its start, after another zero page
	fill(5*page, len(data), 4) // a short tail
	h := newFrameDigest()
	coldDiskFrameDigest(h, 0, data)
	srv := &diskRecvStream{ctx: f.peer, frames: []*pb.ReceiveMigrationDiskRequest{
		{VmName: "os1", Path: f.path, SizeBytes: int64(len(data)), AllocatedBytes: int64(len(data))},
		{Offset: 0, Data: data},
		{Sha256: digestHex(h)},
	}}
	if err := f.dst.ReceiveMigrationDisk(srv); err != nil {
		t.Fatalf("ReceiveMigrationDisk: %v", err)
	}
	got, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		for i := range data {
			if i >= len(got) || got[i] != data[i] {
				t.Fatalf("placed file differs from the frame at byte %d (len %d, want %d)", i, len(got), len(data))
			}
		}
		t.Fatalf("placed file is %d bytes, want %d", len(got), len(data))
	}
}

func newFrameDigest() hash.Hash    { return sha256.New() }
func digestHex(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }
