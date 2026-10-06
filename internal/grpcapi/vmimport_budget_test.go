package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const spaceTestTotal = 100 << 30

// spaceTestServer's filesystem has room bytes free above its headroom, less
// whatever the files under dirs occupy, the way writing into a real
// filesystem uses up its free space.
func spaceTestServer(t *testing.T, room uint64, dirs ...string) *Server {
	t.Helper()
	s := &Server{hostName: "test-host"}
	s.diskSpaceOverride = func(string) (uint64, uint64, error) {
		var used uint64
		for _, d := range dirs {
			_ = filepath.Walk(d, func(p string, fi os.FileInfo, err error) error {
				if err == nil && fi.Mode().IsRegular() {
					n, _ := fileAllocated(p)
					used += n
				}
				return nil
			})
		}
		return coldDiskHeadroom(spaceTestTotal) + room - used, spaceTestTotal, nil
	}
	return s
}

// writeAllocated writes n bytes of data (no holes) to a new file in dir.
func writeAllocated(t *testing.T, dir string, n int) {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xa5
	}
	f, err := os.CreateTemp(dir, "data-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

func refusedForReservation(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("got %v, want a free-space refusal naming the other imports' reservations", err)
	}
}

// A lone import may use the free space down to the headroom a cold migration
// also keeps, and no further.
func TestImportSpace_LeavesTheHeadroomFree(t *testing.T) {
	dir := t.TempDir()
	s := spaceTestServer(t, 64<<20)
	r := s.reserveImportSpace(dir)
	defer r.release()
	if err := r.reserve(dir, 64<<20+1, "x"); err == nil {
		t.Fatal("a reservation reached into the headroom")
	}
	if err := r.reserve(dir, 64<<20, "x"); err != nil {
		t.Fatalf("a reservation of exactly the room above the headroom: %v", err)
	}
}

// Two imports that each fit, but not together: the second is refused while
// the first holds its reservation, and admitted once the first releases it.
func TestImportSpace_AReservationIsNotGrantedTwice(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	s := spaceTestServer(t, 10<<20, a, b)
	ra := s.reserveImportSpace(a)
	if err := ra.reserve(a, 8<<20, "a"); err != nil {
		t.Fatal(err)
	}
	rb := s.reserveImportSpace(b)
	defer rb.release()
	refusedForReservation(t, rb.reserve(b, 4<<20, "b"))
	if err := rb.reserve(b, 2<<20, "b"); err != nil {
		t.Fatalf("a reservation that fits beside the other: %v", err)
	}
	ra.release()
	ra.release() // twice is safe
	if err := rb.reserve(b, 8<<20, "b"); err != nil {
		t.Fatalf("after the other import released its reservation: %v", err)
	}
}

// What an import has written is gone from the free space already, so it no
// longer counts against the others: the reservation shrinks as its files grow.
func TestImportSpace_AReservationShrinksAsItIsWritten(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	writeAllocated(t, a, 1<<20) // a staged source, there before the reservation
	s := spaceTestServer(t, 11<<20, a, b)
	ra := s.reserveImportSpace(a)
	defer ra.release()
	if err := ra.reserve(a, 8<<20, "a"); err != nil {
		t.Fatal(err)
	}
	writeAllocated(t, a, 4<<20)
	ra.refresh()
	// 6 MiB free; a has 4 MiB of its 8 left to write.
	rb := s.reserveImportSpace(b)
	defer rb.release()
	refusedForReservation(t, rb.reserve(b, 3<<20, "b"))
	if err := rb.reserve(b, 3<<19, "b"); err != nil {
		t.Fatalf("beside a reservation half written: %v", err)
	}
}

// A file the conversion writes outside the import directory counts as
// written once tracked.
func TestImportSpace_ATrackedFileCountsAsWritten(t *testing.T) {
	a, pool, b := t.TempDir(), t.TempDir(), t.TempDir()
	s := spaceTestServer(t, 10<<20, a, pool, b)
	ra := s.reserveImportSpace(a)
	defer ra.release()
	ra.begin()
	if err := ra.reserve(pool, 8<<20, "a"); err != nil {
		t.Fatal(err)
	}
	ra.track(filepath.Join(pool, "out.qcow2"))
	writeAllocatedAs(t, filepath.Join(pool, "out.qcow2"), 6<<20)
	ra.refresh()
	// 4 MiB free; a has 2 MiB of its 8 left to write.
	rb := s.reserveImportSpace(b)
	defer rb.release()
	refusedForReservation(t, rb.reserve(b, 3<<20, "b"))
	if err := rb.reserve(b, 1<<20, "b"); err != nil {
		t.Fatalf("beside a conversion 6 MiB into its 8: %v", err)
	}
}

// A new phase drops what the last one reserved and did not write.
func TestImportSpace_BeginDropsTheLastPhasesRest(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	s := spaceTestServer(t, 10<<20, a, b)
	ra := s.reserveImportSpace(a)
	defer ra.release()
	if err := ra.reserve(a, 8<<20, "a"); err != nil {
		t.Fatal(err)
	}
	ra.begin()
	rb := s.reserveImportSpace(b)
	defer rb.release()
	if err := rb.reserve(b, 10<<20, "b"); err != nil {
		t.Fatalf("after the other import's phase ended: %v", err)
	}
}

func writeAllocatedAs(t *testing.T, path string, n int) {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = 0x5a
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}
