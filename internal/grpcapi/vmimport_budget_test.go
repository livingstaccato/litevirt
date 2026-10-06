package grpcapi

import "testing"

// Extraction may use the import directory's free space down to the headroom a
// cold migration also keeps, and no further.
func TestImportExtractBudget_LeavesTheHeadroomFree(t *testing.T) {
	s := &Server{}
	s.diskSpaceOverride = func(string) (uint64, uint64, error) { return 10 << 30, 100 << 30, nil }
	if got, want := s.importExtractBudget(t.TempDir()), uint64(10<<30)-coldDiskHeadroom(100<<30); got != want {
		t.Fatalf("budget = %d, want %d", got, want)
	}
	s.diskSpaceOverride = func(string) (uint64, uint64, error) { return 1 << 30, 100 << 30, nil }
	if got := s.importExtractBudget(t.TempDir()); got != 0 {
		t.Fatalf("budget with less free than the headroom = %d, want 0", got)
	}
}
