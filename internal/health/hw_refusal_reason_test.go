package health

import (
	"errors"
	"fmt"
	"testing"
)

// A pre-start refusal because a disk's NFS export is not mounted is counted
// under its own reason; every other one stays a hardware refusal.
func TestHWRefusalReason(t *testing.T) {
	storage := fmt.Errorf("start: %w", ErrStartStorageNotMounted)
	if got := hwRefusalReason(storage); got != ReasonStorageNotMounted {
		t.Fatalf("storage refusal counted as %q, want %q", got, ReasonStorageNotMounted)
	}
	if got := hwRefusalReason(errors.New("hardware adoption is blocked")); got != ReasonHardwareBlocked {
		t.Fatalf("hardware refusal counted as %q, want %q", got, ReasonHardwareBlocked)
	}
}
