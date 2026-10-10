package libvirt

import (
	"errors"
	"strings"
	"testing"
)

// TestGuardedStart_FailedResumeStopsTheDomain (re-review m5): a domain
// started paused for its guard that then fails to resume is destroyed, as a
// guard refusal is: the start returns an error, and a paused domain left
// behind would disagree with the row it reports.
func TestGuardedStart_FailedResumeStopsTheDomain(t *testing.T) {
	destroyed := false
	err := guardedStart(StartGuard{Before: func(string) (bool, error) { return true, nil }}, "web",
		func(bool) error { return nil },
		func() error { return errors.New("resume failed") },
		func() { destroyed = true })
	if err == nil || !strings.Contains(err.Error(), "resume failed") {
		t.Fatalf("guardedStart = %v, want the resume failure", err)
	}
	if !destroyed {
		t.Error("a domain that could not be resumed was left paused")
	}
}
