package grpcapi

import (
	"slices"
	"testing"
)

// TestResumeAskSet_UnknownVotersNeverCount (re-review 2, N4): with five voters
// on a derived set, two of which this node reads as unknown, a minority host
// must not count their answers: they stay in the majority to reach (3 of 5,
// so 2 clean answers besides itself) and are not asked.
func TestResumeAskSet_UnknownVotersNeverCount(t *testing.T) {
	voters := map[string]bool{"self": true, "a": true, "b": true, "u1": true, "u2": true}
	uncounted := map[string]bool{"u1": true, "u2": true}
	names, need := resumeAskSet("self", voters, uncounted)
	if need != 2 {
		t.Errorf("need = %d, want 2: the unknown voters must stay in the majority to reach", need)
	}
	if slices.Contains(names, "u1") || slices.Contains(names, "u2") {
		t.Errorf("asked %v: an unknown voter's answer would count toward the resume", names)
	}
	if !slices.Equal(names, []string{"a", "b"}) {
		t.Errorf("asked %v, want [a b]", names)
	}
}
