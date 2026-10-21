package health

import (
	"strings"
	"testing"
)

// The fix a restart-same hold prints names `lv host fence-confirm` before
// `lv replication promote`: a same-name promote needs the host proven
// powered off, and a hold does not know it is (ccguard round 4).
//
// Mutation: the confirmation dropped from the text — red.
func TestHeldFix_NamesFenceConfirmBeforeThePromote(t *testing.T) {
	fix := heldFix("web", "node-0")
	c, p := strings.Index(fix, "`lv host fence-confirm node-0`"), strings.Index(fix, "`lv replication promote web`")
	if c < 0 || p < 0 || c > p {
		t.Fatalf("held fix = %q; want `lv host fence-confirm node-0` before `lv replication promote web`", fix)
	}
}
