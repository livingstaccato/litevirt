package grpcapi

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// m11-1: the refusal of keeping the copy names only exits that its next gate
// takes: with the domain running, `lv stop` first; with the source unreadable,
// only --force. Neither offers --accept of the source.
func TestResolveHealthCondition_KeepingTheCopyRefusalNamesWorkingExits(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		running    bool
		unreadable bool
		want       string
	}{
		{name: "the domain running on the copy", running: true, want: "lv stop vm1"},
		{name: "the source unreadable", unreadable: true, want: "--force"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			define := ""
			if tc.running {
				define = "dst"
			}
			s, src, dst := forkedMoveServer(t, "node-a", 3, 4, define, tc.running) // the source is the later file
			if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dst, "nfs", "warm"); err != nil {
				t.Fatal(err)
			}
			if tc.unreadable {
				if err := os.Remove(src); err != nil {
					t.Fatal(err)
				}
			}
			_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("x"))
			mustRefuse(t, s, err, dst, tc.want)
			if strings.Contains(err.Error(), "`--accept "+src+"`") {
				t.Fatalf("the refusal offers --accept of the source, which the next gate refuses: %v", err)
			}
		})
	}
}
