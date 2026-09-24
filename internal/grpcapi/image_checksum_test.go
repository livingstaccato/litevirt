package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A declared checksum matches the recorded one written with or without the
// sha256: prefix, in either case. A copy with no recorded checksum cannot be
// shown to match and is refused, naming the holders and "none".
func TestCheckHeldImageChecksum(t *testing.T) {
	s := autopullServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{Name: "summed", Checksum: "sha256:ABCD"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{Name: "unsummed"}); err != nil {
		t.Fatal(err)
	}

	if err := s.checkHeldImageChecksum(ctx, "summed", "abcd", false, []string{"node-1"}); err != nil {
		t.Errorf("matching checksum refused: %v", err)
	}
	err := s.checkHeldImageChecksum(ctx, "summed", "sha256:ffff", true, []string{"node-1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "sha256:ABCD") ||
		!strings.Contains(err.Error(), "sha256:ffff") || !strings.Contains(err.Error(), s.hostName+", node-1") {
		t.Errorf("mismatch: err=%v, want FailedPrecondition naming both checksums and the holders", err)
	}
	err = s.checkHeldImageChecksum(ctx, "unsummed", "sha256:ffff", false, []string{"node-1"})
	if err == nil || !strings.Contains(err.Error(), "records checksum none") {
		t.Errorf("unrecorded checksum: err=%v, want a refusal saying none is recorded", err)
	}
}
