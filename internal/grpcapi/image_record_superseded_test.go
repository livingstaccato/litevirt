package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review 2, I-1: a newer live record of the image that lands while an
// operation runs — a second copy onto the same host, begun later and finished
// first — is not a delete. The operation succeeds and records this host's
// row; a copy leaves the catalog row to the newer record, and an operator's
// operation records its own content again at fresh clocks.
func TestRecordImage_ANewerLiveRecordSupersedesInsteadOfAborting(t *testing.T) {
	ctx := context.Background()
	for _, op := range []imageOp{imageOpImport, imageOpCopy, imageOpPull, imageOpBuild, imageOpCompose} {
		t.Run(string(op), func(t *testing.T) {
			s := testServer(t)
			earlier, err := s.imageOpStart(ctx, "imgr", op)
			if err != nil {
				t.Fatal(err)
			}
			later, err := s.imageOpStart(ctx, "imgr", imageOpCopy)
			if err != nil {
				t.Fatal(err)
			}
			laterHost := testImageHost(s)
			laterHost.Path = "/x/later.qcow2"
			if err := s.recordImage(ctx, imageOpCopy, later, corrosion.ImageRecord{Name: "imgr", Format: "qcow2", Checksum: "sha256:later"}, laterHost); err != nil {
				t.Fatalf("the later copy: %v", err)
			}
			earlierHost := testImageHost(s)
			earlierHost.Path = "/x/earlier.qcow2"
			earlierSum := "sha256:earlier"
			if op == imageOpCopy {
				earlierSum = "sha256:later" // a copy of the same content (other content: TestRecordImage_ACopyOvertakenByOtherContentIsNotReady)
			}
			if err := s.recordImage(ctx, op, earlier, corrosion.ImageRecord{Name: "imgr", Format: "qcow2", Checksum: earlierSum}, earlierHost); err != nil {
				t.Fatalf("the %s begun first and recording last: %v, want it recorded", op, err)
			}
			want := "sha256:later" // a copy leaves the catalog row to the newer record
			if op != imageOpCopy {
				want = "sha256:earlier" // an operator's content is recorded again, newest
			}
			if img, _ := corrosion.GetImage(ctx, s.db, "imgr"); img == nil || img.Checksum != want {
				t.Fatalf("catalog after the %s: %+v, want checksum %s", op, img, want)
			}
			rows, err := s.db.Query(ctx, `SELECT path FROM image_hosts WHERE image_name = 'imgr' AND host_name = ? AND deleted_at IS NULL`, s.hostName)
			if err != nil || len(rows) != 1 || rows[0].String("path") != earlierHost.Path {
				t.Fatalf("this host's row after the %s: %v (err %v), want its own record (%s)", op, rows, err, earlierHost.Path)
			}
		})
	}
}
