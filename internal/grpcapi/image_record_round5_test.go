package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review 3, m-2: a copy superseded by a record of other content (a refresh
// pull elsewhere, begun after the copy, whose record reached this host first)
// holds older content than the catalog row. It is not recorded as ready here:
// it fails, retryably, and says so (isStaleImageCopy), so ImportImage takes it
// back from the image's current file. A copy of the same content still
// records (TestRecordImage_ANewerLiveRecordSupersedesInsteadOfAborting).
func TestRecordImage_ACopyOvertakenByOtherContentIsNotReady(t *testing.T) {
	ctx := context.Background()
	for _, sums := range []struct{ catalog, copy string }{
		{"sha256:new", "sha256:old"},
		{"", "sha256:old"}, // a pull's first record: its content is not known yet
	} {
		t.Run("catalog "+sums.catalog, func(t *testing.T) {
			s := testServer(t)
			copyT, err := s.imageOpStart(ctx, "imgr", imageOpCopy)
			if err != nil {
				t.Fatal(err)
			}
			res, err := corrosion.RecordImage(ctx, s.db, corrosion.ImageRecord{Name: "imgr", Format: "qcow2", Checksum: sums.catalog}, true, "", corrosion.ReserveImageClocks(s.db))
			if err != nil || res.Outcome != corrosion.ImageRecordWritten {
				t.Fatalf("the refresh's record: %+v err=%v", res, err)
			}
			err = s.recordImage(ctx, imageOpCopy, copyT, corrosion.ImageRecord{Name: "imgr", Format: "qcow2", Checksum: sums.copy}, testImageHost(s))
			if status.Code(err) != codes.Aborted || !isStaleImageCopy(err) {
				t.Fatalf("a copy of %s overtaken by a record of %q: %v, want a retryable stale-copy Aborted", sums.copy, sums.catalog, err)
			}
			rows, qerr := s.db.Query(ctx, `SELECT status FROM image_hosts WHERE image_name = 'imgr' AND host_name = ?`, s.hostName)
			if qerr != nil || len(rows) != 0 {
				t.Fatalf("this host's row after a stale copy: %v (err %v), want none", rows, qerr)
			}
			if img, _ := corrosion.GetImage(ctx, s.db, "imgr"); img == nil || img.Checksum != sums.catalog {
				t.Fatalf("catalog after a stale copy: %+v, want the refresh's %q kept", img, sums.catalog)
			}
		})
	}
}

// A copy's checksum and the catalog's compare as content: the sha256: prefix
// and case do not make two equal digests differ.
func TestSameImageContent(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"sha256:ab", "sha256:ab", true},
		{"sha256:ab", "AB", true},
		{"sha256:ab", "sha256:cd", false},
		{"", "sha256:ab", false},
		{"", "", false},
	} {
		if got := sameImageContent(c.a, c.b); got != c.want {
			t.Errorf("sameImageContent(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// Re-review 3, m-1: an operator's record superseded by a catalog row stamped
// ahead of this host's clock — a peer's whose clock runs ahead, arrived by
// anti-entropy, which adopts no peer's clock — takes the row's stamp, as the
// replicator would have, and records over it. One stamped further ahead than
// the clock accepts (hlc.MaxSkewMS) fails at once, naming the skew and the
// row's stamp, instead of re-recording into it and blaming a race. The
// peer's clock is the stub: the row is written at stamps ahead of this host's.
func TestRecordImage_ARowStampedAheadOfThisHostsClock(t *testing.T) {
	ctx := context.Background()
	at := func(d time.Duration, n int) string {
		return time.Now().Add(d).UTC().Add(time.Duration(n) * time.Microsecond).Format("2006-01-02T15:04:05.000000000Z07:00")
	}
	for _, op := range []imageOp{imageOpImport, imageOpPull} {
		t.Run(string(op)+" 3m ahead", func(t *testing.T) {
			s := testServer(t)
			tk, err := s.imageOpStart(ctx, "imgr", op)
			if err != nil {
				t.Fatal(err)
			}
			ahead := corrosion.ImageClocks{Insert: at(3*time.Minute, 0), Revive: at(3*time.Minute, 1), Host: at(3*time.Minute, 2)}
			if res, err := corrosion.RecordImage(ctx, s.db, corrosion.ImageRecord{Name: "imgr", Format: "qcow2", Checksum: "sha256:peer"}, false, "", ahead); err != nil || res.Outcome != corrosion.ImageRecordWritten {
				t.Fatalf("the peer's row: %+v err=%v", res, err)
			}
			if err := s.recordImage(ctx, op, tk, corrosion.ImageRecord{Name: "imgr", Format: "qcow2", Checksum: "sha256:mine"}, testImageHost(s)); err != nil {
				t.Fatalf("the %s over a row stamped 3m ahead: %v, want it recorded", op, err)
			}
			if img, _ := corrosion.GetImage(ctx, s.db, "imgr"); img == nil || img.Checksum != "sha256:mine" {
				t.Fatalf("catalog after the %s: %+v, want its own content", op, img)
			}
		})
		t.Run(string(op)+" 10m ahead", func(t *testing.T) {
			s := testServer(t)
			tk, err := s.imageOpStart(ctx, "imgr", op)
			if err != nil {
				t.Fatal(err)
			}
			ahead := corrosion.ImageClocks{Insert: at(10*time.Minute, 0), Revive: at(10*time.Minute, 1), Host: at(10*time.Minute, 2)}
			if res, err := corrosion.RecordImage(ctx, s.db, corrosion.ImageRecord{Name: "imgr", Format: "qcow2", Checksum: "sha256:peer"}, false, "", ahead); err != nil || res.Outcome != corrosion.ImageRecordWritten {
				t.Fatalf("the peer's row: %+v err=%v", res, err)
			}
			err = s.recordImage(ctx, op, tk, corrosion.ImageRecord{Name: "imgr", Format: "qcow2", Checksum: "sha256:mine"}, testImageHost(s))
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), ahead.Insert) || !strings.Contains(err.Error(), "clock") {
				t.Fatalf("the %s over a row stamped 10m ahead: %v, want FailedPrecondition naming the clock skew and the stamp %s", op, err, ahead.Insert)
			}
			if img, _ := corrosion.GetImage(ctx, s.db, "imgr"); img == nil || img.Checksum != "sha256:peer" {
				t.Fatalf("catalog after the refused %s: %+v, want the peer's row kept", op, img)
			}
		})
	}
}
