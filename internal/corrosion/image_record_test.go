package corrosion

import (
	"context"
	"testing"
)

// RecordImage writes at clocks reserved as the operation began, only while
// the row reads as it did then (review re-review 1, R-m1): a delete applied
// since wins and nothing is written. A newer live record of the image is not a
// delete: the record is superseded, not refused (re-review 2, I-1).
func TestRecordImage_WritesOnlyOverTheRowItBeganWith(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	img := ImageRecord{Name: "imgr", Format: "qcow2", Checksum: "sha256:ab"}

	// An absent row, live as the operation began: written.
	clk := ReserveImageClocks(c)
	if got, err := RecordImage(ctx, c, img, true, "", clk); err != nil || got != ImageRecordWritten {
		t.Fatalf("a record over an absent row: %v err=%v", got, err)
	}

	// Deleted since the operation began: nothing written.
	clk = ReserveImageClocks(c)
	if err := DeleteImage(ctx, c, "imgr"); err != nil {
		t.Fatal(err)
	}
	if got, err := RecordImage(ctx, c, img, true, "", clk); err != nil || got != ImageRecordDeleted {
		t.Fatalf("a record over a row deleted since it began: %v err=%v, want %v", got, err, ImageRecordDeleted)
	}
	deleted, _ := ImageDeletedAt(ctx, c, "imgr")
	if deleted == "" {
		t.Fatal("the delete was undone")
	}

	// Deleted as it began, and still: an operator's revive is written.
	clk = ReserveImageClocks(c)
	if got, err := RecordImage(ctx, c, img, true, deleted, clk); err != nil || got != ImageRecordWritten {
		t.Fatalf("a revive of a name deleted as it began: %v err=%v", got, err)
	}
	if d, _ := ImageDeletedAt(ctx, c, "imgr"); d != "" {
		t.Fatalf("the revive left the row deleted (%s)", d)
	}

	// A newer live record since the clocks were reserved: superseded, and the
	// older one is not written over it.
	old := ReserveImageClocks(c)
	if got, err := RecordImage(ctx, c, ImageRecord{Name: "imgr", Checksum: "sha256:new"}, true, "", ReserveImageClocks(c)); err != nil || got != ImageRecordWritten {
		t.Fatalf("the newer record: %v err=%v", got, err)
	}
	for _, revive := range []bool{false, true} {
		if got, err := RecordImage(ctx, c, ImageRecord{Name: "imgr", Checksum: "sha256:old"}, revive, "", old); err != nil || got != ImageRecordSuperseded {
			t.Fatalf("a record (revive=%v) at clocks older than a live row: %v err=%v, want %v", revive, got, err, ImageRecordSuperseded)
		}
	}
	if got, _ := GetImage(ctx, c, "imgr"); got == nil || got.Checksum != "sha256:new" {
		t.Fatalf("the row after an older record: %+v, want the newer one kept", got)
	}

	// Deleted since the start, with clocks older than the delete: a delete,
	// not a supersede.
	old = ReserveImageClocks(c)
	if err := DeleteImage(ctx, c, "imgr"); err != nil {
		t.Fatal(err)
	}
	if got, err := RecordImage(ctx, c, img, true, "", old); err != nil || got != ImageRecordDeleted {
		t.Fatalf("a record over a row deleted since it began: %v err=%v, want %v", got, err, ImageRecordDeleted)
	}
}

// RecordImageHost writes this host's row at the clock reserved as the
// operation began while nothing newer is written to the row here, so a delete
// stamped after the start is newer than the row (re-review 2, m-1); over a
// newer row (a pull's progress) it writes at a fresh clock, so the row never
// regresses here.
func TestRecordImageHost_AtTheReservedClockUnlessTheRowIsNewer(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	updatedAt := func() string {
		rows, err := c.Query(ctx, `SELECT updated_at FROM image_hosts WHERE image_name = 'imgh' AND host_name = 'h1'`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("image_hosts row: %v %v", rows, err)
		}
		return rows[0].String("updated_at")
	}
	ih := ImageHostRecord{ImageName: "imgh", HostName: "h1", Path: "/x", Status: "ready", PulledAt: "2026-10-13T00:00:00Z"}
	for _, revive := range []bool{false, true} {
		clk := ReserveImageClocks(c)
		if err := RecordImageHost(ctx, c, ih, revive, clk.Host); err != nil {
			t.Fatal(err)
		}
		if got := updatedAt(); got != clk.Host {
			t.Fatalf("revive=%v: row at %s, want the reserved %s", revive, got, clk.Host)
		}
		// A write to the row since (a pull's progress), then the record.
		clk = ReserveImageClocks(c)
		if err := UpdateImageHostProgress(ctx, c, "imgh", "h1", 50); err != nil {
			t.Fatal(err)
		}
		progress := updatedAt()
		if err := RecordImageHost(ctx, c, ih, revive, clk.Host); err != nil {
			t.Fatal(err)
		}
		if got := updatedAt(); lwwOrder(got, progress) <= 0 {
			t.Fatalf("revive=%v: row at %s over a newer %s, want a fresh clock", revive, got, progress)
		}
	}
}

// GetImageHosts names no host of a deleted image (review re-review 1, R-m5):
// a host row live under a deleted catalog row is no source.
func TestGetImageHosts_NamesNoHostOfADeletedImage(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := InsertImage(ctx, c, ImageRecord{Name: "imgx", Format: "qcow2"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteImage(ctx, c, "imgx"); err != nil {
		t.Fatal(err)
	}
	// A copy recorded on a host the delete had not reached yet.
	if err := ReviveImageHost(ctx, c, ImageHostRecord{ImageName: "imgx", HostName: "node-2", Path: "/x", Status: "ready", PulledAt: "2026-10-13T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if hosts, err := GetImageHosts(ctx, c, "imgx"); err != nil || len(hosts) != 0 {
		t.Fatalf("GetImageHosts of a deleted image = %v (err %v), want none", hosts, err)
	}
	if err := ReviveImage(ctx, c, ImageRecord{Name: "imgx", Format: "qcow2"}); err != nil {
		t.Fatal(err)
	}
	if hosts, err := GetImageHosts(ctx, c, "imgx"); err != nil || len(hosts) != 1 {
		t.Fatalf("GetImageHosts of the image live again = %v (err %v), want node-2", hosts, err)
	}
}
