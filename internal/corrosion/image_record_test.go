package corrosion

import (
	"context"
	"testing"
)

// RecordImage writes at clocks reserved as the operation began, only while
// the row reads as it did then (review re-review 1, R-m1): a delete applied
// since, or a newer record, wins and nothing is written.
func TestRecordImage_WritesOnlyOverTheRowItBeganWith(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	img := ImageRecord{Name: "imgr", Format: "qcow2", Checksum: "sha256:ab"}

	// An absent row, live as the operation began: written.
	clk := ReserveImageClocks(c)
	if ok, err := RecordImage(ctx, c, img, true, "", clk); err != nil || !ok {
		t.Fatalf("a record over an absent row: applied=%v err=%v", ok, err)
	}

	// Deleted since the operation began: nothing written.
	clk = ReserveImageClocks(c)
	if err := DeleteImage(ctx, c, "imgr"); err != nil {
		t.Fatal(err)
	}
	if ok, err := RecordImage(ctx, c, img, true, "", clk); err != nil || ok {
		t.Fatalf("a record over a row deleted since it began: applied=%v err=%v, want not applied", ok, err)
	}
	deleted, _ := ImageDeletedAt(ctx, c, "imgr")
	if deleted == "" {
		t.Fatal("the delete was undone")
	}

	// Deleted as it began, and still: an operator's revive is written.
	clk = ReserveImageClocks(c)
	if ok, err := RecordImage(ctx, c, img, true, deleted, clk); err != nil || !ok {
		t.Fatalf("a revive of a name deleted as it began: applied=%v err=%v", ok, err)
	}
	if d, _ := ImageDeletedAt(ctx, c, "imgr"); d != "" {
		t.Fatalf("the revive left the row deleted (%s)", d)
	}

	// A newer record since the clocks were reserved: the older one is not
	// written over it.
	old := ReserveImageClocks(c)
	if ok, err := RecordImage(ctx, c, ImageRecord{Name: "imgr", Checksum: "sha256:new"}, true, "", ReserveImageClocks(c)); err != nil || !ok {
		t.Fatalf("the newer record: applied=%v err=%v", ok, err)
	}
	if ok, err := RecordImage(ctx, c, ImageRecord{Name: "imgr", Checksum: "sha256:old"}, true, "", old); err != nil || ok {
		t.Fatalf("a record at clocks older than the row: applied=%v err=%v, want not applied", ok, err)
	}
	if got, _ := GetImage(ctx, c, "imgr"); got == nil || got.Checksum != "sha256:new" {
		t.Fatalf("the row after an older record: %+v, want the newer one kept", got)
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
