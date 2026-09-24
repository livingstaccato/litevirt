package grpcapi

import (
	"os"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// imageAvailable applies the pull's own rule: the local store, or a ready
// copy on a peer the cluster does not know to be dead. A copy still pulling,
// or one on a fenced or offline host, is nowhere autoPullImage would pull
// from, so it does not count.
func TestImageAvailable_AgreesWithThePull(t *testing.T) {
	s := autopullServer(t)
	ctx := adminCtx()
	for _, h := range []struct{ name, state string }{
		{"live-host", "active"}, {"fenced-host", "fenced"}, {"offline-host", "offline"}, {"busy-host", "active"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h.name, Address: "10.0.0.9", State: h.state}); err != nil {
			t.Fatal(err)
		}
	}
	add := func(img, host, status string) {
		t.Helper()
		if err := corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
			ImageName: img, HostName: host, Path: "/images/" + img, Status: status}); err != nil {
			t.Fatal(err)
		}
	}
	add("on-live-peer", "live-host", "ready")
	add("on-dead-peers", "fenced-host", "ready")
	add("on-dead-peers", "offline-host", "ready")
	add("still-pulling", "busy-host", "pulling")
	add("row-for-self-only", s.hostName, "ready")
	if err := os.WriteFile(s.images.ImagePath("local"), []byte("qcow2"), 0o644); err != nil {
		t.Fatal(err)
	}

	for img, want := range map[string]bool{
		"local":             true,
		"on-live-peer":      true,
		"on-dead-peers":     false,
		"still-pulling":     false,
		"row-for-self-only": false, // the row says so, but the file is not here and no peer has it
		"nowhere":           false,
	} {
		got, err := s.imageAvailable(ctx, img)
		if err != nil {
			t.Fatalf("imageAvailable(%q): %v", img, err)
		}
		if got != want {
			t.Errorf("imageAvailable(%q) = %v, want %v", img, got, want)
		}
	}
}
