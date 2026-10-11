package placement

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func usbHosts(t *testing.T) *corrosion.Client {
	t.Helper()
	db := testDB(t)
	for _, n := range []string{"a", "b", "c"} {
		insertHost(t, db, corrosion.HostRecord{Name: n, Address: "10.0.0." + n, State: "active", CPUTotal: 32, MemTotal: 65536})
	}
	ctx := context.Background()
	if err := corrosion.CreateResourceMapping(ctx, db, "dongle", ""); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.AddMappingDevice(ctx, db, "dongle", "b", "usb:046d:c52b", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.CreateResourceMapping(ctx, db, "serial", ""); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"b", "c"} {
		if err := corrosion.AddMappingDevice(ctx, db, "serial", h, "usb:1-2", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// A VM whose USB device comes through a mapping lands only on a host the
// mapping has a device on — every mapping, when it names several.
func TestSelect_USBMappingRestrictsHosts(t *testing.T) {
	db := usbHosts(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		host, err := Select(ctx, db, Request{VMName: "u", CPUNeeded: 1, MemMiBNeeded: 512, USBMappings: []string{"dongle", "serial"}})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if host != "b" {
			t.Fatalf("placed on %q; only b has both dongle and serial", host)
		}
	}
	if _, err := Select(ctx, db, Request{VMName: "u", USBMappings: []string{"nosuch"}}); err == nil {
		t.Fatal("a mapping with no devices placed the VM somewhere")
	}
}

// A raw USB device is plugged into one host: the VM goes there or nowhere.
func TestSelect_RawUSBBindsToItsHost(t *testing.T) {
	db := usbHosts(t)
	ctx := context.Background()
	host, err := Select(ctx, db, Request{VMName: "u", USBHost: "c"})
	if err != nil || host != "c" {
		t.Fatalf("Select = %q, %v; want c", host, err)
	}
	if err := ValidatePinned(ctx, db, Request{VMName: "u", USBHost: "c"}, "a"); err == nil ||
		!strings.Contains(err.Error(), "usb device") {
		t.Fatalf("ValidatePinned on another host = %v; want a usb device refusal", err)
	}
}

// RankFromSnapshot never loads mappings: a USB VM must not be ranked onto a
// host merely because the snapshot knows nothing about its devices.
func TestRankFromSnapshot_USBMappingFailsClosed(t *testing.T) {
	db := usbHosts(t)
	snap, err := BuildSnapshot(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	cands, err := RankFromSnapshot(snap, &Request{VMName: "u", USBMappings: []string{"serial"}})
	if err == nil && len(cands) > 0 {
		t.Fatalf("ranked %d candidates for a USB-mapped VM from a snapshot without mapping data", len(cands))
	}
}
