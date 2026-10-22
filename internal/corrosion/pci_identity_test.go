package corrosion

import (
	"context"
	"errors"
	"testing"
)

// The kind of the device a concrete address named is read where the address
// was recorded; failing that, at the host that records the VM as owning a
// device at that address — never from a device at that address the VM does
// not own.
func TestPCIAddressIdentity(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	for _, h := range []string{"a", "b", "c"} {
		if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.1", State: "active", CertSerial: "s-" + h}); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []PCIDeviceRecord{
		{HostName: "a", Address: "0000:41:00.0", VendorID: "10de", DeviceID: "2330", DeviceName: "H100", VMName: "vm"},
		{HostName: "b", Address: "0000:41:00.0", VendorID: "144d", DeviceID: "a808", DeviceName: "NVMe"},
		{HostName: "c", Address: "0000:42:00.0", VendorID: "10de", DeviceID: "26b9"},
		{HostName: "b", Address: "0000:44:00.0", VendorID: "10de", DeviceID: "26b9", VMName: "vm"},
		{HostName: "b", Address: "0000:45:00.0", VendorID: "10de", DeviceID: "26b9"},
	} {
		if err := UpsertPCIDevice(ctx, c, d); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name, origin, bdf string
		want              string // vendor:device, "" for ErrPCIIdentityUnknown
		wantHost          string
	}{
		{"recorded on its host", "a", "0000:41:00.0", "10de:2330", "a"},
		{"short form", "a", "41:00.0", "10de:2330", "a"},
		{"recorded on another host, read there", "b", "0000:41:00.0", "144d:a808", "b"},
		{"no host recorded: the owner's", "", "0000:41:00.0", "10de:2330", "a"},
		{"origin gone from the inventory: the owner's", "c", "0000:41:00.0", "10de:2330", "a"},
		{"nobody owns it", "", "0000:42:00.0", "", ""},
		{"on an owner host, not the VM's", "", "0000:45:00.0", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, host, err := PCIAddressIdentity(ctx, c, "vm", "", tc.origin, tc.bdf)
			if tc.want == "" {
				if !errors.Is(err, ErrPCIIdentityUnknown) {
					t.Fatalf("got %+v on %q, %v; want ErrPCIIdentityUnknown", got, host, err)
				}
				return
			}
			if err != nil || got.VendorID+":"+got.DeviceID != tc.want || host != tc.wantHost {
				t.Fatalf("got %+v on %q, %v; want %s on %s", got, host, err, tc.want, tc.wantHost)
			}
		})
	}
}

// Once the intent is realized on another host, the device that realizes it
// says what kind it needs: not the row it was recorded on, which a rescan
// may have rewritten, or which may be gone.
func TestPCIAddressIdentity_RealizationFirst(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	for _, h := range []string{"a", "b", "c"} {
		if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.1", State: "active", CertSerial: "s-" + h}); err != nil {
			t.Fatal(err)
		}
	}
	put := func(d PCIDeviceRecord) {
		t.Helper()
		if err := UpsertPCIDevice(ctx, c, d); err != nil {
			t.Fatal(err)
		}
	}
	realize := func(dev, host, addr string) {
		t.Helper()
		if err := UpsertPCIRealization(ctx, c, PCIRealizationRecord{VMName: "vm", DeviceID: dev, MemberID: "m0",
			HostName: host, ResolvedAddress: addr, Ordinal: 0}); err != nil {
			t.Fatal(err)
		}
	}
	// Recorded on a at 41; a rescanned since: an L40S there, still "owned".
	put(PCIDeviceRecord{HostName: "a", Address: "0000:41:00.0", VendorID: "10de", DeviceID: "26b9", VMName: "vm"})
	// Realized on b at 81, the VM's H100.
	put(PCIDeviceRecord{HostName: "b", Address: "0000:81:00.0", VendorID: "10de", DeviceID: "2330", VMName: "vm"})
	realize("d1", "b", "0000:81:00.0")
	got, host, err := PCIAddressIdentity(ctx, c, "vm", "d1", "a", "0000:41:00.0")
	if err != nil || got.DeviceID != "2330" || host != "b" || got.Address != "0000:81:00.0" {
		t.Fatalf("realized on b: got %+v on %q, %v; want the H100 at b 0000:81:00.0", got, host, err)
	}

	// Realized on c at 82, which no longer records it as the VM's: the rows
	// the VM left are not trusted, and nothing else says.
	put(PCIDeviceRecord{HostName: "c", Address: "0000:82:00.0", VendorID: "10de", DeviceID: "2330"})
	realize("d2", "c", "0000:82:00.0")
	if got, host, err := PCIAddressIdentity(ctx, c, "vm", "d2", "a", "0000:41:00.0"); !errors.Is(err, ErrPCIIdentityUnknown) {
		t.Fatalf("realized elsewhere, not owned: got %+v on %q, %v; want ErrPCIIdentityUnknown", got, host, err)
	}

	// Never realized elsewhere: the origin's row, if it is not another VM's.
	put(PCIDeviceRecord{HostName: "a", Address: "0000:43:00.0", VendorID: "10de", DeviceID: "2330", VMName: "other"})
	if got, host, err := PCIAddressIdentity(ctx, c, "vm", "d3", "a", "0000:43:00.0"); !errors.Is(err, ErrPCIIdentityUnknown) {
		t.Fatalf("origin row another VM's: got %+v on %q, %v; want ErrPCIIdentityUnknown", got, host, err)
	}
}

// A realized device that is free counts on the host the VM lives on (a stop
// before the latch releases it, and a start does not claim it again), never
// on a host it left, and never when another VM owns it.
func TestPCIAddressIdentity_FreeRealizationOnTheCurrentHost(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	for _, h := range []string{"a", "b"} {
		if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.1", State: "active", CertSerial: "s-" + h}); err != nil {
			t.Fatal(err)
		}
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "vm", HostName: "b", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	put := func(d PCIDeviceRecord) {
		t.Helper()
		if err := UpsertPCIDevice(ctx, c, d); err != nil {
			t.Fatal(err)
		}
	}
	realize := func(dev, host, addr string) {
		t.Helper()
		if err := UpsertPCIRealization(ctx, c, PCIRealizationRecord{VMName: "vm", DeviceID: dev, MemberID: "m0",
			HostName: host, ResolvedAddress: addr, Ordinal: 0}); err != nil {
			t.Fatal(err)
		}
	}
	put(PCIDeviceRecord{HostName: "a", Address: "0000:41:00.0", VendorID: "10de", DeviceID: "26b9", VMName: "vm"})
	put(PCIDeviceRecord{HostName: "b", Address: "0000:81:00.0", VendorID: "10de", DeviceID: "2330"})
	put(PCIDeviceRecord{HostName: "b", Address: "0000:82:00.0", VendorID: "10de", DeviceID: "2330", VMName: "other"})
	put(PCIDeviceRecord{HostName: "a", Address: "0000:42:00.0", VendorID: "10de", DeviceID: "2330"})

	realize("free-here", "b", "0000:81:00.0")
	if got, host, err := PCIAddressIdentity(ctx, c, "vm", "free-here", "a", "0000:41:00.0"); err != nil || got.DeviceID != "2330" || host != "b" {
		t.Errorf("free on the VM's host: got %+v on %q, %v; want the H100 on b", got, host, err)
	}
	realize("other-vm", "b", "0000:82:00.0")
	if got, host, err := PCIAddressIdentity(ctx, c, "vm", "other-vm", "a", "0000:41:00.0"); !errors.Is(err, ErrPCIIdentityUnknown) {
		t.Errorf("another VM's: got %+v on %q, %v; want ErrPCIIdentityUnknown", got, host, err)
	}
	realize("left", "a", "0000:42:00.0")
	if got, host, err := PCIAddressIdentity(ctx, c, "vm", "left", "c", "0000:41:00.0"); !errors.Is(err, ErrPCIIdentityUnknown) {
		t.Errorf("free on a host it left: got %+v on %q, %v; want ErrPCIIdentityUnknown", got, host, err)
	}
}
