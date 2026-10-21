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
			got, host, err := PCIAddressIdentity(ctx, c, "vm", tc.origin, tc.bdf)
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
