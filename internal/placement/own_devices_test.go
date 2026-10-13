package placement

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ownPool is node-1 with two GPUs: 0000:41:00.0 free, 0000:42:00.0 held by db.
func ownPool() map[string][]corrosion.PCIDeviceRecord {
	return map[string][]corrosion.PCIDeviceRecord{"node-1": {
		{HostName: "node-1", Address: "0000:41:00.0", Type: "gpu", IOMMUGroup: -1},
		{HostName: "node-1", Address: "0000:42:00.0", Type: "gpu", IOMMUGroup: -1, VMName: "db"},
	}}
}

// An update may use the device its VM holds; nobody else may.
func TestSelectBatch_ReuseDevicesOfFreesOnlyThatVMsDevices(t *testing.T) {
	hosts := labHosts()[:1]
	own := Request{VMName: "db", PinHost: "node-1", Devices: []DeviceRequest{{Address: "0000:42:00.0", Count: 1}}}

	res, err := SelectBatch(hosts, nil, ownPool(), nil, nil, time.Time{}, []Request{own})
	if err != nil || res["db"].Host != "" {
		t.Fatalf("without ReuseDevicesOf: %+v %v, want db's own device counted as taken", res["db"], err)
	}
	own.ReuseDevicesOf = "db"
	res, err = SelectBatch(hosts, nil, ownPool(), nil, nil, time.Time{}, []Request{own})
	if err != nil || res["db"].Host != "node-1" {
		t.Fatalf("with ReuseDevicesOf db: %+v %v, want node-1", res["db"], err)
	}
	other := own
	other.VMName, other.ReuseDevicesOf = "web", "web"
	res, err = SelectBatch(hosts, nil, ownPool(), nil, nil, time.Time{}, []Request{other})
	if err != nil || res["web"].Host != "" {
		t.Fatalf("web reusing its own devices got db's: %+v %v", res["web"], err)
	}
}

// The in-batch reservation marker can be no VM's name: an update of a VM
// named "reserved" must not free a device an earlier request of the batch
// reserved.
func TestSelectBatch_TheReservationMarkerIsNoVMName(t *testing.T) {
	pool := map[string][]corrosion.PCIDeviceRecord{"node-1": {
		{HostName: "node-1", Address: "0000:41:00.0", Type: "gpu", IOMMUGroup: -1},
	}}
	dev := []DeviceRequest{{Address: "0000:41:00.0", Count: 1}}
	res, err := SelectBatch(labHosts()[:1], nil, pool, nil, nil, time.Time{}, []Request{
		{VMName: "first", Devices: dev},
		{VMName: "reserved", ReuseDevicesOf: "reserved", Devices: dev},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if res["first"].Host != "node-1" || res["reserved"].Host != "" {
		t.Fatalf("first = %+v, reserved = %+v; want only first placed on 0000:41:00.0", res["first"], res["reserved"])
	}
}

// Select and ValidatePinned, from the database, free the VM's own assigned
// GPU to a request with ReuseDevicesOf, refuse it without, and never free
// another VM's.
func TestSelectAndValidatePinned_ReuseDevicesOf(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{Name: "gpu-node", Address: "10.0.0.1", State: "active", CPUTotal: 32, MemTotal: 65536})
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "gpu-node", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1, VMName: "db",
	})
	req := func(name, reuse string) Request {
		return Request{VMName: name, ReuseDevicesOf: reuse, Devices: []DeviceRequest{{Address: "0000:41:00.0", Count: 1}}}
	}
	for _, c := range []struct {
		name, reuse string
		ok          bool
	}{
		{"db", "db", true},
		{"db", "", false},
		{"web", "web", false},
	} {
		host, err := Select(ctx, db, req(c.name, c.reuse))
		if c.ok != (err == nil && host == "gpu-node") {
			t.Errorf("Select %s reusing %q: host %q err %v, want ok=%v", c.name, c.reuse, host, err, c.ok)
		}
		err = ValidatePinned(ctx, db, req(c.name, c.reuse), "gpu-node")
		if c.ok != (err == nil) {
			t.Errorf("ValidatePinned %s reusing %q: err %v, want ok=%v", c.name, c.reuse, err, c.ok)
		}
	}
}

// db's update takes the free GPU, not its own; its own is still db's for the
// rest of the batch, so web cannot be planned onto it.
func TestSelectBatch_AnUnusedOwnDeviceIsReclaimed(t *testing.T) {
	res, err := SelectBatch(labHosts()[:1], nil, ownPool(), nil, nil, time.Time{}, []Request{
		{VMName: "db", ReuseDevicesOf: "db", Devices: []DeviceRequest{{Type: "gpu", Count: 1}}},
		{VMName: "web", Devices: []DeviceRequest{{Address: "0000:42:00.0", Count: 1}}},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if got := res["db"]; got.Host != "node-1" || len(got.Devices) != 1 || got.Devices[0].Address != "0000:41:00.0" {
		t.Fatalf("db = %+v, want node-1 with 0000:41:00.0", got)
	}
	if got := res["web"]; got.Host != "" {
		t.Fatalf("web = %+v, want no host: 0000:42:00.0 is still db's", got)
	}
}
