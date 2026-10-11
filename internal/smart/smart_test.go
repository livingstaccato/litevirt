package smart

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const scanJSON = `{"devices":[{"name":"/dev/sda","type":"sat"},{"name":"/dev/nvme0","type":"nvme"},{"name":"/dev/vda","type":"scsi"}]}`

const sdaPassed = `{"model_name":"WDC WD40","smart_support":{"available":true,"enabled":true},"smart_status":{"passed":true},
"ata_smart_attributes":{"table":[{"id":5,"name":"Reallocated_Sector_Ct","value":100,"thresh":36,"flags":{"prefailure":true},"when_failed":"","raw":{"value":0}}]}}`

const sdaFailed = `{"model_name":"WDC WD40","smart_support":{"available":true,"enabled":true},"smart_status":{"passed":false}}`

const sdaPast = `{"model_name":"WDC WD40","smart_support":{"available":true,"enabled":true},"smart_status":{"passed":true},
"ata_smart_attributes":{"table":[{"id":5,"name":"Reallocated_Sector_Ct","value":30,"thresh":36,"flags":{"prefailure":true},"when_failed":"in_the_past","raw":{"value":900}}]}}`

const nvmeWarn = `{"model_name":"NVME X","smart_support":{"available":true,"enabled":true},"smart_status":{"passed":true},
"nvme_smart_health_information_log":{"critical_warning":1,"available_spare":3,"available_spare_threshold":10}}`

const noSupport = `{"model_name":"QEMU HARDDISK","smart_support":{"available":false}}`

func fakeRunner(outs map[string]string) Runner {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "--scan" {
			return []byte(scanJSON), nil
		}
		dev := args[len(args)-1]
		o, ok := outs[dev]
		if !ok {
			return nil, errors.New("no such device")
		}
		// smartctl exits non-zero (a bitmask) for a failing disk while still
		// printing valid JSON; the runner reports that as an ExitError.
		return []byte(o), &exec.ExitError{}
	}
}

func byDev(r Report) map[string]Disk {
	m := map[string]Disk{}
	for _, d := range r.Disks {
		m[d.Device] = d
	}
	return m
}

func TestCheck_Classification(t *testing.T) {
	r := Check(context.Background(), fakeRunner(map[string]string{"/dev/sda": sdaFailed, "/dev/nvme0": nvmeWarn, "/dev/vda": noSupport}))
	if !r.Available {
		t.Fatal("smartctl reported unavailable")
	}
	m := byDev(r)
	if m["/dev/sda"].Status != Failing {
		t.Errorf("sda = %v, want failing", m["/dev/sda"].Status)
	}
	if m["/dev/nvme0"].Status != Prefail {
		t.Errorf("nvme0 = %v, want prefail", m["/dev/nvme0"].Status)
	}
	if m["/dev/vda"].Status != Unknown {
		t.Errorf("vda = %v, want unknown (no SMART support)", m["/dev/vda"].Status)
	}
	if m["/dev/sda"].Model != "WDC WD40" {
		t.Errorf("model = %q", m["/dev/sda"].Model)
	}
}

func TestCheck_PassedAndPastFailure(t *testing.T) {
	r := Check(context.Background(), fakeRunner(map[string]string{"/dev/sda": sdaPassed, "/dev/nvme0": sdaPast, "/dev/vda": noSupport}))
	m := byDev(r)
	if m["/dev/sda"].Status != OK {
		t.Errorf("healthy disk = %v", m["/dev/sda"].Status)
	}
	if m["/dev/nvme0"].Status != Prefail {
		t.Errorf("attribute that failed in the past = %v, want prefail", m["/dev/nvme0"].Status)
	}
}

func TestCheck_MissingSmartctlDegrades(t *testing.T) {
	missing := func(ctx context.Context, args ...string) ([]byte, error) { return nil, exec.ErrNotFound }
	r := Check(context.Background(), missing)
	if r.Available || len(r.Disks) != 0 {
		t.Errorf("report = %+v, want unavailable and empty", r)
	}
}

func TestCheck_GarbageOutputIsUnknownNotFailing(t *testing.T) {
	r := Check(context.Background(), fakeRunner(map[string]string{"/dev/sda": "not json", "/dev/nvme0": "", "/dev/vda": "{}"}))
	for _, d := range r.Disks {
		if d.Status != Unknown {
			t.Errorf("%s = %v, want unknown", d.Device, d.Status)
		}
	}
}

func TestCheck_ExecFailureIsUnknown(t *testing.T) {
	r := Check(context.Background(), fakeRunner(map[string]string{})) // every device errors, no output
	if !r.Available {
		t.Error("scan worked, so smartctl is available")
	}
	for _, d := range r.Disks {
		if d.Status != Unknown {
			t.Errorf("%s = %v", d.Device, d.Status)
		}
	}
}

func TestStatusString(t *testing.T) {
	for s, want := range map[Status]string{Warning: "warning", OK: "ok", Prefail: "prefail", Failing: "failing", Unknown: "unknown"} {
		if s.String() != want {
			t.Errorf("%d -> %q", s, s.String())
		}
	}
	if !strings.Contains(Failing.Detail(), "FAILED") {
		t.Error("detail")
	}
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestClassify_RealSmartctlFixtures(t *testing.T) {
	cases := []struct {
		file   string
		want   Status
		idWant string
	}{
		{"ata_healthy_exit64.json", OK, "serial:ZFN0ABCD"}, // non-zero exit bitmask, still healthy
		{"ata_failing.json", Failing, "serial:WD-WCC3F0001"},
		{"nvme_healthy.json", OK, "serial:S5GXNX0T123456A"},
		{"nvme_temperature_warning.json", Warning, "serial:S5GXNX0T999999B"}, // temperature bit alone is not prefail
		{"nvme_spare_low.json", Prefail, "serial:BTHH123"},                   // spare bit (with temp bit) is prefail
		{"ata_standby.json", Unknown, ""},                                    // asleep: no data, must not read as failing
	}
	for _, c := range cases {
		_, id, st := classify([]byte(fixture(t, c.file)))
		if st != c.want {
			t.Errorf("%s = %v, want %v", c.file, st, c.want)
		}
		if id != c.idWant {
			t.Errorf("%s id = %q, want %q", c.file, id, c.idWant)
		}
	}
}

func TestCheck_PassesStandbyFlagAndUsesSerialID(t *testing.T) {
	var sawStandby bool
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "--scan" {
			return []byte(`{"devices":[{"name":"/dev/sda","type":"sat"}]}`), nil
		}
		j := strings.Join(args, " ")
		sawStandby = strings.Contains(j, "-n standby")
		return []byte(fixture(t, "ata_healthy_exit64.json")), &exec.ExitError{}
	}
	r := Check(context.Background(), run)
	if !sawStandby {
		t.Error("smartctl run without -n standby: would wake a spun-down disk")
	}
	if len(r.Disks) != 1 || r.Disks[0].ID != "serial:ZFN0ABCD" || r.Disks[0].Status != OK {
		t.Errorf("disks = %+v", r.Disks)
	}
}

// The real standby shape has no serial/WWN, so Check labels it by device name
// and Unknown: callers must treat that ID as "no identity", not as a new disk.
func TestCheck_StandbyDiskIsUnknownWithDeviceNameID(t *testing.T) {
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "--scan" {
			return []byte(`{"devices":[{"name":"/dev/sdc","type":"sat"}]}`), nil
		}
		return []byte(fixture(t, "ata_standby.json")), &exec.ExitError{}
	}
	r := Check(context.Background(), run)
	if len(r.Disks) != 1 || r.Disks[0].Status != Unknown || r.Disks[0].ID != "/dev/sdc" {
		t.Errorf("standby disk = %+v", r.Disks)
	}
}
