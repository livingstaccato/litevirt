package smart

import (
	"context"
	"errors"
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
	for s, want := range map[Status]string{OK: "ok", Prefail: "prefail", Failing: "failing", Unknown: "unknown"} {
		if s.String() != want {
			t.Errorf("%d -> %q", s, s.String())
		}
	}
	if !strings.Contains(Failing.Detail(), "FAILED") {
		t.Error("detail")
	}
}
