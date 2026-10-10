package libvirt

import (
	"strings"
	"testing"
)

func tuneCfg(d DiskConfig, n NetworkConfig) VMConfig {
	d.Name, d.Path, d.Bus = "root", "/var/lib/litevirt/disks/a-root.qcow2", "virtio"
	n.Bridge, n.MAC = "br0", "52:54:00:aa:bb:cc"
	return VMConfig{Name: "a", CPU: 2, MemoryMiB: 512, Disks: []DiskConfig{d}, Networks: []NetworkConfig{n}}
}

func TestGenerateDomainXML_DiskDiscardDetectZeroesAndIOTune(t *testing.T) {
	x, err := GenerateDomainXML(tuneCfg(DiskConfig{
		Discard: "unmap", DetectZeroes: "unmap",
		IOTune: IOTune{ReadBytesSec: 50 << 20, WriteIopsSec: 500, WriteIopsSecMax: 2000, BurstSec: 10},
	}, NetworkConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`discard="unmap"`, `detect_zeroes="unmap"`,
		`<read_bytes_sec>52428800</read_bytes_sec>`,
		`<write_iops_sec>500</write_iops_sec>`,
		`<write_iops_sec_max>2000</write_iops_sec_max>`,
		`<write_iops_sec_max_length>10</write_iops_sec_max_length>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("domain XML lacks %s:\n%s", want, x)
		}
	}
	// No limit was named for the others: none are emitted, and no length for a
	// burst that was not set.
	for _, not := range []string{"total_bytes_sec", "read_iops_sec", "read_bytes_sec_max_length"} {
		if strings.Contains(x, not) {
			t.Errorf("domain XML carries %s though it was not set", not)
		}
	}
	got, ok := DiskIOTuneFromXML(x, "vda")
	if !ok || got != (IOTune{ReadBytesSec: 50 << 20, WriteIopsSec: 500, WriteIopsSecMax: 2000, BurstSec: 10}) {
		t.Errorf("DiskIOTuneFromXML = %+v ok=%v", got, ok)
	}
}

// A disk with none of the new settings renders exactly what it did: nothing.
func TestGenerateDomainXML_UntunedDiskAndNICAreUnchanged(t *testing.T) {
	x, err := GenerateDomainXML(tuneCfg(DiskConfig{}, NetworkConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, not := range []string{"discard", "detect_zeroes", "iotune", "queues", "vhost"} {
		if strings.Contains(x, not) {
			t.Errorf("an untuned VM renders %q:\n%s", not, x)
		}
	}
}

// A CD-ROM is read-only media: it gets neither discard nor a throttle.
func TestGenerateDomainXML_CDROMTakesNoDiskTuning(t *testing.T) {
	cfg := tuneCfg(DiskConfig{}, NetworkConfig{})
	cfg.Disks = append(cfg.Disks, DiskConfig{Name: "installer", Path: "/x.iso", IsISO: true,
		Discard: "unmap", DetectZeroes: "on", IOTune: IOTune{TotalIopsSec: 10}})
	x, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(x, "iotune") || strings.Contains(x, "discard") {
		t.Errorf("CD-ROM carries disk tuning:\n%s", x)
	}
}

func TestGenerateDomainXML_NICQueues(t *testing.T) {
	x, err := GenerateDomainXML(tuneCfg(DiskConfig{}, NetworkConfig{Queues: 4}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(x, `<driver name="vhost" queues="4"`) {
		t.Errorf("virtio NIC with queues=4 lacks the vhost driver:\n%s", x)
	}
	// One queue is the default, and a non-virtio model has no multiqueue.
	for _, n := range []NetworkConfig{{Queues: 1}, {Queues: 0}, {Queues: 4, Model: "e1000"}} {
		x, err := GenerateDomainXML(tuneCfg(DiskConfig{}, n))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(x, "queues") {
			t.Errorf("NIC %+v renders queues:\n%s", n, x)
		}
	}
}

func TestIOTuneValidate(t *testing.T) {
	cases := []struct {
		name string
		t    IOTune
		bad  string // substring of the error; "" = valid
	}{
		{"empty", IOTune{}, ""},
		{"read+write", IOTune{ReadBytesSec: 1, WriteBytesSec: 2, ReadIopsSec: 3}, ""},
		{"total", IOTune{TotalBytesSec: 100, TotalIopsSec: 10}, ""},
		{"burst", IOTune{TotalIopsSec: 100, TotalIopsSecMax: 400, BurstSec: 5}, ""},
		{"total with read bytes", IOTune{TotalBytesSec: 100, ReadBytesSec: 1}, "total_bytes_sec cannot be combined"},
		{"total with write iops", IOTune{TotalIopsSec: 100, WriteIopsSec: 1}, "total_iops_sec cannot be combined"},
		{"negative", IOTune{ReadIopsSec: -1}, "negative"},
		{"max without sustained", IOTune{ReadIopsSecMax: 10}, "needs read_iops_sec"},
		{"max below sustained", IOTune{ReadIopsSec: 100, ReadIopsSecMax: 50}, "below"},
		{"burst length without a ceiling", IOTune{ReadIopsSec: 100, BurstSec: 3}, "burst_seconds needs"},
		{"too large", IOTune{ReadBytesSec: maxIOTuneValue + 1}, "more than"},
	}
	for _, tc := range cases {
		err := tc.t.Validate()
		switch {
		case tc.bad == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.bad != "" && (err == nil || !strings.Contains(err.Error(), tc.bad)):
			t.Errorf("%s: error = %v, want one containing %q", tc.name, err, tc.bad)
		}
	}
}

func TestDiscardValidation(t *testing.T) {
	for _, ok := range []string{"", "unmap", "ignore"} {
		if err := ValidateDiscard(ok); err != nil {
			t.Errorf("discard %q: %v", ok, err)
		}
	}
	if ValidateDiscard("yes") == nil {
		t.Error("discard yes accepted")
	}
	if ValidateDetectZeroes("unmap", "") == nil || ValidateDetectZeroes("unmap", "ignore") == nil {
		t.Error("detect_zeroes unmap accepted without discard unmap")
	}
	if err := ValidateDetectZeroes("unmap", "unmap"); err != nil {
		t.Errorf("detect_zeroes unmap with discard unmap: %v", err)
	}
	if ValidateDetectZeroes("maybe", "") == nil {
		t.Error("detect_zeroes maybe accepted")
	}
}

func TestPatchDiskIOTune(t *testing.T) {
	x, err := GenerateDomainXML(tuneCfg(DiskConfig{IOTune: IOTune{ReadIopsSec: 10}}, NetworkConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := PatchDiskIOTune(x, "vda", IOTune{WriteBytesSec: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := DiskIOTuneFromXML(out, "vda")
	if got != (IOTune{WriteBytesSec: 1 << 20}) {
		t.Errorf("after replacing the throttle: %+v (the old read_iops_sec must be gone)", got)
	}
	cleared, err := PatchDiskIOTune(out, "vda", IOTune{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cleared, "iotune") {
		t.Errorf("clearing left an <iotune>:\n%s", cleared)
	}
	if _, err := PatchDiskIOTune(x, "vdz", IOTune{ReadIopsSec: 1}); err == nil {
		t.Error("patching a disk the domain does not have succeeded")
	}
}

// Setting a field to 0 is how libvirt clears a limit: the live call must send
// every field, or a limit removed from the spec stays in force on the disk.
func TestIOTuneTypedParamsSendEveryField(t *testing.T) {
	ps := IOTune{ReadIopsSec: 5}.typedParams()
	if len(ps) != 18 {
		t.Fatalf("typedParams sends %d fields, want all 18", len(ps))
	}
	seen := map[string]bool{}
	for _, p := range ps {
		seen[p.Field] = true
	}
	for _, f := range []string{"total_bytes_sec", "write_iops_sec_max_length", "read_iops_sec"} {
		if !seen[f] {
			t.Errorf("field %s not sent", f)
		}
	}
}
