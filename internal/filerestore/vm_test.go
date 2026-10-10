package filerestore

import (
	"encoding/json"
	"strings"
	"testing"
)

func baseSpec() VMSpec {
	return VMSpec{
		QEMU: "qemu-system-x86_64", Kernel: "/boot/vmlinuz", Initrd: "/var/lib/litevirt/file-restore/cache/i.cpio",
		MemoryMiB: 512, NBDSocket: "/var/lib/litevirt/file-restore/run/s-1/nbd.sock", Export: "backup",
		DiskFormat: "raw", Kind: KindFS, CID: 1234, SerialLog: "/run/s/console.log", Arch: "amd64",
		RunAs: "libvirt-qemu", RunWith: true, Sandbox: true,
	}
}

func argValues(args []string, flag string) []string {
	var out []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			out = append(out, args[i+1])
		}
	}
	return out
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// The restore VM's isolation is its command line: no NIC and no default
// devices, one read-only disk, vsock as the only channel, fixed resources,
// and no reboot.
func TestQemuArgs_Isolation(t *testing.T) {
	args, err := qemuArgs(baseSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"-nodefaults", "-no-user-config", "-nographic", "-no-reboot"} {
		if !hasFlag(args, f) {
			t.Errorf("missing %s", f)
		}
	}
	if v := argValues(args, "-nic"); len(v) != 1 || v[0] != "none" {
		t.Errorf("-nic = %v, want none", v)
	}
	for _, forbidden := range []string{"-netdev", "-net", "-drive", "-hda", "-virtfs", "-fsdev", "-chardev", "-monitor", "-qmp", "-vnc", "-spice"} {
		if hasFlag(args, forbidden) {
			t.Errorf("unexpected %s", forbidden)
		}
	}
	devs := argValues(args, "-device")
	if len(devs) != 2 || !strings.HasPrefix(devs[0], "virtio-blk-pci,drive=disk") || devs[1] != "vhost-vsock-pci,guest-cid=1234" {
		t.Errorf("devices %v: want exactly the disk and one vsock", devs)
	}
	bds := argValues(args, "-blockdev")
	if len(bds) != 2 {
		t.Fatalf("blockdevs %v", bds)
	}
	for _, bd := range bds {
		var m map[string]any
		if err := json.Unmarshal([]byte(bd), &m); err != nil {
			t.Fatalf("blockdev %q: %v", bd, err)
		}
		if m["read-only"] != true {
			t.Errorf("blockdev %v is not read-only", m)
		}
	}
	if v := argValues(args, "-m"); len(v) != 1 || v[0] != "512" {
		t.Errorf("-m %v", v)
	}
	if v := argValues(args, "-smp"); len(v) != 1 || v[0] != "1" {
		t.Errorf("-smp %v", v)
	}
	if v := argValues(args, "-sandbox"); len(v) != 1 || !strings.Contains(v[0], "spawn=deny") || !strings.Contains(v[0], "elevateprivileges=deny") {
		t.Errorf("-sandbox %v", v)
	}
	if v := argValues(args, "-run-with"); len(v) != 1 || v[0] != "user=libvirt-qemu" {
		t.Errorf("-run-with %v", v)
	}
	app := argValues(args, "-append")
	if len(app) != 1 || !strings.Contains(app[0], "litevirt_filerestore=1") || !strings.Contains(app[0], "litevirt_fr_kind=fs") || !strings.Contains(app[0], "panic=-1") {
		t.Errorf("-append %v", app)
	}
}

// A qcow2 disk-file backup is opened with no backing at all: qemu never
// opens a file the image header names.
func TestQemuArgs_Qcow2HasNoBacking(t *testing.T) {
	s := baseSpec()
	s.DiskFormat = "qcow2"
	args, err := qemuArgs(s)
	if err != nil {
		t.Fatal(err)
	}
	var fmtNode map[string]any
	_ = json.Unmarshal([]byte(argValues(args, "-blockdev")[1]), &fmtNode)
	if fmtNode["driver"] != "qcow2" {
		t.Fatalf("format node %v", fmtNode)
	}
	if b, ok := fmtNode["backing"]; !ok || b != nil {
		t.Fatalf("qcow2 node must carry backing: null, got %v", fmtNode)
	}
	s.DiskFormat = "raw"
	args, _ = qemuArgs(s)
	_ = json.Unmarshal([]byte(argValues(args, "-blockdev")[1]), &fmtNode)
	if fmtNode["driver"] != "raw" {
		t.Fatalf("raw node %v", fmtNode)
	}
}

func TestQemuArgs_RejectsBadSpecs(t *testing.T) {
	for name, mut := range map[string]func(*VMSpec){
		"format":   func(s *VMSpec) { s.DiskFormat = "vmdk" },
		"kind":     func(s *VMSpec) { s.Kind = "lvm" },
		"cid":      func(s *VMSpec) { s.CID = 2 },
		"cid-zero": func(s *VMSpec) { s.CID = 0 },
	} {
		s := baseSpec()
		mut(&s)
		if _, err := qemuArgs(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s := baseSpec()
	s.RunWith = false
	args, _ := qemuArgs(s)
	if v := argValues(args, "-runas"); len(v) != 1 || v[0] != "libvirt-qemu" {
		t.Errorf("-runas %v", v)
	}
	s.Arch = "arm64"
	args, _ = qemuArgs(s)
	if m := argValues(args, "-machine"); len(m) != 1 || !strings.HasPrefix(m[0], "virt,") {
		t.Errorf("arm64 machine %v", m)
	}
}

func TestQemuSupportsRunWith(t *testing.T) {
	for banner, want := range map[string]bool{
		"QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1)": false,
		"QEMU emulator version 9.0.0":                              false,
		"QEMU emulator version 9.1.0":                              true,
		"QEMU emulator version 10.0.2 (qemu-10.0.2-1.el10)":        true,
		"garbage": false,
	} {
		if got := qemuSupportsRunWith(banner); got != want {
			t.Errorf("%q: %v, want %v", banner, got, want)
		}
	}
}

func TestTailClean(t *testing.T) {
	r := strings.NewReader("boot\x1b[31m red\x00\nlast line: panic")
	if got := tailClean(r, 20); strings.ContainsAny(got, "\x1b\x00\n") || !strings.HasSuffix(got, "last line: panic") {
		t.Fatalf("tailClean = %q", got)
	}
}
