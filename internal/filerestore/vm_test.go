package filerestore

import (
	"encoding/json"
	"strings"
	"testing"
)

func baseSpec() VMSpec {
	return VMSpec{
		QEMU: "qemu-system-x86_64", Kernel: "/var/lib/litevirt/file-restore/cache/kernel-x", Initrd: "/var/lib/litevirt/file-restore/cache/i.cpio",
		MemoryMiB: 512, NBDSocket: "/run/litevirt/file-restore/s-1/nbd.sock", Export: "backup",
		DiskFormat: "raw", Kind: KindFS, CID: 1234, VhostFD: 3, Arch: "amd64",
		Nonce: "abc123", AgentIdleSec: 360, Sandbox: true,
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

// The restore VM's isolation is its command line.
func TestQemuArgs_Isolation(t *testing.T) {
	args, err := qemuArgs(baseSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"-nodefaults", "-no-user-config", "-no-reboot"} {
		if !hasFlag(args, f) {
			t.Errorf("missing %s", f)
		}
	}
	if v := argValues(args, "-display"); len(v) != 1 || v[0] != "none" {
		t.Errorf("-display %v", v)
	}
	if v := argValues(args, "-nic"); len(v) != 1 || v[0] != "none" {
		t.Errorf("-nic = %v, want none", v)
	}
	for _, forbidden := range []string{"-netdev", "-net", "-drive", "-hda", "-virtfs", "-fsdev", "-chardev", "-monitor", "-qmp", "-vnc", "-spice", "-runas", "-run-with", "-pidfile", "-D"} {
		if hasFlag(args, forbidden) {
			t.Errorf("unexpected %s", forbidden)
		}
	}
	devs := argValues(args, "-device")
	if len(devs) != 2 || !strings.HasPrefix(devs[0], "virtio-blk-pci,drive=disk") || devs[1] != "vhost-vsock-pci,guest-cid=1234,vhostfd=3" {
		t.Errorf("devices %v: want exactly the disk and one vsock on the inherited fd", devs)
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
	app := argValues(args, "-append")
	for _, want := range []string{"litevirt_filerestore=1", "litevirt_fr_kind=fs", "panic=-1", "litevirt_fr_nonce=abc123", "litevirt_fr_idle=360"} {
		if len(app) != 1 || !strings.Contains(app[0], want) {
			t.Errorf("-append %v lacks %s", app, want)
		}
	}
}

// I-3: the console goes to qemu's stdout (an in-memory buffer), never a
// file on the host.
func TestQemuArgs_ConsoleIsNotAFile(t *testing.T) {
	args, _ := qemuArgs(baseSpec())
	if v := argValues(args, "-serial"); len(v) != 1 || v[0] != "stdio" {
		t.Fatalf("-serial %v, want stdio", v)
	}
	for _, a := range args {
		if strings.HasPrefix(a, "file:") || strings.Contains(a, "logfile") {
			t.Fatalf("a file-backed character device: %q", a)
		}
	}
}

func TestQemuArgs_Qcow2HasNoBacking(t *testing.T) {
	s := baseSpec()
	s.DiskFormat = "qcow2"
	args, err := qemuArgs(s)
	if err != nil {
		t.Fatal(err)
	}
	var fmtNode map[string]any
	_ = json.Unmarshal([]byte(argValues(args, "-blockdev")[1]), &fmtNode)
	if b, ok := fmtNode["backing"]; fmtNode["driver"] != "qcow2" || !ok || b != nil {
		t.Fatalf("qcow2 node must carry backing: null, got %v", fmtNode)
	}
}

func TestQemuArgs_RejectsBadSpecs(t *testing.T) {
	for name, mut := range map[string]func(*VMSpec){
		"format":   func(s *VMSpec) { s.DiskFormat = "vmdk" },
		"kind":     func(s *VMSpec) { s.Kind = "lvm" },
		"cid":      func(s *VMSpec) { s.CID = 2 },
		"vhostfd":  func(s *VMSpec) { s.VhostFD = 0 },
		"nonce":    func(s *VMSpec) { s.Nonce = "" },
		"nonce-ws": func(s *VMSpec) { s.Nonce = "a b" },
	} {
		s := baseSpec()
		mut(&s)
		if _, err := qemuArgs(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s := baseSpec()
	s.Sandbox = false
	if args, _ := qemuArgs(s); hasFlag(args, "-sandbox") {
		t.Error("-sandbox with Sandbox false")
	}
	s.Arch = "arm64"
	args, _ := qemuArgs(s)
	if m := argValues(args, "-machine"); len(m) != 1 || !strings.HasPrefix(m[0], "virt,") {
		t.Errorf("arm64 machine %v", m)
	}
}

// I-3: the console buffer keeps only its last bytes, however much the guest
// writes.
func TestConsoleRing_Bounded(t *testing.T) {
	r := newConsoleRing(1024)
	chunk := []byte(strings.Repeat("A", 700) + "\n")
	for i := 0; i < 10000; i++ {
		_, _ = r.Write(chunk)
	}
	_, _ = r.Write([]byte("panic: the end\x1b[0m‮"))
	if len(r.buf) > 1024 {
		t.Fatalf("console buffer holds %d bytes, cap 1024", len(r.buf))
	}
	tail := r.Tail(200)
	if !strings.Contains(tail, "panic: the end") || strings.ContainsAny(tail, "\x1b‮\n") {
		t.Fatalf("tail %q", tail)
	}
	if r.seen != int64(10000*len(chunk)+len("panic: the end\x1b[0m‮")) {
		t.Fatalf("seen %d", r.seen)
	}
}

func TestStderrClassifiers(t *testing.T) {
	if !stderrSaysNoSeccomp("qemu-system-x86_64: -sandbox on: seccomp support is disabled") {
		t.Error("no-seccomp message not recognized")
	}
	if stderrSaysNoSeccomp("qemu-system-x86_64: could not load kernel") {
		t.Error("an unrelated error read as no seccomp")
	}
	if !stderrSaysCIDInUse("vhost-vsock: unable to set guest cid: Address already in use") {
		t.Error("cid collision not recognized")
	}
}
