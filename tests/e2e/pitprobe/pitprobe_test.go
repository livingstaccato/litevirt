package pitprobe

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// shq is tests/e2e's shellQuote.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// A dir pool takes its directory as --target: since 934c3222 a dir pool
// refuses a --source (storage.ValidateSource; lab 2 run c2, defect 1).
// cmd/litevirt's TestPITE2E_DirPoolArgsParse checks the argv against the
// real command and the storage rule.
func TestDirPoolCreateArgs_TargetNotSource(t *testing.T) {
	args := DirPoolCreateArgs("p", "/var/lib/litevirt/pools/p", "node-1")
	i := slices.Index(args, "--target")
	if slices.Contains(args, "--source") || i < 0 || args[i+1] != "/var/lib/litevirt/pools/p" {
		t.Fatalf("dir pool argv %v: want the directory as --target, and no --source", args)
	}
}

// The alias comes from the live XML, parsed: libvirt 10's virsh --xpath
// takes node sets only and refuses string() (defect 2).
func TestDiskAlias_FromTheLiveXML(t *testing.T) {
	const x = `<domain type='kvm'><name>vm</name><devices>
  <disk type='file' device='cdrom'><source file='/var/lib/litevirt/ci/vm.iso'/><target dev='sda' bus='sata'/><alias name='sata0-0-0'/></disk>
  <disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/var/lib/litevirt/pools/p/vm-root.qcow2' index='1'/><backingStore/><target dev='vda' bus='virtio'/><alias name='virtio-disk0'/></disk>
</devices></domain>`
	got, err := DiskAlias(x, "/var/lib/litevirt/pools/p/vm-root.qcow2")
	if err != nil || got != "virtio-disk0" {
		t.Fatalf("DiskAlias = %q, %v; want virtio-disk0", got, err)
	}
	if got, err := DiskAlias(x, "/nowhere.qcow2"); err == nil {
		t.Fatalf("DiskAlias of a file no disk names = %q; want an error", got)
	}
	if cmd := DumpXMLCmd("'vm'"); strings.Contains(cmd, "--xpath") {
		t.Fatalf("the dump %q still uses --xpath", cmd)
	}
}

// HMP qemu-io -d takes a block backend, and a -blockdev disk has no named
// one: the device is the virtio-blk backend under the disk's qdev id
// (defect 3).
func TestQemuIODevice_IsTheVirtioBackend(t *testing.T) {
	if got := QemuIODevice("virtio-disk0"); got != "/machine/peripheral/virtio-disk0/virtio-backend" {
		t.Fatalf("QemuIODevice = %q", got)
	}
}

// fakeVirsh runs script with virsh replaced by a shell function that logs
// each HMP argument and answers reply.
func fakeVirsh(t *testing.T, script, reply string) (log []string, err error) {
	t.Helper()
	logf := filepath.Join(t.TempDir(), "virsh.log")
	pre := `virsh() { for a; do last=$a; done; printf '%s\n' "$last" >> ` + shq(logf) + `; printf '%s\n' ` + shq(reply) + `; }; `
	out, err := exec.Command("sh", "-c", pre+script).CombinedOutput()
	b, _ := os.ReadFile(logf)
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			log = append(log, l)
		}
	}
	if err != nil {
		t.Logf("script output: %s", out)
	}
	return log, err
}

// The writer's round byte reaches qemu-io: $v expands (defect 4: it sat in
// a single-quoted HMP argument, so every write was "write -P $v" and every
// slot read 0).
func TestWriterScript_TheRoundByteExpands(t *testing.T) {
	s := WriterScript(shq("vm"), QemuIODevice("virtio-disk0"), 2, 4096, 8192, 512, "0")
	log, err := fakeVirsh(t, s, "wrote 512/512 bytes at offset 4096")
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	want := []string{
		`qemu-io -d /machine/peripheral/virtio-disk0/virtio-backend "write -P 1 4096 512"`,
		`qemu-io -d /machine/peripheral/virtio-disk0/virtio-backend "write -P 1 8192 512"`,
		`qemu-io -d /machine/peripheral/virtio-disk0/virtio-backend "write -P 2 4096 512"`,
		`qemu-io -d /machine/peripheral/virtio-disk0/virtio-backend "write -P 2 8192 512"`,
	}
	if !slices.Equal(log, want) {
		t.Fatalf("HMP commands:\n%s\nwant:\n%s", strings.Join(log, "\n"), strings.Join(want, "\n"))
	}
}

// HMP returns qemu-io's failures as ordinary output with virsh exiting 0:
// the writer stops on any reply that is not a completed write, and Wrote
// says the same of one command (defect 4's silent half).
func TestWriterScript_StopsOnAFailedWrite(t *testing.T) {
	s := WriterScript(shq("vm"), QemuIODevice("virtio-disk0"), 3, 4096, 8192, 512, "0")
	log, err := fakeVirsh(t, s, "Device does not have a block device backend")
	if err == nil || len(log) != 1 {
		t.Fatalf("writer against a failing qemu-io: err %v after %d commands; want it to stop at the first", err, len(log))
	}
	if Wrote("Device does not have a block device backend") || !Wrote("wrote 65536/65536 bytes at offset 268435456\n64 KiB, 1 ops; 00.00 sec") {
		t.Fatal("Wrote misreads qemu-io's reply")
	}
}

// The token is read alone: getfattr's "Removing leading '/'" notice is not
// folded into it (defect 5).
func TestWindowTokenCmd_PrintsTheTokenAlone(t *testing.T) {
	if _, err := exec.LookPath("getfattr"); err != nil {
		t.Skip("getfattr not installed")
	}
	f := filepath.Join(t.TempDir(), "disk.qcow2")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const tok = "0123456789abcdef0123456789abcdef"
	if out, err := exec.Command("setfattr", "-n", "user.litevirt.pit_window", "-v", tok, f).CombinedOutput(); err != nil {
		t.Skipf("no user xattrs here: %v %s", err, out)
	}
	out, err := exec.Command("sh", "-c", WindowTokenCmd(shq(f))+" 2>&1").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != tok {
		t.Fatalf("token read = %q, %v; want %q alone", out, err, tok)
	}
}
