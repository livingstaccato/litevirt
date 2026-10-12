package pitprobe

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

// The same property where getfattr or user xattrs are missing (a CI runner
// without attr): the command asks getfattr not to print its notice, and does
// not fold stderr into the token.
//
// Mutations "no --absolute-names" and "2>&1 back" — red.
func TestWindowTokenCmd_Shape(t *testing.T) {
	c := WindowTokenCmd("'/d'")
	if !strings.Contains(c, "--absolute-names") || strings.Contains(c, "2>&1") {
		t.Fatalf("WindowTokenCmd = %q: want --absolute-names and stderr kept apart", c)
	}
}

// runHMPQemuIO runs HMPQemuIO's command (a 512-byte write at offset 0) with
// virsh replaced by a function that, after delay seconds, appends logAppend
// to the domain log (where qemu 8.2 / libvirt 10 put qemu-io's output; first
// truncating it when trunc) and prints reply (the HMP reply). The log starts
// with logBefore, an earlier command's output.
func runHMPQemuIO(t *testing.T, reply, logBefore, logAppend string, trunc bool, delay string) string {
	t.Helper()
	dir := t.TempDir()
	old := DomainLogDir
	DomainLogDir = dir
	t.Cleanup(func() { DomainLogDir = old })
	lf := filepath.Join(dir, "vm.log")
	if err := os.WriteFile(lf, []byte(logBefore), 0o600); err != nil {
		t.Fatal(err)
	}
	pre := `virsh() { sleep ` + delay + `; if [ -n "$TRUNC" ]; then : > ` + shq(lf) + `; fi; printf '%s' "$APPEND" >> ` + shq(lf) + `; printf '%s' "$REPLY"; }; `
	cmd := exec.Command("sh", "-c", pre+HMPQemuIO(shq("vm"), QemuIODevice("virtio-disk0"), "write -P 1 0 512"))
	env := append(os.Environ(), "APPEND="+logAppend, "REPLY="+reply)
	if trunc {
		env = append(env, "TRUNC=1")
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("HMPQemuIO command: %v\n%s", err, out)
	}
	return string(out)
}

const (
	mine   = "wrote 512/512 bytes at offset 0\n"
	others = "wrote 512/512 bytes at offset 4096\n"
)

// qemu 8.2 / libvirt 10: the HMP reply is empty and qemu-io's output goes to
// the domain log. The result is this command's line, not an earlier
// command's "wrote" (lab 2 run 1012).
func TestHMPQemuIO_ReadsTheDomainLogWhenTheReplyIsEmpty(t *testing.T) {
	if out := runHMPQemuIO(t, "", others, mine, false, "0"); !Wrote(out) || strings.Count(out, "wrote ") != 1 || !strings.Contains(out, "offset 0") {
		t.Fatalf("success: output %q; want only this command's line", out)
	}
	if out := runHMPQemuIO(t, "", mine, "write failed: Input/output error\n", false, "0"); Wrote(out) {
		t.Fatalf("failure: output %q reads as a completed write (an earlier command's log line leaked in)", out)
	}
}

// Another command's output lands in the log while this one runs: this
// command's failure must not read as a success on its neighbour's line, and
// its success is picked out from among the neighbour's.
func TestHMPQemuIO_IgnoresAConcurrentCommandsOutput(t *testing.T) {
	if out := runHMPQemuIO(t, "", "", others+"write failed: Input/output error\n", false, "0"); Wrote(out) {
		t.Fatalf("output %q: this write failed and another's line made it read as written", out)
	}
	out := runHMPQemuIO(t, "", "", others+mine+others, false, "0")
	if !Wrote(out) || strings.Count(out, "wrote ") != 1 || !strings.Contains(out, "offset 0") {
		t.Fatalf("output %q: want this command's line alone", out)
	}
}

// The log is rotated or truncated while the command runs: its line, written
// to the new file, is still found.
func TestHMPQemuIO_SurvivesALogTruncation(t *testing.T) {
	long := strings.Repeat("qemu: some earlier line\n", 50)
	if out := runHMPQemuIO(t, "", long, mine, true, "0"); !Wrote(out) {
		t.Fatalf("output %q: the line written after the log was truncated was lost", out)
	}
}

// qemu-io's line can arrive well after virsh returns.
func TestHMPQemuIO_WaitsForALateLine(t *testing.T) {
	if out := runHMPQemuIO(t, "", "", mine, false, "0"); !Wrote(out) {
		t.Fatalf("baseline: %q", out)
	}
	dir := t.TempDir()
	old := DomainLogDir
	DomainLogDir = dir
	t.Cleanup(func() { DomainLogDir = old })
	lf := filepath.Join(dir, "vm.log")
	if err := os.WriteFile(lf, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = os.WriteFile(lf, []byte(mine), 0o600)
	}()
	pre := `virsh() { :; }; `
	out, err := exec.Command("sh", "-c", pre+HMPQemuIO(shq("vm"), QemuIODevice("virtio-disk0"), "write -P 1 0 512")).CombinedOutput()
	if err != nil || !Wrote(string(out)) {
		t.Fatalf("output %q, %v: a line 1.5 s late (past the old 0.5 s window) was missed", out, err)
	}
}

// A reply that is not empty is the result, as on a qemu that answers over
// HMP; a stale log line does not turn a failed reply into a write.
func TestHMPQemuIO_PrefersANonEmptyReply(t *testing.T) {
	out := runHMPQemuIO(t, "Device does not have a block device backend", mine, mine, false, "0")
	if Wrote(out) || !strings.Contains(out, "Device does not have") {
		t.Fatalf("output %q: want the HMP reply alone", out)
	}
	if out := runHMPQemuIO(t, "wrote 512/512 bytes at offset 0", "", "", false, "0"); !Wrote(out) {
		t.Fatalf("output %q: a replied write must read as written", out)
	}
}
