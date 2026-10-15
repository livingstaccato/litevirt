package libvirt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The running-code check (spec §3.5, T-13) reads a fake /proc root. Every
// fixture starts from one fully valid host — a running SB+TPM domain whose
// QEMU, swtpm, libtpms and OVMF CODE are the installed files — and each test
// breaks exactly one thing. The positive tests prove the baseline passes, so
// every refusal below is the refusal of the one thing the test broke; each
// negative test also asserts the reason, so a refusal for some other reason
// does not pass it.

const (
	fxUUID      = "5113ced7-9006-4086-b7dd-9d1840181e03"
	fxOtherUUID = "6224dfe8-9006-4086-b7dd-9d1840181e03"
	// Longer than libvirt's 20-character short name, so a pid-file path built
	// from the full name misses.
	fxName     = "fw-live-migration-test-vm"
	fxID       = 7
	fxQEMUPid  = 4242
	fxSwtpmPid = 4243
)

type fwFixture struct {
	t        *testing.T
	root     string
	probe    *FirmwareCodeProbe
	dom      runningDomain
	qemuBin  string
	swtpmBin string
	libReal  string
	loader   string
	nvram    string
}

func fxWrite(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func fxLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// fxLibRange is the address range of the libtpms mapping in the fixture's
// maps, zero-padded as maps prints it; fxLibMapFile is its map_files name,
// which the kernel prints without the padding.
const (
	fxLibRange   = "00400000-00452000"
	fxLibMapFile = "400000-452000"
)

// fxMapsLine is a /proc/<pid>/maps line at fxLibRange naming path with the
// (dev, inode) of the file at statPath.
func fxMapsLine(t *testing.T, path, statPath string) string {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(statPath, &st); err != nil {
		t.Fatal(err)
	}
	dev := uint64(st.Dev) //nolint:unconvert // Dev is int32 on some unixes
	return fmt.Sprintf("%s r-xp 00001000 %02x:%02x %d                     %s\n",
		fxLibRange, unix.Major(dev), unix.Minor(dev), st.Ino, path)
}

func newFWFixture(t *testing.T) *fwFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fx := &fwFixture{t: t, root: root}

	// Installed code. The fake binaries print what the lab's print.
	fx.qemuBin = filepath.Join(root, "usr/bin/qemu-system-x86_64")
	fxWrite(t, fx.qemuBin, "#!/bin/sh\necho 'QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)'\necho 'Copyright (c) 2003-2023 Fabrice Bellard and the QEMU Project developers'\n", 0o755)
	fx.swtpmBin = filepath.Join(root, "usr/bin/swtpm")
	fxWrite(t, fx.swtpmBin, "#!/bin/sh\necho 'TPM emulator version 0.7.3, Copyright (c) 2014-2022 IBM Corp. and others'\n", 0o755)
	libDir := filepath.Join(root, "usr/lib/x86_64-linux-gnu")
	fx.libReal = filepath.Join(libDir, "libtpms.so.0.9.3")
	fxWrite(t, fx.libReal, "ELF libtpms 0.9.3", 0o644)
	fxLink(t, "libtpms.so.0.9.3", filepath.Join(libDir, "libtpms.so.0"))
	ovmf := filepath.Join(root, "usr/share/OVMF")
	fp := FirmwarePaths{
		Code: filepath.Join(ovmf, "OVMF_CODE_4M.fd"), Vars: filepath.Join(ovmf, "OVMF_VARS_4M.fd"),
		SecbootCode: filepath.Join(ovmf, "OVMF_CODE_4M.secboot.fd"), MsVars: filepath.Join(ovmf, "OVMF_VARS_4M.ms.fd"),
	}
	for _, p := range []string{fp.Code, fp.Vars, fp.SecbootCode, fp.MsVars} {
		fxWrite(t, p, "ovmf-2024.02:"+filepath.Base(p), 0o644)
	}
	fx.loader = fp.SecbootCode

	store := &FirmwareStore{DataDir: filepath.Join(root, "var/lib/litevirt"), SwtpmBase: filepath.Join(root, "var/lib/libvirt/swtpm")}
	fx.nvram = store.NvramPath(fxName)
	fxWrite(t, fx.nvram, "vars", 0o600)

	fx.probe = NewFirmwareCodeProbe(store, fp, func() (uint64, error) { return 10000000, nil })
	fx.probe.ProcRoot = filepath.Join(root, "proc")
	fx.probe.QEMURunDir = filepath.Join(root, "run/libvirt/qemu")
	fx.probe.SwtpmRunDir = filepath.Join(root, "run/libvirt/qemu/swtpm")
	fx.probe.QEMUBinary = fx.qemuBin
	fx.probe.SwtpmBinary = fx.swtpmBin
	fx.probe.LibDirs = []string{libDir}

	fx.dom = runningDomain{Name: fxName, ID: fxID, UUID: fxUUID, Loader: fx.loader, TPM: true}

	// libvirt's pid files: QEMU by name, swtpm by the SHORT name.
	fxWrite(t, filepath.Join(fx.probe.QEMURunDir, fxName+".pid"), strconv.Itoa(fxQEMUPid)+"\n", 0o644)
	fxWrite(t, filepath.Join(fx.probe.SwtpmRunDir, "7-fw-live-migration-te-swtpm.pid"), strconv.Itoa(fxSwtpmPid)+"\n", 0o644)

	// The QEMU process.
	qp := fx.procDir(fxQEMUPid)
	fx.setCmdline(fxQEMUPid, "/usr/bin/qemu-system-x86_64", "-name", "guest="+fxName+",debug-threads=on",
		"-S", "-uuid", fxUUID, "-blockdev", `{"driver":"file","filename":"`+fx.loader+`","read-only":true}`)
	fxLink(t, fx.qemuBin, filepath.Join(qp, "exe"))
	fxLink(t, "/dev/null", filepath.Join(qp, "fd/0"))
	fxLink(t, fx.nvram, filepath.Join(qp, "fd/17"))
	fxLink(t, fx.loader, filepath.Join(qp, "fd/18"))

	// The swtpm process, with libtpms mapped from its real file.
	sp := fx.procDir(fxSwtpmPid)
	fx.setCmdline(fxSwtpmPid, "swtpm", "socket", "--ctrl", "type=unixio,path=/run/libvirt/qemu/swtpm/7-fw-live-migration-te-swtpm.sock,mode=0600",
		"--tpmstate", "dir="+store.SwtpmBase+"/"+fxUUID+"/tpm2,mode=0600",
		"--log", "file=/var/log/swtpm/libvirt/qemu/"+fxName+"-swtpm.log", "--terminate", "--tpm2")
	fxLink(t, fx.swtpmBin, filepath.Join(sp, "exe"))
	fx.setMaps(fxSwtpmPid, "55d000000000-55d000001000 r--p 00000000 fd:01 1234 /usr/bin/swtpm\n"+
		fxMapsLine(t, fx.libReal, fx.libReal)+
		"7f0000003000-7f0000004000 rw-p 00000000 00:00 0 \n")
	fx.setMapFile(fx.libReal)

	// Both processes' start times, read before and after the checks.
	fx.setStat(fxQEMUPid, "qemu-system-x86", 1000)
	fx.setStat(fxSwtpmPid, "swtpm", 999)
	return fx
}

// setMapFile points swtpm's map_files entry of the libtpms mapping at target:
// the file the mapping really is, whatever maps prints.
func (fx *fwFixture) setMapFile(target string) {
	fxLink(fx.t, target, filepath.Join(fx.procDir(fxSwtpmPid), "map_files", fxLibMapFile))
}

// setStat writes /proc/<pid>/stat with start time (field 22) start. The comm
// carries a space and a parenthesis, as a real one can.
func (fx *fwFixture) setStat(pid int, comm string, start int) {
	fields := []string{"S", "1", "2", "3", "0", "-1", "4194560", "100", "0", "0", "0", "5", "6", "0", "0", "20", "0", "4", "0", strconv.Itoa(start), "123456"}
	fx.replace(filepath.Join(fx.procDir(pid), "stat"), fmt.Sprintf("%d (%s (x)) %s\n", pid, comm, strings.Join(fields, " ")))
}

func (fx *fwFixture) procDir(pid int) string {
	return filepath.Join(fx.probe.ProcRoot, strconv.Itoa(pid))
}

func (fx *fwFixture) setCmdline(pid int, argv ...string) {
	fx.replace(filepath.Join(fx.procDir(pid), "cmdline"), strings.Join(argv, "\x00")+"\x00")
}

func (fx *fwFixture) setMaps(pid int, maps string) {
	fx.replace(filepath.Join(fx.procDir(pid), "maps"), maps)
}

// replace writes a read-only /proc file afresh (a plain write cannot open
// the 0444 file it replaces).
func (fx *fwFixture) replace(p, body string) {
	fx.t.Helper()
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fx.t.Fatal(err)
	}
	fxWrite(fx.t, p, body, 0o444)
}

func (fx *fwFixture) run(t *testing.T) (FirmwareRuntime, error) {
	t.Helper()
	return fx.probe.runningFirmwareCode(context.Background(), fx.dom)
}

// wantPass asserts the check passes and reports the installed versions.
func (fx *fwFixture) wantPass(t *testing.T) {
	t.Helper()
	got, err := fx.run(t)
	if err != nil {
		t.Fatalf("RunningFirmwareCode refused a host running the installed code: %v", err)
	}
	ovmf, err := OVMFContentFingerprint(fx.probe.Firmware, fx.probe.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	want := FirmwareRuntime{Libvirt: "10.0.0", QEMU: "8.2.2", Swtpm: "0.7.3", Libtpms: "0.9.3", OVMFFingerprint: ovmf}
	if got != want {
		t.Fatalf("RunningFirmwareCode = %+v, want %+v", got, want)
	}
}

// wantRefused asserts the check refuses — an ErrRunningCodeUnverified with a
// zero runtime, never a partial one — and that the reason names every word
// in why.
func (fx *fwFixture) wantRefused(t *testing.T, why ...string) error {
	t.Helper()
	got, err := fx.run(t)
	if err == nil {
		t.Fatalf("RunningFirmwareCode passed (%+v); want a refusal naming %q", got, why)
	}
	if !errors.Is(err, ErrRunningCodeUnverified) {
		t.Fatalf("refusal %v is not ErrRunningCodeUnverified", err)
	}
	if got != (FirmwareRuntime{}) {
		t.Fatalf("refusal returned a runtime %+v; an unknown must carry nothing to compare", got)
	}
	for _, w := range why {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("refusal %q does not name %q", err, w)
		}
	}
	return err
}

// statSwap is the fake /proc with Stat of one entry answered from another
// file: the (dev, inode) a real /proc reports through a magic link, which a
// plain symlink in a directory cannot express.
type statSwap struct {
	procView
	entry, from string
}

func (s statSwap) Stat(name string) (fs.FileInfo, error) {
	if name == s.entry {
		return os.Stat(s.from)
	}
	return s.procView.Stat(name)
}

// failing is the fake /proc with one entry failing with err.
type failing struct {
	procView
	entry string
	err   error
}

func (f failing) hit(name string) error {
	if name == f.entry {
		return &fs.PathError{Op: "open", Path: name, Err: f.err}
	}
	return nil
}

func (f failing) ReadFile(name string) ([]byte, error) {
	if err := f.hit(name); err != nil {
		return nil, err
	}
	return f.procView.ReadFile(name)
}

func (f failing) Readlink(name string) (string, error) {
	if err := f.hit(name); err != nil {
		return "", err
	}
	return f.procView.Readlink(name)
}

func (f failing) Stat(name string) (fs.FileInfo, error) {
	if err := f.hit(name); err != nil {
		return nil, err
	}
	return f.procView.Stat(name)
}

func (f failing) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := f.hit(name); err != nil {
		return nil, err
	}
	return f.procView.ReadDir(name)
}

func pidEntry(pid int, rest string) string { return strconv.Itoa(pid) + "/" + rest }

func TestRunningFirmwareCode_DeletedExe(t *testing.T) {
	for _, tc := range []struct {
		name string
		pid  int
		bin  func(*fwFixture) string
	}{
		{"qemu", fxQEMUPid, func(fx *fwFixture) string { return fx.qemuBin }},
		{"swtpm", fxSwtpmPid, func(fx *fwFixture) string { return fx.swtpmBin }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFWFixture(t)
			// The package was upgraded under the running process: the kernel
			// reports the unlinked binary with the suffix. The path is
			// otherwise the installed one, so only the suffix can refuse it.
			fxLink(t, tc.bin(fx)+" (deleted)", filepath.Join(fx.procDir(tc.pid), "exe"))
			fx.wantRefused(t, "(deleted)", tc.name, "restart it (lv stop, lv start)")
		})
	}
}

func TestRunningFirmwareCode_InodeDiffers(t *testing.T) {
	for _, tc := range []struct {
		name, entry string
		why         string
		installed   func(*fwFixture) string
	}{
		{"qemu", pidEntry(fxQEMUPid, "exe"), "qemu", func(fx *fwFixture) string { return fx.qemuBin }},
		{"swtpm", pidEntry(fxSwtpmPid, "exe"), "swtpm", func(fx *fwFixture) string { return fx.swtpmBin }},
		{"ovmf", pidEntry(fxQEMUPid, "fd/18"), "OVMF", func(fx *fwFixture) string { return fx.loader }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFWFixture(t)
			// Same path, other file: a copy with the same bytes and a new inode.
			other := filepath.Join(fx.root, "old-"+tc.name)
			b, _ := os.ReadFile(tc.installed(fx))
			fxWrite(t, other, string(b), 0o755)
			fx.probe.proc = statSwap{procView: dirProc(fx.probe.ProcRoot), entry: tc.entry, from: other}
			fx.wantRefused(t, tc.why, "inode")
		})
	}
	t.Run("libtpms", func(t *testing.T) {
		fx := newFWFixture(t)
		other := filepath.Join(fx.root, "old-libtpms")
		fxWrite(t, other, "ELF libtpms 0.9.3", 0o644)
		// The mapping names the installed path, but map_files reaches
		// another file.
		fx.setMapFile(other)
		fx.wantRefused(t, "libtpms", "inode", "map_files", "restart it")
	})
}

func TestRunningFirmwareCode_LibtpmsMapped(t *testing.T) {
	newFWFixture(t).wantPass(t)
}

// The installed library is reached through its soname symlink; the mapping
// names the file it resolves to. Only the realpath can match them, and only
// the realpath's name carries the release.
func TestRunningFirmwareCode_LibtpmsMappedViaSymlink(t *testing.T) {
	fx := newFWFixture(t)
	realDir := filepath.Join(fx.root, "opt/libtpms/lib")
	real := filepath.Join(realDir, "libtpms.so.0.9.3")
	fxWrite(t, real, "ELF libtpms 0.9.3 (opt)", 0o644)
	linkDir := filepath.Join(fx.root, "usr/lib64")
	fxLink(t, real, filepath.Join(linkDir, "libtpms.so.0"))
	fx.probe.LibDirs = []string{linkDir}
	fx.setMaps(fxSwtpmPid, fxMapsLine(t, real, real))
	fx.setMapFile(real)
	fx.wantPass(t)

	// The mapping names the symlink's own path: not the realpath, refused.
	fx.setMaps(fxSwtpmPid, fxMapsLine(t, filepath.Join(linkDir, "libtpms.so.0"), real))
	fx.wantRefused(t, "libtpms", "no mapping")
}

func TestRunningFirmwareCode_LibtpmsMappingDeletedSuffix(t *testing.T) {
	fx := newFWFixture(t)
	// Same (dev, inode) and the installed path: only the suffix refuses it.
	line := fxMapsLine(t, fx.libReal, fx.libReal)
	fx.setMaps(fxSwtpmPid, strings.TrimSuffix(line, "\n")+" (deleted)\n")
	fx.wantRefused(t, "libtpms", "(deleted)")

	// A good mapping beside a deleted one does not excuse it.
	fx.setMaps(fxSwtpmPid, line+strings.TrimSuffix(line, "\n")+" (deleted)\n")
	fx.wantRefused(t, "libtpms", "(deleted)")
}

func TestRunningFirmwareCode_NoLibtpmsMapping(t *testing.T) {
	fx := newFWFixture(t)
	fx.setMaps(fxSwtpmPid, "55d000000000-55d000001000 r--p 00000000 fd:01 1234 /usr/bin/swtpm\n")
	fx.wantRefused(t, "libtpms", "no mapping")

	// An older libtpms mapped from another file is not the installed one.
	old := filepath.Join(fx.root, "usr/lib/x86_64-linux-gnu.old/libtpms.so.0.9.2")
	fxWrite(t, old, "ELF libtpms 0.9.2", 0o644)
	fx.setMaps(fxSwtpmPid, fxMapsLine(t, old, old))
	fx.wantRefused(t, "libtpms", "no mapping")

	// Empty maps: nothing found is a refusal, never "nothing to check".
	fx.setMaps(fxSwtpmPid, "")
	fx.wantRefused(t, "libtpms", "no mapping")
}

func TestRunningFirmwareCode_OVMFfd(t *testing.T) {
	fx := newFWFixture(t)
	fx.wantPass(t)

	// A non-SB UEFI domain loads the plain CODE; that passes too.
	fx.dom.Loader = fx.probe.Firmware.Code
	fxLink(t, fx.probe.Firmware.Code, filepath.Join(fx.procDir(fxQEMUPid), "fd/18"))
	fx.wantPass(t)

	// A loader that is not one of the installed OVMF CODE files refuses, even
	// with QEMU holding it open.
	stray := filepath.Join(fx.root, "srv/OVMF_CODE.custom.fd")
	fxWrite(t, stray, "custom", 0o644)
	fx.dom.Loader = stray
	fxLink(t, stray, filepath.Join(fx.procDir(fxQEMUPid), "fd/18"))
	fx.wantRefused(t, "OVMF", "not an installed")
}

func TestRunningFirmwareCode_OVMFfdDeletedSuffix(t *testing.T) {
	fx := newFWFixture(t)
	fxLink(t, fx.loader+" (deleted)", filepath.Join(fx.procDir(fxQEMUPid), "fd/18"))
	fx.wantRefused(t, "OVMF", "(deleted)")

	// A good fd beside the deleted one does not excuse it.
	fxLink(t, fx.loader, filepath.Join(fx.procDir(fxQEMUPid), "fd/19"))
	fx.wantRefused(t, "OVMF", "(deleted)")
}

func TestRunningFirmwareCode_NoOVMFfd(t *testing.T) {
	fx := newFWFixture(t)
	if err := os.Remove(filepath.Join(fx.procDir(fxQEMUPid), "fd/18")); err != nil {
		t.Fatal(err)
	}
	fx.wantRefused(t, "OVMF", "no open fd")

	// The other CODE file open is not the domain's loader.
	fxLink(t, fx.probe.Firmware.Code, filepath.Join(fx.procDir(fxQEMUPid), "fd/18"))
	fx.wantRefused(t, "OVMF", "no open fd")
}

func TestRunningFirmwareCode_QEMUPidWrongUUID(t *testing.T) {
	for name, argv := range map[string][]string{
		"other uuid":    {"/usr/bin/qemu-system-x86_64", "-name", "guest=" + fxName, "-uuid", fxOtherUUID},
		"no uuid":       {"/usr/bin/qemu-system-x86_64", "-name", "guest=" + fxName},
		"uuid last arg": {"/usr/bin/qemu-system-x86_64", "-name", "guest=" + fxName, "-uuid"},
		"uuid as value": {"/usr/bin/qemu-system-x86_64", "-name", fxUUID, "-smbios", "type=1,uuid=" + fxUUID},
		"empty":         {""},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newFWFixture(t)
			fx.setCmdline(fxQEMUPid, argv...)
			fx.wantRefused(t, "qemu", "-uuid", "pid file does not lead")
		})
	}
	t.Run("upper-case uuid matches", func(t *testing.T) {
		fx := newFWFixture(t)
		fx.setCmdline(fxQEMUPid, "/usr/bin/qemu-system-x86_64", "-uuid", strings.ToUpper(fxUUID))
		fx.wantPass(t)
	})
}

func TestRunningFirmwareCode_SwtpmPidFileShortName(t *testing.T) {
	fx := newFWFixture(t)
	fx.wantPass(t)

	// Only a pid file at the FULL-name path: libvirt never writes that one,
	// so reading it would be reading the wrong file.
	if err := os.Remove(filepath.Join(fx.probe.SwtpmRunDir, "7-fw-live-migration-te-swtpm.pid")); err != nil {
		t.Fatal(err)
	}
	fxWrite(t, filepath.Join(fx.probe.SwtpmRunDir, fxName+"-swtpm.pid"), strconv.Itoa(fxSwtpmPid)+"\n", 0o644)
	fx.wantRefused(t, "swtpm", "pid file")

	// The short name is built from the LIVE domain id: another id's file is
	// not this domain's.
	fxWrite(t, filepath.Join(fx.probe.SwtpmRunDir, "8-fw-live-migration-te-swtpm.pid"), strconv.Itoa(fxSwtpmPid)+"\n", 0o644)
	fx.wantRefused(t, "swtpm", "pid file")
}

func TestLibvirtShortName(t *testing.T) {
	for _, tc := range []struct {
		id   int
		name string
		want string
	}{
		{7, "fw-live-migration-test-vm", "7-fw-live-migration-te"},
		{12, "short", "12-short"},
		{3, "exactly-twenty-chars", "3-exactly-twenty-chars"},
		{3, "exactly-twenty-chars1", "3-exactly-twenty-chars"},
	} {
		if got := libvirtShortName(tc.id, tc.name); got != tc.want {
			t.Errorf("libvirtShortName(%d, %q) = %q, want %q", tc.id, tc.name, got, tc.want)
		}
	}
}

func TestRunningFirmwareCode_SwtpmPidWrongStateDir(t *testing.T) {
	base := func(fx *fwFixture) string { return fx.probe.SwtpmBase }
	for name, tpmstate := range map[string]func(*fwFixture) []string{
		"other uuid": func(fx *fwFixture) []string {
			return []string{"--tpmstate", "dir=" + base(fx) + "/" + fxOtherUUID + "/tpm2,mode=0600"}
		},
		"uuid prefix trap": func(fx *fwFixture) []string {
			return []string{"--tpmstate", "dir=" + base(fx) + "/" + fxUUID + "x/tpm2,mode=0600"}
		},
		"other base": func(fx *fwFixture) []string {
			return []string{"--tpmstate", "dir=/var/lib/elsewhere/" + fxUUID + "/tpm2,mode=0600"}
		},
		"escaping dir": func(fx *fwFixture) []string {
			return []string{"--tpmstate", "dir=" + base(fx) + "/" + fxUUID + "/../" + fxOtherUUID}
		},
		"no tpmstate": func(fx *fwFixture) []string { return nil },
		"no dir key": func(fx *fwFixture) []string {
			return []string{"--tpmstate", "backend-uri=file://" + base(fx) + "/" + fxUUID}
		},
		"dangling flag": func(fx *fwFixture) []string { return []string{"--tpmstate"} },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newFWFixture(t)
			argv := append([]string{"swtpm", "socket", "--ctrl", "type=unixio,path=/x"}, tpmstate(fx)...)
			fx.setCmdline(fxSwtpmPid, append(argv, "--tpm2")...)
			fx.wantRefused(t, "swtpm", "state dir")
		})
	}
	t.Run("equals form and bare uuid dir", func(t *testing.T) {
		fx := newFWFixture(t)
		fx.setCmdline(fxSwtpmPid, "swtpm", "socket", "--tpmstate=dir="+fx.probe.SwtpmBase+"/"+fxUUID+",mode=0600", "--tpm2")
		fx.wantPass(t)
	})
}

func TestRunningFirmwareCode_ProcUnreadable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, fx *fwFixture)
		why    string
	}{
		{"qemu pid file missing", func(t *testing.T, fx *fwFixture) {
			_ = os.Remove(filepath.Join(fx.probe.QEMURunDir, fxName+".pid"))
		}, "qemu"},
		{"qemu pid file garbage", func(t *testing.T, fx *fwFixture) {
			fxWrite(t, filepath.Join(fx.probe.QEMURunDir, fxName+".pid"), "42x\n", 0o644)
		}, "qemu"},
		{"qemu pid zero", func(t *testing.T, fx *fwFixture) {
			fxWrite(t, filepath.Join(fx.probe.QEMURunDir, fxName+".pid"), "0\n", 0o644)
		}, "qemu"},
		{"qemu not in this pid namespace", func(t *testing.T, fx *fwFixture) {
			_ = os.RemoveAll(fx.procDir(fxQEMUPid))
		}, "qemu"},
		{"swtpm not in this pid namespace", func(t *testing.T, fx *fwFixture) {
			_ = os.RemoveAll(fx.procDir(fxSwtpmPid))
		}, "swtpm"},
		{"swtpm maps missing", func(t *testing.T, fx *fwFixture) {
			_ = os.Remove(filepath.Join(fx.procDir(fxSwtpmPid), "maps"))
		}, "maps"},
		{"qemu fd dir missing", func(t *testing.T, fx *fwFixture) {
			_ = os.RemoveAll(filepath.Join(fx.procDir(fxQEMUPid), "fd"))
		}, "fd"},
		{"qemu exe missing", func(t *testing.T, fx *fwFixture) {
			_ = os.Remove(filepath.Join(fx.procDir(fxQEMUPid), "exe"))
		}, "qemu"},
		{"whole /proc missing", func(t *testing.T, fx *fwFixture) {
			_ = os.RemoveAll(fx.probe.ProcRoot)
		}, "qemu"},
		{"domain not running", func(t *testing.T, fx *fwFixture) { fx.dom.ID = 0 }, "not running"},
		{"domain uuid malformed", func(t *testing.T, fx *fwFixture) { fx.dom.UUID = "../" + fxUUID }, "uuid"},
		{"domain name unsafe", func(t *testing.T, fx *fwFixture) { fx.dom.Name = "../" + fxName }, "name"},
		{"installed qemu missing", func(t *testing.T, fx *fwFixture) { _ = os.Remove(fx.qemuBin) }, "installed"},
		{"installed libtpms ambiguous", func(t *testing.T, fx *fwFixture) {
			other := filepath.Join(fx.root, "opt/libtpms.so.1.0.0")
			fxWrite(t, other, "other major", 0o644)
			fxLink(t, other, filepath.Join(filepath.Dir(fx.libReal), "libtpms.so.1"))
		}, "ldconfig"},
		{"swtpm map_files missing", func(t *testing.T, fx *fwFixture) {
			_ = os.RemoveAll(filepath.Join(fx.procDir(fxSwtpmPid), "map_files"))
		}, "map_files"},
		{"qemu stat missing", func(t *testing.T, fx *fwFixture) {
			_ = os.Remove(filepath.Join(fx.procDir(fxQEMUPid), "stat"))
		}, "qemu"},
		{"swtpm stat garbage", func(t *testing.T, fx *fwFixture) {
			fx.replace(filepath.Join(fx.procDir(fxSwtpmPid), "stat"), "4243 (swtpm) S 1 2\n")
		}, "swtpm"},
		{"libvirt version unreadable", func(t *testing.T, fx *fwFixture) {
			fx.probe.LibvirtVersion = func() (uint64, error) { return 0, errors.New("no connection") }
		}, "libvirt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFWFixture(t)
			tc.break_(t, fx)
			fx.wantRefused(t, tc.why)
		})
	}
}

func TestRunningFirmwareCode_EACCES(t *testing.T) {
	for _, tc := range []struct {
		entry string
		why   string
	}{
		{pidEntry(fxQEMUPid, "cmdline"), "qemu"},
		{pidEntry(fxQEMUPid, "exe"), "qemu"},
		{pidEntry(fxQEMUPid, "fd"), "fd"},
		{pidEntry(fxQEMUPid, "fd/18"), "OVMF"},
		{pidEntry(fxSwtpmPid, "cmdline"), "swtpm"},
		{pidEntry(fxSwtpmPid, "exe"), "swtpm"},
		{pidEntry(fxSwtpmPid, "maps"), "maps"},
		{pidEntry(fxSwtpmPid, "map_files/"+fxLibMapFile), "map_files"},
		{pidEntry(fxQEMUPid, "stat"), "qemu"},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			fx := newFWFixture(t)
			fx.probe.proc = failing{procView: dirProc(fx.probe.ProcRoot), entry: tc.entry, err: syscall.EACCES}
			err := fx.wantRefused(t, tc.why, "root")
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("refusal %v does not carry the permission error", err)
			}
		})
	}
	// A real unreadable file, where the test is not root (root reads it).
	t.Run("mode 000 maps", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores file modes; the injected cases cover EACCES")
		}
		fx := newFWFixture(t)
		if err := os.Chmod(filepath.Join(fx.procDir(fxSwtpmPid), "maps"), 0); err != nil {
			t.Fatal(err)
		}
		if err := fx.wantRefused(t, "maps"); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("refusal %v does not carry the permission error", err)
		}
	})
	// A vanished fd (closed between the listing and the readlink) is skipped,
	// never a match; with the loader's fd still there, the check passes.
	t.Run("vanished fd skipped", func(t *testing.T) {
		fx := newFWFixture(t)
		fx.probe.proc = failing{procView: dirProc(fx.probe.ProcRoot), entry: pidEntry(fxQEMUPid, "fd/17"), err: syscall.ENOENT}
		fx.wantPass(t)
	})
}

// Applicability: a domain without a vTPM has no swtpm to find, and a BIOS
// domain no loader. Everything the domain HAS is still checked.
func TestRunningFirmwareCode_Applicability(t *testing.T) {
	t.Run("no tpm", func(t *testing.T) {
		fx := newFWFixture(t)
		fx.dom.TPM = false
		_ = os.RemoveAll(fx.procDir(fxSwtpmPid))
		_ = os.RemoveAll(fx.probe.SwtpmRunDir)
		fx.wantPass(t)
		fxLink(t, fx.loader+" (deleted)", filepath.Join(fx.procDir(fxQEMUPid), "fd/18"))
		fx.wantRefused(t, "OVMF", "(deleted)")
	})
	t.Run("bios", func(t *testing.T) {
		fx := newFWFixture(t)
		fx.dom.Loader = ""
		_ = os.Remove(filepath.Join(fx.procDir(fxQEMUPid), "fd/18"))
		fx.wantPass(t)
		fx.setMaps(fxSwtpmPid, "")
		fx.wantRefused(t, "libtpms", "no mapping")
	})
}

func TestRunningDomainFromXML(t *testing.T) {
	live := `<domain type='kvm' id='7'>
  <name>` + fxName + `</name>
  <uuid>` + strings.ToUpper(fxUUID) + `</uuid>
  <os>
    <type arch='x86_64' machine='pc-q35-8.2'>hvm</type>
    <loader readonly='yes' secure='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE_4M.secboot.fd</loader>
    <nvram template='/usr/share/OVMF/OVMF_VARS_4M.ms.fd'>/var/lib/litevirt/nvram/x_VARS.fd</nvram>
  </os>
  <devices>
    <tpm model='tpm-crb'>
      <backend type='emulator' version='2.0' persistent_state='yes'/>
      <alias name='tpm0'/>
    </tpm>
  </devices>
</domain>`
	got, err := runningDomainFromXML(live)
	if err != nil {
		t.Fatal(err)
	}
	want := runningDomain{Name: fxName, ID: 7, UUID: fxUUID, Loader: "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd", TPM: true}
	if got != want {
		t.Fatalf("runningDomainFromXML = %+v, want %+v", got, want)
	}

	inactive := `<domain type='kvm'><name>vm</name><uuid>` + fxUUID + `</uuid><os><type>hvm</type></os><devices/></domain>`
	got, err = runningDomainFromXML(inactive)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 0 || got.TPM || got.Loader != "" {
		t.Fatalf("inactive/BIOS/no-TPM parsed as %+v", got)
	}

	passthrough := strings.Replace(live, `type='emulator'`, `type='passthrough'`, 1)
	// Any TPM device counts: a passthrough one has no swtpm to find, so the
	// check refuses it rather than skipping the TPM.
	if got, _ := runningDomainFromXML(passthrough); !got.TPM {
		t.Fatal("a passthrough TPM read as no TPM")
	}
	if _, err := runningDomainFromXML("not xml"); err == nil {
		t.Fatal("malformed XML parsed")
	}
}

// TestTPMPersistentStateYes: stage A's check of the RUNNING definition (§3.2
// item 3) passes only an emulator backend with persistent_state='yes'.
func TestTPMPersistentStateYes(t *testing.T) {
	dom := func(tpm string) string {
		return `<domain type='kvm' id='3'><name>vm</name><devices>` + tpm + `</devices></domain>`
	}
	cases := map[string]struct {
		xml  string
		want bool
	}{
		"yes":            {dom(`<tpm model='tpm-crb'><backend type='emulator' version='2.0' persistent_state='yes'/></tpm>`), true},
		"absent":         {dom(`<tpm model='tpm-crb'><backend type='emulator' version='2.0'/></tpm>`), false},
		"no":             {dom(`<tpm model='tpm-crb'><backend type='emulator' version='2.0' persistent_state='no'/></tpm>`), false},
		"passthrough":    {dom(`<tpm model='tpm-tis'><backend type='passthrough' persistent_state='yes'/></tpm>`), false},
		"no tpm":         {dom(``), false},
		"malformed":      {`<domain><devices><tpm>`, false},
		"empty":          {``, false},
		"second not yes": {dom(`<tpm model='tpm-crb'><backend type='emulator' persistent_state='yes'/></tpm><tpm model='tpm-crb'><backend type='emulator'/></tpm>`), false},
	}
	for name, tc := range cases {
		if got := TPMPersistentStateYes(tc.xml); got != tc.want {
			t.Errorf("%s: TPMPersistentStateYes = %v, want %v", name, got, tc.want)
		}
	}

	// What litevirt renders passes.
	cfg := VMConfig{Name: "vm", UUID: fxUUID, CPU: 1, MemoryMiB: 512, Machine: "q35", Firmware: "uefi"}
	FirmwarePaths{SecbootCode: "/c", MsVars: "/v"}.ApplyTo(&cfg, "/var/lib/litevirt", "vm", true, true)
	out, err := GenerateDomainXML(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !TPMPersistentStateYes(out) {
		t.Fatal("the rendered vTPM does not pass the running-definition check")
	}
}

// The maps dev of a btrfs subvolume or an overlayfs file is not stat's
// st_dev. The mapping is proven through map_files, so a maps line whose dev
// and inode text differ from stat still passes when map_files reaches the
// installed file (review I-1).
func TestRunningFirmwareCode_LibtpmsMapsDevDiffersFromStat(t *testing.T) {
	fx := newFWFixture(t)
	fx.setMaps(fxSwtpmPid, fxLibRange+" r-xp 00001000 00:2a 1 "+fx.libReal+"\n")
	fx.wantPass(t)
}

// A pid recycled between the first and the last read of it refuses: the
// start time is read again after the checks (review m-4).
func TestRunningFirmwareCode_PidRecycled(t *testing.T) {
	for _, tc := range []struct {
		name string
		pid  int
	}{{"qemu", fxQEMUPid}, {"swtpm", fxSwtpmPid}} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFWFixture(t)
			fx.probe.proc = &restat{procView: dirProc(fx.probe.ProcRoot), entry: pidEntry(tc.pid, "stat"),
				after: func() { fx.setStat(tc.pid, "recycled", 5000) }}
			fx.wantRefused(t, tc.name, "start time changed")
		})
	}
}

// restat runs after once, after the first read of entry: the process at the
// pid is replaced while the check reads it.
type restat struct {
	procView
	entry string
	after func()
	done  bool
}

func (r *restat) ReadFile(name string) ([]byte, error) {
	b, err := r.procView.ReadFile(name)
	if name == r.entry && !r.done {
		r.done = true
		r.after()
	}
	return b, err
}

// The exported entry point takes the live XML: the checks that apply are
// read from it, so a caller cannot drop the swtpm or OVMF check by leaving
// a field empty (review m-5).
func TestRunningFirmwareCode_FromLiveXML(t *testing.T) {
	fx := newFWFixture(t)
	live := `<domain type='kvm' id='7'><name>` + fxName + `</name><uuid>` + fxUUID + `</uuid>
  <os><type arch='x86_64' machine='pc-q35-8.2'>hvm</type><loader readonly='yes' secure='yes' type='pflash'>` + fx.loader + `</loader></os>
  <devices><tpm model='tpm-crb'><backend type='emulator' version='2.0' persistent_state='yes'/></tpm></devices></domain>`
	run := func() (FirmwareRuntime, error) {
		return fx.probe.RunningFirmwareCode(context.Background(), live)
	}
	if _, err := run(); err != nil {
		t.Fatalf("live XML of a host running the installed code refused: %v", err)
	}
	// The XML has a TPM, so the swtpm checks run: no libtpms mapping refuses.
	fx.setMaps(fxSwtpmPid, "")
	if got, err := run(); !errors.Is(err, ErrRunningCodeUnverified) || got != (FirmwareRuntime{}) || !strings.Contains(err.Error(), "libtpms") {
		t.Fatalf("TPM in the live XML not checked: %+v, %v", got, err)
	}
	for name, bad := range map[string]string{
		"malformed": "<domain>",
		"inactive":  strings.Replace(live, " id='7'", "", 1),
	} {
		if got, err := fx.probe.RunningFirmwareCode(context.Background(), bad); !errors.Is(err, ErrRunningCodeUnverified) || got != (FirmwareRuntime{}) {
			t.Errorf("%s live XML: %+v, %v; want a refusal", name, got, err)
		}
	}
}

// Installed never returns a half-read value with its error (review m-2).
func TestFirmwareCodeProbe_InstalledZeroOnError(t *testing.T) {
	for name, brk := range map[string]func(*fwFixture){
		"qemu missing":    func(fx *fwFixture) { _ = os.Remove(fx.qemuBin) },
		"swtpm missing":   func(fx *fwFixture) { _ = os.Remove(fx.swtpmBin) },
		"no libtpms":      func(fx *fwFixture) { fx.probe.LibDirs = []string{filepath.Join(fx.root, "empty")} },
		"ovmf unreadable": func(fx *fwFixture) { _ = os.Remove(fx.probe.Firmware.MsVars) },
		"no libvirt conn": func(fx *fwFixture) { fx.probe.LibvirtVersion = nil },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newFWFixture(t)
			brk(fx)
			in, err := fx.probe.Installed(context.Background())
			if err == nil {
				t.Fatal("Installed succeeded")
			}
			if !reflect.DeepEqual(in, InstalledFirmwareCode{}) {
				t.Fatalf("Installed returned %+v with its error", in)
			}
		})
	}
}

// Only the soname links (libtpms.so.<N>) the dynamic linker resolves count; a
// stray real file or a dangling dev link does not, and one file reached
// through a usrmerge /lib → /usr/lib link counts once (review m-3).
func TestFirmwareCodeProbe_InstalledLibtpmsSonameOnly(t *testing.T) {
	fx := newFWFixture(t)
	libDir := filepath.Dir(fx.libReal)
	fxWrite(t, filepath.Join(libDir, "libtpms.so.0.9.2"), "stray old copy", 0o644)
	fxLink(t, "libtpms.so.0.9.99", filepath.Join(libDir, "libtpms.so"))
	usrmerged := filepath.Join(fx.root, "lib")
	fxLink(t, filepath.Join(fx.root, "usr/lib"), usrmerged)
	fx.probe.LibDirs = []string{libDir, filepath.Join(usrmerged, "x86_64-linux-gnu"), filepath.Join(fx.root, "absent")}
	in, err := fx.probe.Installed(context.Background())
	if err != nil {
		t.Fatalf("Installed: %v", err)
	}
	if in.Libtpms != fx.libReal || in.Runtime.Libtpms != "0.9.3" {
		t.Fatalf("installed libtpms = %s (%s), want %s (0.9.3)", in.Libtpms, in.Runtime.Libtpms, fx.libReal)
	}
	fx.wantPass(t)
}
