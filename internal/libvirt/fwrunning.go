package libvirt

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/litevirt/litevirt/internal/safename"
)

// Running firmware code (spec §3.5). QEMU, swtpm, libtpms and the OVMF CODE are
// loaded when a guest starts, and a live move streams state out of those
// processes. A package upgraded on both hosts makes the INSTALLED versions
// equal while the source still runs the old code, so the source proves from
// /proc that its processes run the installed files before it reports the
// installed versions as its running ones.
//
// Every check must find what it looks for. A missing pid file, process, fd or
// mapping, an unreadable or EACCES entry, a process in another pid namespace,
// and a ` (deleted)` suffix all refuse: the answer is then "unknown", and
// unknown is never "matches". No QMP command is used (it taints the domain).

// ErrRunningCodeUnverified is every refusal of RunningFirmwareCode: the
// source could not prove that the domain runs the installed firmware code.
var ErrRunningCodeUnverified = errors.New("running firmware code not verified")

// deletedSuffix is what the kernel appends to a /proc link target or maps path
// whose file has been unlinked.
const deletedSuffix = " (deleted)"

// Production locations (Ubuntu's libvirt, the system QEMU driver).
const (
	DefaultProcRoot    = "/proc"
	DefaultQEMURunDir  = "/run/libvirt/qemu"       // <name>.pid
	DefaultSwtpmRunDir = "/run/libvirt/qemu/swtpm" // <shortName>-swtpm.pid
	// DefaultQEMUBinary is the emulator every rendered domain names (xmlgen).
	DefaultQEMUBinary = "/usr/bin/qemu-system-x86_64"
)

// DefaultLibDirs are searched for the installed libtpms.so*.
var DefaultLibDirs = []string{
	"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib64", "/usr/lib",
	"/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu", "/lib64",
}

// procView is the slice of /proc the check reads, by names relative to the
// proc root ("<pid>/exe"). Stat follows links, which on a real /proc reaches
// the file a process has open even where its name now points elsewhere.
type procView interface {
	ReadFile(name string) ([]byte, error)
	Readlink(name string) (string, error)
	Stat(name string) (fs.FileInfo, error)
	ReadDir(name string) ([]fs.DirEntry, error)
}

// dirProc is a procView over a directory: /proc, or a test's fake root.
type dirProc string

func (d dirProc) path(name string) string              { return filepath.Join(string(d), name) }
func (d dirProc) ReadFile(name string) ([]byte, error) { return os.ReadFile(d.path(name)) }
func (d dirProc) Readlink(name string) (string, error) { return os.Readlink(d.path(name)) }
func (d dirProc) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(d.path(name))
}
func (d dirProc) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(d.path(name)) }

// FirmwareCodeProbe reads one host's installed firmware code and checks a
// running domain against it.
type FirmwareCodeProbe struct {
	Firmware    FirmwarePaths // the resolved OVMF files
	DataDir     string        // the daemon's data dir (part of the OVMF fingerprint)
	SwtpmBase   string        // libvirt's swtpm root (swtpm's --tpmstate dir)
	ProcRoot    string
	QEMURunDir  string
	SwtpmRunDir string
	QEMUBinary  string
	SwtpmBinary string // "" → swtpm on PATH, as libvirt finds it
	LibDirs     []string
	// LibvirtVersion is the daemon's packed libvirt version (Client.LibvirtVersion).
	LibvirtVersion func() (uint64, error)

	proc procView // nil → dirProc(ProcRoot); tests replace it
}

// NewFirmwareCodeProbe is the probe of the host whose firmware state is store,
// at the production locations.
func NewFirmwareCodeProbe(store *FirmwareStore, fp FirmwarePaths, libvirtVersion func() (uint64, error)) *FirmwareCodeProbe {
	return &FirmwareCodeProbe{
		Firmware: fp, DataDir: store.DataDir, SwtpmBase: store.SwtpmBase,
		ProcRoot: DefaultProcRoot, QEMURunDir: DefaultQEMURunDir, SwtpmRunDir: DefaultSwtpmRunDir,
		QEMUBinary: DefaultQEMUBinary, LibDirs: DefaultLibDirs, LibvirtVersion: libvirtVersion,
	}
}

func (p *FirmwareCodeProbe) procfs() procView {
	if p.proc != nil {
		return p.proc
	}
	return dirProc(p.ProcRoot)
}

// InstalledFirmwareCode is a host's installed firmware code: its versions and
// the real paths of the files a running domain must have loaded.
type InstalledFirmwareCode struct {
	Runtime FirmwareRuntime
	QEMU    string   // realpath of the emulator binary
	Swtpm   string   // realpath of the swtpm binary
	Libtpms string   // realpath of the libtpms library
	Loaders []string // realpaths of the OVMF CODE files (plain and Secure Boot)
}

// versionTimeout bounds each `--version` run.
const versionTimeout = 10 * time.Second

// Installed reads the host's installed firmware code. This is what the target
// compares (its incoming QEMU and swtpm are exec'd from it) and what the
// source's running processes must be. Any version or file it cannot read is an
// error.
func (p *FirmwareCodeProbe) Installed(ctx context.Context) (InstalledFirmwareCode, error) {
	var in InstalledFirmwareCode
	if p.LibvirtVersion == nil {
		return in, fmt.Errorf("libvirt version: no connection")
	}
	lv, err := p.LibvirtVersion()
	if err != nil {
		return in, fmt.Errorf("libvirt version: %w", err)
	}
	if in.Runtime.Libvirt, err = FormatLibvirtVersion(lv); err != nil {
		return in, err
	}

	qemuBin := p.QEMUBinary
	if in.QEMU, err = filepath.EvalSymlinks(qemuBin); err != nil {
		return in, fmt.Errorf("installed qemu %s: %w", qemuBin, err)
	}
	out, err := versionOutput(ctx, in.QEMU)
	if err != nil {
		return in, fmt.Errorf("installed qemu %s: %w", in.QEMU, err)
	}
	if in.Runtime.QEMU, err = ParseQEMUVersion(out); err != nil {
		return in, err
	}

	swtpmBin := p.SwtpmBinary
	if swtpmBin == "" {
		if swtpmBin, err = exec.LookPath("swtpm"); err != nil {
			return in, fmt.Errorf("installed swtpm: %w", err)
		}
	}
	if in.Swtpm, err = filepath.EvalSymlinks(swtpmBin); err != nil {
		return in, fmt.Errorf("installed swtpm %s: %w", swtpmBin, err)
	}
	if out, err = versionOutput(ctx, in.Swtpm); err != nil {
		return in, fmt.Errorf("installed swtpm %s: %w", in.Swtpm, err)
	}
	if in.Runtime.Swtpm, err = ParseSwtpmVersion(out); err != nil {
		return in, err
	}

	if in.Libtpms, err = p.installedLibtpms(); err != nil {
		return in, err
	}
	if in.Runtime.Libtpms, err = ParseLibtpmsSoname(in.Libtpms); err != nil {
		return in, err
	}

	if in.Runtime.OVMFFingerprint, err = OVMFContentFingerprint(p.Firmware, p.DataDir); err != nil {
		return in, err
	}
	for _, c := range []string{p.Firmware.Code, p.Firmware.SecbootCode} {
		if c == "" {
			continue
		}
		r, err := filepath.EvalSymlinks(c)
		if err != nil {
			return in, fmt.Errorf("installed OVMF CODE %s: %w", c, err)
		}
		in.Loaders = append(in.Loaders, r)
	}
	return in, nil
}

func versionOutput(ctx context.Context, bin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", bin, err)
	}
	return string(out), nil
}

// installedLibtpms is the one real file every libtpms.so* in the library dirs
// resolves to. None, or two different files, is an error: which of them a
// newly exec'd swtpm loads would be a guess.
func (p *FirmwareCodeProbe) installedLibtpms() (string, error) {
	seen := map[string]bool{}
	for _, dir := range p.LibDirs {
		matches, err := filepath.Glob(filepath.Join(dir, "libtpms.so*"))
		if err != nil {
			return "", fmt.Errorf("installed libtpms: %w", err)
		}
		for _, m := range matches {
			r, err := filepath.EvalSymlinks(m)
			if err != nil {
				return "", fmt.Errorf("installed libtpms %s: %w", m, err)
			}
			seen[r] = true
		}
	}
	var found []string
	for r := range seen {
		found = append(found, r)
	}
	sort.Strings(found)
	switch len(found) {
	case 0:
		return "", fmt.Errorf("installed libtpms: no libtpms.so* in %s", strings.Join(p.LibDirs, ", "))
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("installed libtpms ambiguous: %s", strings.Join(found, ", "))
	}
}

// RunningDomain is what the check needs of a running domain, from its LIVE
// definition: the live id names swtpm's pid file.
type RunningDomain struct {
	Name   string
	ID     int    // live domain id; 0 when not running
	UUID   string // lower case
	Loader string // <os><loader>; "" for BIOS
	TPM    bool   // any <tpm> device
}

// RunningDomainFromXML reads a RunningDomain from a domain's live XML
// (DumpXML of a running domain).
func RunningDomainFromXML(liveXML string) (RunningDomain, error) {
	var d struct {
		ID     string `xml:"id,attr"`
		Name   string `xml:"name"`
		UUID   string `xml:"uuid"`
		Loader string `xml:"os>loader"`
		TPM    []struct {
			Model string `xml:"model,attr"`
		} `xml:"devices>tpm"`
	}
	if err := xml.Unmarshal([]byte(liveXML), &d); err != nil {
		return RunningDomain{}, fmt.Errorf("parse domain XML: %w", err)
	}
	rd := RunningDomain{
		Name:   strings.TrimSpace(d.Name),
		UUID:   strings.ToLower(strings.TrimSpace(d.UUID)),
		Loader: strings.TrimSpace(d.Loader),
		TPM:    len(d.TPM) > 0,
	}
	if d.ID != "" {
		id, err := strconv.Atoi(d.ID)
		if err != nil {
			return RunningDomain{}, fmt.Errorf("domain id %q: %w", d.ID, err)
		}
		if id > 0 {
			rd.ID = id
		}
	}
	return rd, nil
}

// TPMPersistentStateYes reports whether every TPM of the domain XML is an
// emulator with persistent_state='yes' (and there is at least one). It reads
// the RUNNING definition in stage A (spec §3.2 item 3): without
// persistent_state libvirt deletes the swtpm tree with the domain, and the
// source's copy is what a failed move falls back to.
func TPMPersistentStateYes(domXML string) bool {
	var d struct {
		TPM []struct {
			Backend []struct {
				Type            string `xml:"type,attr"`
				PersistentState string `xml:"persistent_state,attr"`
			} `xml:"backend"`
		} `xml:"devices>tpm"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil || len(d.TPM) == 0 {
		return false
	}
	for _, t := range d.TPM {
		if len(t.Backend) != 1 || t.Backend[0].Type != "emulator" || t.Backend[0].PersistentState != "yes" {
			return false
		}
	}
	return true
}

// libvirtShortName is libvirt's virDomainDefGetShortName for an ASCII name:
// "<id>-<first 20 bytes of name>". swtpm's pid file is named after it
// (qemuTPMEmulatorPidFileBuildPath). VM names are ASCII (safename).
func libvirtShortName(id int, name string) string {
	const max = 20
	if len(name) > max {
		name = name[:max]
	}
	return strconv.Itoa(id) + "-" + name
}

// refuse wraps a refusal of the running-code check.
func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRunningCodeUnverified, fmt.Errorf(format, args...))
}

// refuseErr is refuse keeping err in the chain (errors.Is(…, fs.ErrPermission)).
func refuseErr(err error, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %w", ErrRunningCodeUnverified, fmt.Sprintf(format, args...), err)
}

// RunningFirmwareCode proves that the running domain dom runs this host's
// installed firmware code and returns the installed runtime as its running
// one. Each check below must find what it looks for (spec §3.5):
//
//  1. QEMU: the pid from <QEMURunDir>/<name>.pid, whose cmdline carries
//     "-uuid <uuid>".
//  2. swtpm (a domain with a TPM): the pid from
//     <SwtpmRunDir>/<id>-<name[:20]>-swtpm.pid, whose cmdline's --tpmstate dir
//     is <SwtpmBase>/<uuid> or below it.
//  3. Each exe links to the installed binary's realpath, without the
//     (deleted) suffix, and stats to the installed file's (dev, inode).
//  4. libtpms: swtpm maps the installed libtpms realpath, every such mapping
//     undeleted and with the installed (dev, inode).
//  5. OVMF CODE (a domain with a loader): the loader is an installed CODE
//     file, and QEMU holds it open by an fd, every such fd undeleted and the
//     installed file.
//
// Any refusal is an ErrRunningCodeUnverified with a zero runtime.
func (p *FirmwareCodeProbe) RunningFirmwareCode(ctx context.Context, dom RunningDomain) (FirmwareRuntime, error) {
	if dom.ID <= 0 {
		return FirmwareRuntime{}, refuse("domain %s is not running (no live id)", dom.Name)
	}
	if err := safename.ValidateVMName(dom.Name); err != nil {
		return FirmwareRuntime{}, refuse("domain name: %v", err)
	}
	uuid := strings.ToLower(dom.UUID)
	if !ValidFirmwareUUID(uuid) {
		return FirmwareRuntime{}, refuse("domain %s: invalid uuid %q", dom.Name, dom.UUID)
	}
	in, err := p.Installed(ctx)
	if err != nil {
		return FirmwareRuntime{}, refuseErr(err, "domain %s: installed firmware code unknown", dom.Name)
	}
	proc := p.procfs()

	// 1. QEMU, by the domain's pid file and its -uuid.
	qemuPid, err := readPidFile(filepath.Join(p.QEMURunDir, dom.Name+".pid"))
	if err != nil {
		return FirmwareRuntime{}, refuseErr(err, "qemu of %s: pid file", dom.Name)
	}
	argv, err := readCmdline(proc, qemuPid)
	if err != nil {
		return FirmwareRuntime{}, refuseErr(err, "qemu (pid %d) of %s: cmdline", qemuPid, dom.Name)
	}
	if !argPairEqualFold(argv, "-uuid", uuid) {
		return FirmwareRuntime{}, refuse("qemu (pid %d) of %s: cmdline carries no -uuid %s (stale or reused pid)", qemuPid, dom.Name, uuid)
	}
	if err := checkExe(proc, qemuPid, "qemu", in.QEMU); err != nil {
		return FirmwareRuntime{}, err
	}

	// 2-4. swtpm and its libtpms.
	if dom.TPM {
		pidFile := filepath.Join(p.SwtpmRunDir, libvirtShortName(dom.ID, dom.Name)+"-swtpm.pid")
		swtpmPid, err := readPidFile(pidFile)
		if err != nil {
			return FirmwareRuntime{}, refuseErr(err, "swtpm of %s: pid file", dom.Name)
		}
		argv, err := readCmdline(proc, swtpmPid)
		if err != nil {
			return FirmwareRuntime{}, refuseErr(err, "swtpm (pid %d) of %s: cmdline", swtpmPid, dom.Name)
		}
		stateDir := filepath.Join(p.SwtpmBase, uuid)
		if !swtpmStateDirIs(argv, stateDir) {
			return FirmwareRuntime{}, refuse("swtpm (pid %d) of %s: cmdline does not name the state dir %s", swtpmPid, dom.Name, stateDir)
		}
		if err := checkExe(proc, swtpmPid, "swtpm", in.Swtpm); err != nil {
			return FirmwareRuntime{}, err
		}
		if err := checkLibtpmsMapped(proc, swtpmPid, in.Libtpms); err != nil {
			return FirmwareRuntime{}, err
		}
	}

	// 5. OVMF CODE.
	if dom.Loader != "" {
		if err := checkLoaderOpen(proc, qemuPid, dom.Loader, in.Loaders); err != nil {
			return FirmwareRuntime{}, err
		}
	}
	return in.Runtime, nil
}

// readPidFile reads a libvirt pid file: one positive decimal pid.
func readPidFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("%s: not a pid: %q", path, strings.TrimSpace(string(b)))
	}
	return pid, nil
}

func readCmdline(proc procView, pid int) ([]string, error) {
	b, err := proc.ReadFile(strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"), nil
}

// argPairEqualFold reports whether argv carries flag immediately followed by
// value (case-insensitive value).
func argPairEqualFold(argv []string, flag, value string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag && strings.EqualFold(argv[i+1], value) {
			return true
		}
	}
	return false
}

// swtpmStateDirIs reports whether swtpm's --tpmstate names stateDir or a
// directory below it, in either the "--tpmstate <opts>" or the
// "--tpmstate=<opts>" form. Every --tpmstate must; at least one must exist.
func swtpmStateDirIs(argv []string, stateDir string) bool {
	var opts []string
	for i, a := range argv {
		switch {
		case a == "--tpmstate":
			if i+1 >= len(argv) {
				return false
			}
			opts = append(opts, argv[i+1])
		case strings.HasPrefix(a, "--tpmstate="):
			opts = append(opts, strings.TrimPrefix(a, "--tpmstate="))
		}
	}
	if len(opts) == 0 {
		return false
	}
	for _, o := range opts {
		dir := ""
		for _, kv := range strings.Split(o, ",") {
			if v, ok := strings.CutPrefix(kv, "dir="); ok {
				dir = v
			}
		}
		if dir == "" || dir != filepath.Clean(dir) && filepath.Clean(dir)+"/" != dir {
			return false
		}
		dir = filepath.Clean(dir)
		if dir != stateDir && !strings.HasPrefix(dir, stateDir+"/") {
			return false
		}
	}
	return true
}

// checkExe: /proc/<pid>/exe links to installed (a realpath) without the
// deleted suffix, and stats to the installed file.
func checkExe(proc procView, pid int, what, installed string) error {
	entry := strconv.Itoa(pid) + "/exe"
	target, err := proc.Readlink(entry)
	if err != nil {
		return refuseErr(err, "%s (pid %d): exe", what, pid)
	}
	if strings.HasSuffix(target, deletedSuffix) {
		return refuse("%s (pid %d) runs %s: the binary it was started from is gone", what, pid, target)
	}
	if target != installed {
		return refuse("%s (pid %d) runs %s, the installed binary is %s", what, pid, target, installed)
	}
	if err := sameFile(proc, entry, installed); err != nil {
		return refuseErr(err, "%s (pid %d): exe", what, pid)
	}
	return nil
}

// sameFile requires the file reached through the /proc entry to be the
// installed file (dev, inode).
func sameFile(proc procView, entry, installed string) error {
	running, err := proc.Stat(entry)
	if err != nil {
		return err
	}
	inst, err := os.Stat(installed)
	if err != nil {
		return err
	}
	if !os.SameFile(running, inst) {
		return fmt.Errorf("running file is another inode than the installed %s", installed)
	}
	return nil
}

// checkLibtpmsMapped: swtpm maps the installed libtpms, and every mapping of
// that path is undeleted and the installed (dev, inode).
func checkLibtpmsMapped(proc procView, pid int, installed string) error {
	b, err := proc.ReadFile(strconv.Itoa(pid) + "/maps")
	if err != nil {
		return refuseErr(err, "swtpm (pid %d): read maps for libtpms", pid)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(installed, &st); err != nil {
		return refuseErr(err, "swtpm (pid %d): stat installed libtpms", pid)
	}
	dev := uint64(st.Dev) //nolint:unconvert // Dev is int32 on some unixes
	wantDev := fmt.Sprintf("%02x:%02x", unix.Major(dev), unix.Minor(dev))
	wantIno := strconv.FormatUint(uint64(st.Ino), 10) //nolint:unconvert
	found := 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue // anonymous mapping
		}
		path := strings.Join(f[5:], " ")
		stripped, deleted := strings.CutSuffix(path, deletedSuffix)
		if stripped != installed {
			continue
		}
		if deleted {
			return refuse("swtpm (pid %d) maps libtpms %s: the library it loaded is gone", pid, path)
		}
		if !strings.EqualFold(f[3], wantDev) || f[4] != wantIno {
			return refuse("swtpm (pid %d) maps libtpms %s as dev %s inode %s, the installed file is dev %s inode %s",
				pid, path, f[3], f[4], wantDev, wantIno)
		}
		found++
	}
	if found == 0 {
		return refuse("swtpm (pid %d): no mapping of the installed libtpms %s", pid, installed)
	}
	return nil
}

// checkLoaderOpen: the loader is an installed OVMF CODE file, QEMU holds it
// open, and every fd on it is undeleted and the installed file.
func checkLoaderOpen(proc procView, pid int, loader string, installed []string) error {
	real, err := filepath.EvalSymlinks(loader)
	if err != nil {
		return refuseErr(err, "OVMF CODE %s", loader)
	}
	ok := false
	for _, l := range installed {
		ok = ok || l == real
	}
	if !ok {
		return refuse("OVMF CODE %s (%s) is not an installed OVMF CODE file", loader, real)
	}
	fdDir := strconv.Itoa(pid) + "/fd"
	ents, err := proc.ReadDir(fdDir)
	if err != nil {
		return refuseErr(err, "OVMF CODE: qemu (pid %d): list fd", pid)
	}
	found := 0
	for _, e := range ents {
		entry := fdDir + "/" + e.Name()
		target, err := proc.Readlink(entry)
		if errors.Is(err, fs.ErrNotExist) {
			continue // closed since the listing: not open, so not a match
		}
		if err != nil {
			return refuseErr(err, "OVMF CODE: qemu (pid %d) fd %s", pid, e.Name())
		}
		stripped, deleted := strings.CutSuffix(target, deletedSuffix)
		if stripped != real {
			continue
		}
		if deleted {
			return refuse("OVMF CODE: qemu (pid %d) fd %s is %s: the firmware it loaded is gone", pid, e.Name(), target)
		}
		if err := sameFile(proc, entry, real); err != nil {
			return refuseErr(err, "OVMF CODE: qemu (pid %d) fd %s", pid, e.Name())
		}
		found++
	}
	if found == 0 {
		return refuse("OVMF CODE: qemu (pid %d) has no open fd on %s", pid, real)
	}
	return nil
}
