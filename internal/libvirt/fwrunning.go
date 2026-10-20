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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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
// error, and an error carries a zero value: never a half-read runtime.
func (p *FirmwareCodeProbe) Installed(ctx context.Context) (InstalledFirmwareCode, error) {
	in, err := p.installed(ctx)
	if err != nil {
		return InstalledFirmwareCode{}, err
	}
	return in, nil
}

func (p *FirmwareCodeProbe) installed(ctx context.Context) (InstalledFirmwareCode, error) {
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

// libtpmsSonameRe is the soname link the dynamic linker resolves
// (libtpms.so.<major>); the real file and a dev link are not what it loads.
var libtpmsSonameRe = regexp.MustCompile(`^libtpms\.so\.[0-9]+$`)

// libtpmsRemedy is the operator's way out of an unknown installed libtpms.
const libtpmsRemedy = "remove the stray libtpms copy or run ldconfig; live firmware moves on this host stay refused until exactly one libtpms is installed"

// installedLibtpms is the one real file every libtpms soname link
// (libtpms.so.<major>) in the library dirs resolves to. None, or two different
// files, is an error: which of them a newly exec'd swtpm loads would be a
// guess. One file reached through several dirs (usrmerge: /lib → /usr/lib)
// counts once.
func (p *FirmwareCodeProbe) installedLibtpms() (string, error) {
	seen := map[string]bool{}
	for _, dir := range p.LibDirs {
		ents, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("installed libtpms: %w", err)
		}
		for _, e := range ents {
			if !libtpmsSonameRe.MatchString(e.Name()) {
				continue
			}
			m := filepath.Join(dir, e.Name())
			r, err := filepath.EvalSymlinks(m)
			if err != nil {
				return "", fmt.Errorf("installed libtpms %s: %w; %s", m, err, libtpmsRemedy)
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
		return "", fmt.Errorf("installed libtpms: no libtpms.so.<N> in %s; install libtpms", strings.Join(p.LibDirs, ", "))
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("installed libtpms ambiguous: %s; %s", strings.Join(found, ", "), libtpmsRemedy)
	}
}

// runningDomain is what the check needs of a running domain, read from its
// LIVE definition by runningDomainFromXML: the live id names swtpm's pid file,
// and the devices decide which checks apply. It is not built by hand, so a
// caller cannot skip a check by leaving a field empty.
type runningDomain struct {
	Name   string
	ID     int    // live domain id; 0 when not running
	UUID   string // lower case
	Loader string // <os><loader>; "" for BIOS
	TPM    bool   // any <tpm> device
}

// runningDomainFromXML reads a runningDomain from a domain's live XML.
func runningDomainFromXML(liveXML string) (runningDomain, error) {
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
		return runningDomain{}, fmt.Errorf("parse domain XML: %w", err)
	}
	rd := runningDomain{
		Name:   strings.TrimSpace(d.Name),
		UUID:   strings.ToLower(strings.TrimSpace(d.UUID)),
		Loader: strings.TrimSpace(d.Loader),
		TPM:    len(d.TPM) > 0,
	}
	if d.ID != "" {
		id, err := strconv.Atoi(d.ID)
		if err != nil {
			return runningDomain{}, fmt.Errorf("domain id %q: %w", d.ID, err)
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

// Remedies, one per class of refusal. Every refusal ends with one.
const (
	// The process runs a file that is not the installed one: a package was
	// updated under the running guest (K-4).
	remedyRestart = "the VM still runs code from before a package update; restart it (lv stop, lv start) to load the installed code"
	// /proc could not be read: the daemon lacks root or runs in another pid
	// namespace or container (K-8).
	remedyProc = "the daemon must run as root in the host pid namespace to read /proc (K-8); this is a refusal, not a pass"
	// The pid file does not lead to this domain's process.
	remedyPid = "libvirt's pid file does not lead to this domain's process; check that the VM runs under this host's libvirtd and retry"
	// The domain itself is not in a state the check can read.
	remedyDomain = "only a running domain's live definition can be checked"
	// The host's installed code could not be read.
	remedyHost = "host configuration: the installed QEMU, swtpm, libtpms and OVMF must all be readable"
)

// refuse is a refusal of the running-code check, with its remedy.
func refuse(remedy, format string, args ...any) error {
	return fmt.Errorf("%w: %s; %s", ErrRunningCodeUnverified, fmt.Sprintf(format, args...), remedy)
}

// refuseErr is refuse keeping err in the chain (errors.Is(…, fs.ErrPermission)).
func refuseErr(err error, remedy, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %w; %s", ErrRunningCodeUnverified, fmt.Sprintf(format, args...), err, remedy)
}

// procRemedy is the remedy for a failed /proc read: a permission error is the
// daemon's privilege (K-8); a missing entry means the process is gone or not
// visible here, which is the pid file's problem.
func procRemedy(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return remedyProc
	}
	return remedyPid
}

// RunningFirmwareCode proves that the domain whose LIVE XML (DumpXML of the
// running domain) is liveXML runs this host's installed firmware code, and
// returns the installed runtime as its running one. The checks that apply
// are read from that XML: QEMU always, swtpm and libtpms for a domain with a
// <tpm>, the OVMF CODE for one with a <loader>. Each must find what it looks
// for (spec §3.5):
//
//  1. QEMU: the pid from <QEMURunDir>/<name>.pid, whose cmdline carries
//     "-uuid <uuid>".
//  2. swtpm: the pid from <SwtpmRunDir>/<id>-<name[:20]>-swtpm.pid, whose
//     cmdline's --tpmstate dir is <SwtpmBase>/<uuid> or below it.
//  3. Each exe links to the installed binary's realpath, without the
//     (deleted) suffix, and is the installed file.
//  4. libtpms: swtpm maps the installed libtpms realpath, every such mapping
//     undeleted and, through /proc/<pid>/map_files, the installed file.
//  5. OVMF CODE: the loader is an installed CODE file, and QEMU holds it open
//     by an fd, every such fd undeleted and the installed file.
//
// Each pid's start time is read before its first check and again after its
// last: a pid recycled in between refuses. Any refusal is an
// ErrRunningCodeUnverified with a zero runtime and a remedy.
func (p *FirmwareCodeProbe) RunningFirmwareCode(ctx context.Context, liveXML string) (FirmwareRuntime, error) {
	dom, err := runningDomainFromXML(liveXML)
	if err != nil {
		return FirmwareRuntime{}, refuseErr(err, remedyDomain, "live domain XML")
	}
	return p.runningFirmwareCode(ctx, dom)
}

func (p *FirmwareCodeProbe) runningFirmwareCode(ctx context.Context, dom runningDomain) (FirmwareRuntime, error) {
	if dom.ID <= 0 {
		return FirmwareRuntime{}, refuse(remedyDomain, "domain %s is not running (no live id)", dom.Name)
	}
	if err := safename.ValidateVMName(dom.Name); err != nil {
		return FirmwareRuntime{}, refuse(remedyDomain, "domain name: %v", err)
	}
	uuid := strings.ToLower(dom.UUID)
	if !ValidFirmwareUUID(uuid) {
		return FirmwareRuntime{}, refuse(remedyDomain, "domain %s: invalid uuid %q", dom.Name, dom.UUID)
	}
	in, err := p.Installed(ctx)
	if err != nil {
		return FirmwareRuntime{}, refuseErr(err, remedyHost, "domain %s: installed firmware code unknown", dom.Name)
	}
	proc := p.procfs()

	// 1. QEMU, by the domain's pid file and its -uuid.
	qemuPid, err := readPidFile(filepath.Join(p.QEMURunDir, dom.Name+".pid"))
	if err != nil {
		return FirmwareRuntime{}, refuseErr(err, remedyPid, "qemu of %s: pid file", dom.Name)
	}
	qemuStart, err := pidStartTime(proc, qemuPid)
	if err != nil {
		return FirmwareRuntime{}, refuseErr(err, procRemedy(err), "qemu (pid %d) of %s: stat", qemuPid, dom.Name)
	}
	argv, err := readCmdline(proc, qemuPid)
	if err != nil {
		return FirmwareRuntime{}, refuseErr(err, procRemedy(err), "qemu (pid %d) of %s: cmdline", qemuPid, dom.Name)
	}
	if !argPairEqualFold(argv, "-uuid", uuid) {
		return FirmwareRuntime{}, refuse(remedyPid, "qemu (pid %d) of %s: cmdline carries no -uuid %s (stale or reused pid)", qemuPid, dom.Name, uuid)
	}
	if err := checkExe(proc, qemuPid, "qemu", in.QEMU); err != nil {
		return FirmwareRuntime{}, err
	}

	// 2-4. swtpm and its libtpms.
	if dom.TPM {
		pidFile := filepath.Join(p.SwtpmRunDir, libvirtShortName(dom.ID, dom.Name)+"-swtpm.pid")
		swtpmPid, err := readPidFile(pidFile)
		if err != nil {
			return FirmwareRuntime{}, refuseErr(err, remedyPid, "swtpm of %s: pid file", dom.Name)
		}
		swtpmStart, err := pidStartTime(proc, swtpmPid)
		if err != nil {
			return FirmwareRuntime{}, refuseErr(err, procRemedy(err), "swtpm (pid %d) of %s: stat", swtpmPid, dom.Name)
		}
		argv, err := readCmdline(proc, swtpmPid)
		if err != nil {
			return FirmwareRuntime{}, refuseErr(err, procRemedy(err), "swtpm (pid %d) of %s: cmdline", swtpmPid, dom.Name)
		}
		stateDir := filepath.Join(p.SwtpmBase, uuid)
		if !swtpmStateDirIs(argv, stateDir) {
			return FirmwareRuntime{}, refuse(remedyPid, "swtpm (pid %d) of %s: cmdline does not name the state dir %s", swtpmPid, dom.Name, stateDir)
		}
		if err := checkExe(proc, swtpmPid, "swtpm", in.Swtpm); err != nil {
			return FirmwareRuntime{}, err
		}
		if err := checkLibtpmsMapped(proc, swtpmPid, in.Libtpms); err != nil {
			return FirmwareRuntime{}, err
		}
		if err := samePidStart(proc, swtpmPid, "swtpm", swtpmStart); err != nil {
			return FirmwareRuntime{}, err
		}
	}

	// 5. OVMF CODE.
	if dom.Loader != "" {
		if err := checkLoaderOpen(proc, qemuPid, dom.Loader, in.Loaders); err != nil {
			return FirmwareRuntime{}, err
		}
	}
	if err := samePidStart(proc, qemuPid, "qemu", qemuStart); err != nil {
		return FirmwareRuntime{}, err
	}
	return in.Runtime, nil
}

// pidStartTime is field 22 (starttime) of /proc/<pid>/stat. The comm field
// may hold spaces and parentheses, so the fields are counted after its LAST
// closing parenthesis (field 3 onward).
func pidStartTime(proc procView, pid int) (string, error) {
	b, err := proc.ReadFile(strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return "", fmt.Errorf("/proc/%d/stat: no comm field", pid)
	}
	f := strings.Fields(s[i+1:])
	const startIdx = 22 - 3
	if len(f) <= startIdx {
		return "", fmt.Errorf("/proc/%d/stat: %d fields after comm, want more than %d", pid, len(f), startIdx)
	}
	if _, err := strconv.ParseUint(f[startIdx], 10, 64); err != nil {
		return "", fmt.Errorf("/proc/%d/stat: start time %q: %w", pid, f[startIdx], err)
	}
	return f[startIdx], nil
}

// samePidStart re-reads the pid's start time after its last check. A
// different one means the pid was recycled while it was being read.
func samePidStart(proc procView, pid int, what, before string) error {
	after, err := pidStartTime(proc, pid)
	if err != nil {
		return refuseErr(err, procRemedy(err), "%s (pid %d): stat after the checks", what, pid)
	}
	if after != before {
		return refuse(remedyPid, "%s (pid %d): start time changed from %s to %s while it was checked (pid recycled)", what, pid, before, after)
	}
	return nil
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
// deleted suffix, and is the installed file.
func checkExe(proc procView, pid int, what, installed string) error {
	entry := strconv.Itoa(pid) + "/exe"
	target, err := proc.Readlink(entry)
	if err != nil {
		return refuseErr(err, procRemedy(err), "%s (pid %d): exe", what, pid)
	}
	if strings.HasSuffix(target, deletedSuffix) {
		return refuse(remedyRestart, "%s (pid %d) runs %s: the binary it was started from is gone", what, pid, target)
	}
	if target != installed {
		return refuse(remedyRestart, "%s (pid %d) runs %s, the installed binary is %s", what, pid, target, installed)
	}
	return sameFile(proc, entry, installed, fmt.Sprintf("%s (pid %d): exe", what, pid))
}

// sameFile requires the file reached through the /proc magic link entry to be
// the installed file. Both sides are stat'ed through the VFS, so they agree on
// every filesystem (btrfs and overlayfs included), unlike the dev printed in
// maps.
func sameFile(proc procView, entry, installed, what string) error {
	running, err := proc.Stat(entry)
	if err != nil {
		return refuseErr(err, procRemedy(err), "%s: stat %s", what, entry)
	}
	inst, err := os.Stat(installed)
	if err != nil {
		return refuseErr(err, remedyHost, "%s: stat installed %s", what, installed)
	}
	if !os.SameFile(running, inst) {
		return refuse(remedyRestart, "%s: the running file is another inode than the installed %s", what, installed)
	}
	return nil
}

// mapFilesName is the /proc/<pid>/map_files entry of a maps range: the kernel
// names it "%lx-%lx", without the zero padding maps uses.
func mapFilesName(rng string) (string, error) {
	lo, hi, ok := strings.Cut(rng, "-")
	if !ok {
		return "", fmt.Errorf("maps range %q", rng)
	}
	a, err := strconv.ParseUint(lo, 16, 64)
	if err != nil {
		return "", fmt.Errorf("maps range %q: %w", rng, err)
	}
	b, err := strconv.ParseUint(hi, 16, 64)
	if err != nil {
		return "", fmt.Errorf("maps range %q: %w", rng, err)
	}
	return fmt.Sprintf("%x-%x", a, b), nil
}

// checkLibtpmsMapped: swtpm maps the installed libtpms, and every mapping of
// that path is undeleted and, stat'ed through /proc/<pid>/map_files, the
// installed file. map_files needs CAP_SYS_ADMIN (the daemon runs as root,
// K-8); any failure to stat it refuses.
func checkLibtpmsMapped(proc procView, pid int, installed string) error {
	b, err := proc.ReadFile(strconv.Itoa(pid) + "/maps")
	if err != nil {
		return refuseErr(err, procRemedy(err), "swtpm (pid %d): read maps for libtpms", pid)
	}
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
			return refuse(remedyRestart, "swtpm (pid %d) maps libtpms %s: the library it loaded is gone", pid, path)
		}
		name, err := mapFilesName(f[0])
		if err != nil {
			return refuseErr(err, remedyProc, "swtpm (pid %d) maps libtpms: unreadable map_files range", pid)
		}
		entry := strconv.Itoa(pid) + "/map_files/" + name
		running, err := proc.Stat(entry)
		if err != nil {
			return refuseErr(err, remedyProc, "swtpm (pid %d) maps libtpms: stat map_files/%s", pid, name)
		}
		inst, err := os.Stat(installed)
		if err != nil {
			return refuseErr(err, remedyHost, "swtpm (pid %d): stat installed libtpms %s", pid, installed)
		}
		if !os.SameFile(running, inst) {
			return refuse(remedyRestart, "swtpm (pid %d) maps libtpms %s (map_files/%s) from another inode than the installed file", pid, path, name)
		}
		found++
	}
	if found == 0 {
		return refuse(remedyRestart, "swtpm (pid %d): no mapping of the installed libtpms %s", pid, installed)
	}
	return nil
}

// checkLoaderOpen: the loader is an installed OVMF CODE file, QEMU holds it
// open, and every fd on it is undeleted and the installed file.
func checkLoaderOpen(proc procView, pid int, loader string, installed []string) error {
	real, err := filepath.EvalSymlinks(loader)
	if err != nil {
		return refuseErr(err, remedyHost, "OVMF CODE %s", loader)
	}
	ok := false
	for _, l := range installed {
		ok = ok || l == real
	}
	if !ok {
		return refuse(remedyRestart, "OVMF CODE %s (%s) is not an installed OVMF CODE file", loader, real)
	}
	fdDir := strconv.Itoa(pid) + "/fd"
	ents, err := proc.ReadDir(fdDir)
	if err != nil {
		return refuseErr(err, procRemedy(err), "OVMF CODE: qemu (pid %d): list fd", pid)
	}
	found := 0
	for _, e := range ents {
		entry := fdDir + "/" + e.Name()
		target, err := proc.Readlink(entry)
		if errors.Is(err, fs.ErrNotExist) {
			continue // closed since the listing: not open, so not a match
		}
		if err != nil {
			return refuseErr(err, procRemedy(err), "OVMF CODE: qemu (pid %d) fd %s", pid, e.Name())
		}
		stripped, deleted := strings.CutSuffix(target, deletedSuffix)
		if stripped != real {
			continue
		}
		if deleted {
			return refuse(remedyRestart, "OVMF CODE: qemu (pid %d) fd %s is %s: the firmware it loaded is gone", pid, e.Name(), target)
		}
		if err := sameFile(proc, entry, real, fmt.Sprintf("OVMF CODE: qemu (pid %d) fd %s", pid, e.Name())); err != nil {
			return err
		}
		found++
	}
	if found == 0 {
		return refuse(remedyRestart, "OVMF CODE: qemu (pid %d) has no open fd on %s", pid, real)
	}
	return nil
}
