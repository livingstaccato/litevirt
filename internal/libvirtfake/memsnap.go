package libvirtfake

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// Memory snapshots. CreateLiveSnapshot runs the production capture
// (libvirt.CaptureMemorySnapshot) over captureAPI, a model of the libvirt
// calls it makes, so a scenario exercises the real variant choice, deadline
// and resume handling. The model follows libvirt v10.0.0
// src/qemu/qemu_snapshot.c at the v10.0.0 tag
// (qemuSnapshotCreateXMLValidateDef 1533-1539,
// qemuSnapshotCreateActiveExternal 1287-1480):
//
//   - VIR_DOMAIN_SNAPSHOT_CREATE_LIVE is refused unless the domain is active
//     and the memory location is external;
//   - a domain RUNNING when the snapshot begins is resumed when it ends;
//     without LIVE its vCPUs are stopped first; with LIVE the guest runs
//     while RAM is precopied, and its vCPUs stop only for the remainder;
//   - a domain PAUSED when it begins is left paused;
//   - a suspend during the memory write is admitted.
//
// Time is a fake clock per fake, advanced by the model: writing all of RAM
// takes RAMBytes/WriteBps. Every capture writes a real vmstate artifact at
// its path, derived from the domain's memory generation, and a revert reads
// it back (a missing one fails the revert, as libvirt's restore does).

// MemoryModel is how the fake's QEMU behaves for a domain's memory
// snapshots. Zero fields take the defaults: 1 GiB of RAM, written at
// 1 GiB/s, a guest that dirties nothing.
type MemoryModel struct {
	RAMBytes uint64
	WriteBps float64
	// DirtyBps is how fast the guest really dirties memory while it runs.
	DirtyBps float64
	// ReportBps is what a dirty-rate calculation reports; < 0 makes it fail.
	ReportBps float64
	// IgnoreAbort: an abort of a LIVE capture succeeds but the job runs on
	// (a QEMU that does not act on migrate_cancel in time).
	IgnoreAbort bool
	// AbortBlock, when set, holds every DomainAbortJob until it is closed:
	// libvirt does not answer the abort (its job lock held by a stuck call,
	// or the connection wedged).
	AbortBlock chan struct{}
	// AbortDelay is how long libvirt takes to answer a DomainAbortJob (the
	// job's cancel and cleanup); the job ends when the answer comes.
	AbortDelay time.Duration
}

// PauseWindow is one stretch of fake time the guest's vCPUs were stopped.
type PauseWindow struct {
	Start, End time.Duration
}

// Len is the window's duration.
func (w PauseWindow) Len() time.Duration { return w.End - w.Start }

// CaptureCall is one modelled virDomainSnapshotCreateXML of a full-system
// snapshot.
type CaptureCall struct {
	Flags        uint32
	Memory       string // the external memory file
	PausedBefore bool   // the vCPUs were stopped when it began
	// SuspendedDuring: a suspend arrived while a LIVE capture ran.
	SuspendedDuring bool
}

// Live reports whether the call asked for a live capture.
func (c CaptureCall) Live() bool { return c.Flags&uint32(golibvirt.DomainSnapshotCreateLive) != 0 }

// memState is the fake's per-domain memory-snapshot model. Guarded by f.mu.
type memState struct {
	model      MemoryModel
	gen        int           // memory generation: bumps on every start and capture
	qemuStarts int           // QEMU processes started: starts and restores
	stoppedAt  time.Duration // < 0 while the vCPUs run
	pauses     []PauseWindow
	captures   []CaptureCall
	liveJob    chan struct{} // set while a non-converging LIVE capture waits
	suspended  bool          // a suspend arrived during liveJob
	jobAbort   chan struct{} // closed by DomainAbortJob during liveJob
}

func (f *Fake) memLocked(name string) *memState {
	if f.mem == nil {
		f.mem = map[string]*memState{}
	}
	m := f.mem[name]
	if m == nil {
		m = &memState{stoppedAt: -1}
		f.mem[name] = m
	}
	return m
}

// SetMemoryModel sets how a domain's QEMU behaves for memory snapshots.
func (f *Fake) SetMemoryModel(name string, mm MemoryModel) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.memLocked(name).model = mm
}

// PauseWindows returns the stretches of fake time the domain's vCPUs were
// stopped by memory snapshot captures.
func (f *Fake) PauseWindows(name string) []PauseWindow {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]PauseWindow(nil), f.memLocked(name).pauses...)
}

// QEMUStarts returns how many QEMU processes the domain has had: every start
// and every restore of a saved image starts a new one. A capture in the
// running process leaves it unchanged.
func (f *Fake) QEMUStarts(name string) int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.memLocked(name).qemuStarts
}

// MemoryGeneration returns the domain's guest-memory generation: it bumps on
// every start and capture, and a revert restores the one its image holds.
func (f *Fake) MemoryGeneration(name string) int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.memLocked(name).gen
}

// LiveJobRunning reports whether a LIVE capture of the domain is in its
// memory write, waiting to converge.
func (f *Fake) LiveJobRunning(name string) bool {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.memLocked(name).liveJob != nil
}

// Captures returns the full-system snapshot calls the domain's captures made.
func (f *Fake) Captures(name string) []CaptureCall {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]CaptureCall(nil), f.memLocked(name).captures...)
}

func (m *memState) ram() uint64 {
	if m.model.RAMBytes == 0 {
		return 1 << 30
	}
	return m.model.RAMBytes
}

func (m *memState) writeTime(bytes float64) time.Duration {
	bps := m.model.WriteBps
	if bps <= 0 {
		bps = 1 << 30
	}
	return time.Duration(bytes / bps * float64(time.Second))
}

// stop and run move the domain's vCPUs and keep the fake clock's pause
// windows. Caller holds f.mu.
func (f *Fake) stopCPUsLocked(name string) {
	if f.domains[name] != StateRunning {
		return
	}
	f.domains[name] = StatePaused
	m := f.memLocked(name)
	if m.stoppedAt < 0 {
		m.stoppedAt = f.memClock
	}
}

func (f *Fake) runCPUsLocked(name string) {
	f.domains[name] = StateRunning
	f.markRanLocked(name)
	m := f.memLocked(name)
	if m.stoppedAt >= 0 {
		m.pauses = append(m.pauses, PauseWindow{Start: m.stoppedAt, End: f.memClock})
	}
	m.stoppedAt = -1
}

// vmstateArtifact is the content of a capture's image: the domain and the
// memory generation it holds.
func vmstateArtifact(domain string, gen int) []byte {
	return []byte(fmt.Sprintf("libvirtfake-vmstate domain=%s gen=%d\n", domain, gen))
}

var vmstateGenRe = regexp.MustCompile(`^libvirtfake-vmstate domain=(\S+) gen=(\d+)\n$`)

// readVMState reads a capture's image back: the memory generation it holds.
func readVMState(path, domain string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("libvirtfake: Failed to open domain image file '%s': %w", path, err)
	}
	m := vmstateGenRe.FindSubmatch(b)
	if m == nil {
		// An image the fake did not write (a test's placeholder, an older
		// node's save): restorable, generation unknown.
		return -1, nil
	}
	if string(m[1]) != domain {
		return 0, fmt.Errorf("libvirtfake: image %s holds domain %s, not %s", path, m[1], domain)
	}
	return strconv.Atoi(string(m[2]))
}

// captureAPI is libvirt.LiveCaptureAPI over the fake, for one capture.
type captureAPI struct{ f *Fake }

var _ libvirt.LiveCaptureAPI = captureAPI{}

func (c captureAPI) DomainLookupByName(name string) (golibvirt.Domain, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if st, ok := c.f.domains[name]; !ok || st == StateNoDomain {
		return golibvirt.Domain{}, golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "Domain not found: " + name}
	}
	return golibvirt.Domain{Name: name}, nil
}

func (c captureAPI) DomainGetState(dom golibvirt.Domain, _ uint32) (int32, int32, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	switch c.f.domains[dom.Name] {
	case StateRunning:
		return int32(golibvirt.DomainRunning), 0, nil
	case StatePaused:
		return int32(golibvirt.DomainPaused), 0, nil
	}
	return int32(golibvirt.DomainShutoff), 0, nil
}

func (c captureAPI) DomainGetXMLDesc(dom golibvirt.Domain, _ golibvirt.DomainXMLFlags) (string, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	x := c.f.liveXMLLocked(dom.Name)
	if strings.TrimSpace(x) == "" {
		// libvirt always has a definition for a domain it knows.
		x = "<domain><name>" + dom.Name + "</name></domain>"
	}
	m := c.f.memLocked(dom.Name)
	if !memoryElemRe.MatchString(x) && m.model.RAMBytes > 0 {
		// The model's RAM, where the definition does not give it.
		mem := fmt.Sprintf("<memory unit='KiB'>%d</memory>", m.model.RAMBytes/1024)
		if i := strings.Index(x, "</name>"); i >= 0 {
			x = x[:i+len("</name>")] + mem + x[i+len("</name>"):]
		} else {
			x = "<domain><name>" + dom.Name + "</name>" + mem + "</domain>"
		}
	}
	if srcs := c.f.diskSources[dom.Name]; len(srcs) > 0 && !strings.Contains(x, "<disk") {
		// The live disk sources a test set (SetDiskSource), as libvirt
		// shows them: on their overlays once a capture switched them.
		var b strings.Builder
		for _, dev := range sortedKeys(srcs) {
			fmt.Fprintf(&b, "<disk type='file' device='disk'><source file='%s'/><target dev='%s'/></disk>", srcs[dev], dev)
		}
		if i := strings.Index(x, "</devices>"); i >= 0 {
			x = x[:i] + b.String() + x[i:]
		} else if i := strings.LastIndex(x, "</domain>"); i >= 0 {
			x = x[:i] + "<devices>" + b.String() + "</devices>" + x[i:]
		}
	}
	return x, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var memoryElemRe = regexp.MustCompile(`<memory[\s>]`)

func (c captureAPI) DomainListAllSnapshots(dom golibvirt.Domain, _ int32, _ uint32) ([]golibvirt.DomainSnapshot, int32, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	var out []golibvirt.DomainSnapshot
	for n := range c.f.snapshots[dom.Name] {
		out = append(out, golibvirt.DomainSnapshot{Name: n, Dom: dom})
	}
	return out, int32(len(out)), nil
}

var fakeMemoryFileRe = regexp.MustCompile(`<memory\s+snapshot=['"]external['"]\s+file=['"]([^'"]+)['"]`)
var fakeSnapNameRe = regexp.MustCompile(`<name>([^<]*)</name>`)

// DomainSnapshotCreateXML models a full-system external snapshot of an
// active domain (the only kind a capture takes).
func (c captureAPI) DomainSnapshotCreateXML(dom golibvirt.Domain, x string, flags uint32) (golibvirt.DomainSnapshot, error) {
	f := c.f
	name := dom.Name
	live := flags&uint32(golibvirt.DomainSnapshotCreateLive) != 0
	f.mu.Lock()
	st := f.domains[name]
	mm := fakeMemoryFileRe.FindStringSubmatch(x)
	active := st == StateRunning || st == StatePaused
	if live && (!active || len(mm) < 2) {
		f.mu.Unlock()
		return golibvirt.DomainSnapshot{}, errors.New("Operation not supported: live snapshot creation is supported only during full system snapshots")
	}
	if !active || len(mm) < 2 || flags&uint32(golibvirt.DomainSnapshotCreateDiskOnly) != 0 {
		f.mu.Unlock()
		return golibvirt.DomainSnapshot{}, fmt.Errorf("libvirtfake: a capture takes an external memory snapshot of an active domain (flags %#x)", flags)
	}
	// libvirt's own refusal (qemuMigrationSrcIsAllowed), reached only when the
	// capture's preflight is bypassed: before any state changes.
	if b, berr := libvirt.MemorySnapshotBlockers(f.liveXMLLocked(name)); berr == nil && len(b) > 0 {
		f.mu.Unlock()
		return golibvirt.DomainSnapshot{}, errors.New("Requested operation is not valid: cannot migrate a domain with <hostdev mode='subsystem' type='pci'>")
	}
	file := mm[1]
	snapName := ""
	if n := fakeSnapNameRe.FindStringSubmatch(x); n != nil {
		snapName = n[1]
	}
	if _, ok := f.snapshots[name][snapName]; ok {
		f.mu.Unlock()
		return golibvirt.DomainSnapshot{}, fmt.Errorf("libvirtfake: snapshot %q exists", snapName)
	}
	m := f.memLocked(name)
	call := CaptureCall{Flags: flags, Memory: file, PausedBefore: st != StateRunning}
	resume := st == StateRunning
	if resume && !live {
		f.stopCPUsLocked(name)
	}
	remaining := float64(m.ram())
	if live && f.domains[name] == StateRunning {
		set := remaining
		converged := false
		for i := 0; i < 64; i++ {
			pass := m.writeTime(set)
			f.memClock += pass
			next := m.model.DirtyBps * pass.Seconds()
			if next > float64(m.ram()) {
				next = float64(m.ram())
			}
			set = next
			if m.writeTime(set) <= 300*time.Millisecond { // QEMU's default downtime-limit
				converged = true
				break
			}
		}
		if !converged {
			ch, ab := make(chan struct{}), make(chan struct{})
			m.liveJob, m.suspended, m.jobAbort = ch, false, ab
			f.mu.Unlock()
			aborted := false
			select {
			case <-ch:
			case <-ab:
				aborted = true
			case <-time.After(30 * time.Second):
			}
			f.mu.Lock()
			m.liveJob, m.jobAbort = nil, nil
			if aborted {
				// migrate_cancel: nothing written; libvirt's cleanup
				// resumes a guest that was running.
				if resume {
					f.runCPUsLocked(name)
				}
				f.mu.Unlock()
				return golibvirt.DomainSnapshot{}, errors.New("operation aborted: snapshot job: canceled by client")
			}
			if !m.suspended {
				f.mu.Unlock()
				return golibvirt.DomainSnapshot{}, errors.New("libvirtfake: the live capture never converged and nothing suspended the guest")
			}
			call.SuspendedDuring = true
		}
		remaining = set
		f.stopCPUsLocked(name) // QEMU stops the vCPUs at switch-over
	}
	f.memClock += m.writeTime(remaining)
	m.gen++
	if err := os.WriteFile(file, vmstateArtifact(name, m.gen), 0o600); err != nil {
		if resume {
			f.runCPUsLocked(name)
		}
		f.mu.Unlock()
		return golibvirt.DomainSnapshot{}, fmt.Errorf("libvirtfake: write memory image: %w", err)
	}
	m.captures = append(m.captures, call)
	// The disks switch over after the memory is written.
	if f.snapshots[name] == nil {
		f.snapshots[name] = map[string]struct{}{}
	}
	f.snapshots[name][snapName] = struct{}{}
	f.cutoverDisks(name, snapName)
	f.record("snapshot-live", name, snapName)
	hook := f.FailCreateLiveSnapshot
	f.mu.Unlock()
	var herr error
	if hook != nil {
		herr = hook(name, snapName)
	}
	if resume {
		f.mu.Lock()
		f.runCPUsLocked(name)
		f.mu.Unlock()
	}
	if herr != nil {
		return golibvirt.DomainSnapshot{}, herr
	}
	return golibvirt.DomainSnapshot{Name: snapName, Dom: dom}, nil
}

// DomainAbortJob cancels a LIVE capture's memory write; with no job it is
// refused, as libvirt does.
func (c captureAPI) DomainAbortJob(dom golibvirt.Domain) error {
	c.f.mu.Lock()
	block, delay := c.f.memLocked(dom.Name).model.AbortBlock, c.f.memLocked(dom.Name).model.AbortDelay
	c.f.mu.Unlock()
	if block != nil {
		<-block
	}
	time.Sleep(delay)
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	m := c.f.memLocked(dom.Name)
	if m.jobAbort == nil {
		return errors.New("Requested operation is not valid: no job is active on the domain")
	}
	if m.model.IgnoreAbort {
		return nil
	}
	close(m.jobAbort)
	m.jobAbort = nil
	return nil
}

// DomainSaveImageGetXMLDesc and DomainSaveImageDefineXML read and replace
// the definition a capture's image carries (SetSavedImageXML's map).
func (c captureAPI) DomainSaveImageGetXMLDesc(file string, _ uint32) (string, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if _, err := os.Stat(file); err != nil {
		return "", fmt.Errorf("libvirtfake: no saved image %s: %w", file, err)
	}
	if x, ok := c.f.savedImageXML[file]; ok {
		return x, nil
	}
	return c.f.liveXMLLocked(fakeDomainOfImage(file)), nil
}

func (c captureAPI) DomainSaveImageDefineXML(file, dxml string, _ uint32) error {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if _, err := os.Stat(file); err != nil {
		return fmt.Errorf("libvirtfake: no saved image %s: %w", file, err)
	}
	if c.f.savedImageXML == nil {
		c.f.savedImageXML = map[string]string{}
	}
	c.f.savedImageXML[file] = dxml
	return nil
}

// fakeDomainOfImage is the domain a fake capture's image holds ("" when
// unreadable).
func fakeDomainOfImage(file string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	if m := vmstateGenRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

func (c captureAPI) DomainSuspend(dom golibvirt.Domain) error {
	f := c.f
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[dom.Name]
	if !ok || (st != StateRunning && st != StatePaused) {
		return fmt.Errorf("libvirtfake: domain %q is not running", dom.Name)
	}
	f.stopCPUsLocked(dom.Name)
	f.record("suspend", dom.Name, "")
	m := f.memLocked(dom.Name)
	if m.liveJob != nil {
		m.suspended = true
		close(m.liveJob)
		m.liveJob = nil
	}
	return nil
}

func (c captureAPI) DomainResume(dom golibvirt.Domain) error {
	f := c.f
	if f.FailResumeDomain != nil {
		if err := f.FailResumeDomain(dom.Name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	if f.domains[dom.Name] != StatePaused {
		st := f.domains[dom.Name]
		f.mu.Unlock()
		return fmt.Errorf("libvirtfake: domain %q is not paused (%s)", dom.Name, st)
	}
	f.runCPUsLocked(dom.Name)
	f.record("resume", dom.Name, "")
	f.flushPendingNvramLocked(dom.Name)
	f.mu.Unlock()
	f.running(dom.Name)
	return nil
}

// CaptureSleep is the capture's wait for a dirty-rate result, on the fake
// clock.
func (c captureAPI) CaptureSleep(d time.Duration) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.memClock += d
}

func (c captureAPI) DomainGetBlockInfo(golibvirt.Domain, string, uint32) (uint64, uint64, uint64, error) {
	return 4 << 20, 0, 0, nil
}

func (c captureAPI) DomainStartDirtyRateCalc(dom golibvirt.Domain, _ int32, _ uint32) error {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if c.f.memLocked(dom.Name).model.ReportBps < 0 {
		return errors.New("Operation not supported: dirty rate calculation")
	}
	return nil
}

func (c captureAPI) ConnectGetAllDomainStats(doms []golibvirt.Domain, _ uint32, _ uint32) ([]golibvirt.DomainStatsRecord, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	var out []golibvirt.DomainStatsRecord
	for _, d := range doms {
		r := c.f.memLocked(d.Name).model.ReportBps
		if r < 0 {
			return nil, errors.New("Operation not supported: dirty rate")
		}
		out = append(out, golibvirt.DomainStatsRecord{Dom: d, Params: []golibvirt.TypedParam{
			{Field: golibvirt.DomainStatsDirtyrateCalcStatus, Value: golibvirt.TypedParamValue{D: 1, I: int32(2)}},
			{Field: golibvirt.DomainStatsDirtyrateMegabytesPerSecond, Value: golibvirt.TypedParamValue{D: 3, I: int64(r / (1 << 20))}},
		}})
	}
	return out, nil
}
