// Package libvirtfake is an in-memory implementation of
// grpcapi.LibvirtBackend for tests and harnesses. It tracks domain
// state in maps, no qemu processes are launched, no XML is parsed
// beyond minimal name extraction.
//
// Scenarios that need to assert on domain lifecycle (e.g. "VM was
// started after CreateVM" or "ShutdownDomain happened during drain")
// inspect Fake.State / Fake.Events / Fake.SnapshotsOf directly.
//
// The fake is deliberately permissive: any method that doesn't have
// an explicit override returns nil. If a scenario needs to observe
// failure-injection, set the corresponding Fail* field. The harness
// stays small by leaning on this default-success-with-overrides
// pattern.
package libvirtfake

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/xml"
	"errors"
	"fmt"
	golibvirt "github.com/digitalocean/go-libvirt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/nictap"
)

// State describes a single domain's lifecycle. Mirrors what
// libvirt.Client.DomainState would return.
type State string

const (
	StateDefined  State = "shutoff" // defined but not started
	StateRunning  State = "running"
	StateShutdown State = "shutoff"
	StateNoDomain State = "no-domain"
	// StatePaused is an ACTIVE domain that is not executing. It exists so a
	// scenario can model libvirt's coarse-state trap: DomainState reports a
	// paused domain as "stopped" (libvirt.coarseDomainState folds DomainPaused
	// and DomainPmsuspended in with DomainShutoff), yet the domain has a LIVE
	// instance whose XML can carry devices the persistent config does not.
	StatePaused State = "paused"
)

// Event captures an interesting transition for scenario asserts.
// Recorded in Fake.Events in the order operations arrived.
type Event struct {
	Op     string // "define" | "start" | "shutdown" | "destroy" | "undefine" | "snapshot" | ...
	Domain string
	Note   string // free-form ("xml=...", "snapshot=foo")
	When   time.Time
}

// Fake satisfies grpcapi.LibvirtBackend.
type Fake struct {
	execStdout, execStderr string
	execExitCode           int32
	mu                     sync.Mutex
	gate                   daemonGate // the daemon's calls pass it (sever.go)
	domains                map[string]State
	xml                    map[string]string
	activeXML              map[string]string              // domain → live-view override (see DumpXML)
	snapshots              map[string]map[string]struct{} // domain → snapshot names
	diskSources            map[string]map[string]string   // domain → target-dev → source file
	pitOn                  map[string]string              // point-in-time overlay → domain on it (pit_snapshot.go)
	pitSnapErr             error
	pitCommitErr           error
	stats                  map[string]*libvirt.DomainStats
	reasons                map[string]string // domain → injected DomainStateReason.Reason
	managedSave            map[string]bool   // domain → has a managed-save (suspend-to-disk) image
	ownerEpochs            map[string]int64  // domain → Phase 4 owner-epoch metadata marker
	managed                map[string]bool   // domain → litevirt managed-stamp metadata
	managedInc             map[string]string // domain → the managed stamp's incarnation attribute
	events                 []Event

	// Console passwords (libvirt.Client.SetConsolePasswordPolicy): the policy
	// DefineDomain applies, and the passwords each running guest STARTED
	// with (domain → kind → password), which a redefine does not change.
	consolePolicy  func() libvirt.ConsolePolicy
	vncUnavailable string // SetVNCPasswordUnavailable
	spiceUnusable  string // SetSpiceUnusable
	liveConsolePw  map[string]map[string]string
	vncPorts       map[string]int    // domain → VNC port (SetVNCPort); default 5901
	spicePorts     map[string]int    // SetSpicePort
	consolePTYs    map[string]string // SetConsolePTYPath

	// starts counts each domain's StartDomain calls, and taps holds the host
	// device each NIC was given in one of those runs (keyed by domain, run and
	// lower-cased MAC). nextTap is the host-wide vnetN counter. Together they
	// model what libvirt does: a NIC gets the next free vnetN when the domain
	// starts, so the same NIC has a different tap after a stop and start.
	starts  map[string]int
	taps    map[tapKey]string
	nextTap int

	// eventCB is the domain lifecycle callback registered by
	// RegisterDomainEventCallback; nil until something registers. FireEvent
	// delivers to it. Guarded by f.mu.
	eventCB libvirt.DomainEventCallback

	// secrets models libvirt's secret store: UUID → ceph secret. Guarded by f.mu.
	secrets map[string]fakeSecret

	// bridgeMTU is each bridge's MTU on this node (SetBridgeMTU). Guarded by f.mu.
	bridgeMTU map[string]int
	// bridgeMTUErr fails the read of a bridge's MTU (FailBridgeMTU). Guarded by f.mu.
	bridgeMTUErr map[string]error

	// Optional time source for events. Defaults to time.Now.
	Now func() time.Time

	// attachDiskN / detachDiskN count disk hot-plug primitive calls so at-most-once
	// tests can assert exactly one libvirt attach/detach happened for one operation.
	attachDiskN int
	detachDiskN int
	// attachNICN / detachNICN are the NIC-hotplug equivalent.
	attachNICN int
	detachNICN int
	// attachHostdevN / detachHostdevN count PCI passthrough hot-plug primitive calls
	// (both the plain and alias-carrying attach) so at-most-once tests can assert
	// exactly one libvirt hostdev attach/detach happened per member per operation.
	attachHostdevN int
	detachHostdevN int
	// detachHostdevConfigN counts CONFIG-only hostdev detaches (DetachHostdevConfig) so a
	// test can prove the shut-off reclaim took the config path, NOT the live one.
	detachHostdevConfigN int

	// comparedCPUXML / comparedMachines record every CompareCPU argument pair
	// (see ComparedCPUXML, ComparedMachines).
	comparedCPUXML   []string
	comparedMachines []string

	// CPUCompareResult overrides CompareCPU's verdict; nil = Superset (this host
	// can run anything). HostCPUModel names the model HostCPUXML reports.
	CPUCompareResult *libvirt.CPUCompare
	HostCPUModel     string
	// HostModelFeatures, when set, models this host's hypervisor: it is the
	// feature list its domcapabilities host-model reports (HostModelCPUFeatures;
	// nil = no host-model to report, an error), and (with CPUCompareResult nil)
	// CompareCPU answers by it — incompatible as soon as
	// the compared CPU requires a feature not on the list, identical otherwise.
	// That is how libvirt's hypervisor compare treats a live host-model CPU.
	HostModelFeatures []string

	// Fail* hooks let scenarios inject failures into specific methods.
	// Nil = default success.
	FailCompareCPU   func(cpuXML string) error
	FailHostCPUXML   func() error
	FailDefineDomain func(xml string) error
	FailStartDomain  func(name string) error
	// FillDefine, when set, rewrites a definition as DefineDomain stores it:
	// what libvirt fills in at define, such as the vars path of a UEFI domain.
	FillDefine func(xml string) string
	// startGuard mirrors libvirt.Client.SetStartGuard; guardReady and
	// guardWait mirror RequireStartGuard.
	startGuard libvirt.StartGuard
	guardSet   bool
	guardReady chan struct{}
	guardWait  time.Duration
	guardNeeds func(name string) bool
	// fwGuard mirrors libvirt.Client.SetFirmwareMoveGuard: every start,
	// resume, stop, define and undefine asks it first, as the client does.
	fwGuard libvirt.FirmwareMoveGuard
	// fwStore is the host's firmware store (SetFirmwareStore): the files
	// the libvirt model in firmware_live.go acts on. nil: no firmware state.
	fwStore *libvirt.FirmwareStore
	// pendingNvram is, per migrated-in guest that has not resumed yet, the
	// source's final NVRAM its QEMU writes to the file on resume (probe
	// (d)). offReason is the shut-off reason the model gave a domain
	// (migrated, or a ShutOffDomain reason); a start clears it.
	pendingNvram map[string][]byte
	offReason    map[string]string
	// ioPaused names the paused domains PauseOnIOError paused: QEMU's own
	// pause on a failed disk write, reported with PausedReason io-error.
	// Any other state change of the domain forgets it.
	ioPaused map[string]bool
	// ppMark is the partition-pause mark (MarkPartitionPaused), live only:
	// it holds for the run it was set in (starts) while the domain is active.
	ppMark map[string]ppMark

	// imageLocks is the shared-storage image-lock registry this fake joined
	// (image_lock.go); nil models storage with no cross-host locking.
	imageLocks *ImageLocks
	// pendingPermall is, per migrated-in TPM guest that has not resumed
	// yet, the uuid whose permall its swtpm writes back once it runs.
	pendingPermall map[string]string
	// Firmware move knobs (spec §15). CorruptLandedPermall makes
	// LandFirmwareLive on this (target) fake write an altered permall.
	// FailAfterTargetTree fails LandFirmwareLive once the target's swtpm
	// tree exists, before any domain is defined here. ReportSourceReasonUnknown
	// makes this (source) fake report reason unknown, not migrated, for the
	// shut-off a FirmwareLive migrate leaves; it is called under the fake's
	// lock and must not call the fake.
	CorruptLandedPermall      func(name string) bool
	FailAfterTargetTree       func(name string) error
	ReportSourceReasonUnknown func(name string) bool
	// OnRunning, when set, is called (outside the fake's lock) each time a
	// domain starts running: a start, a resume, a migration that lands it
	// running (LandMigratedState), and SetState into running. A scenario
	// samples what is in force at the moment a guest runs.
	OnRunning func(name string)
	// OnMigrateToTarget, when set, runs inside MigrateToTarget after it is
	// recorded, with the parameters libvirt was given; a scenario uses it to
	// land the domain on the target's fake.
	OnMigrateToTarget func(name, dconnuri string, p libvirt.MigrateParams) error
	// JobActive, when set, answers DomainJobActive (a migration job a test
	// has running on the domain). Set it under no lock the test holds.
	JobActive func(name string) (bool, error)
	// IgnoreShutdown makes ShutdownDomain a guest that ignores the ACPI
	// request when it returns true: the call succeeds, the domain keeps
	// running, and WaitForShutdown times out.
	IgnoreShutdown func(name string) bool
	// ShutdownLate makes ShutdownDomain a guest slower than its stop timeout
	// when it returns true: the domain keeps running through the first
	// WaitForShutdown, which times out, and is shut off by the second.
	ShutdownLate func(name string) bool
	lateWaits    map[string]int
	// FailSuspendDomain / FailResumeDomain inject a pause/resume failure
	// (partition pause, docs/design/partition-pause.md §3.4).
	FailSuspendDomain func(name string) error
	FailResumeDomain  func(name string) error
	// FailKillPartitionPaused fails KillPartitionPaused (a missing or
	// foreign pid file).
	FailKillPartitionPaused func(name string) error
	// FailMarkPartitionPaused / FailClearPartitionPauseMark inject a failure
	// to set or remove the partition-pause mark.
	FailMarkPartitionPaused     func(name string) error
	FailClearPartitionPauseMark func(name string) error
	// FailListDomains makes domain enumeration fail — the shape of a libvirtd
	// outage, which marks the host's runtime inventory INCOMPLETE and must
	// refuse new residency at admission time.
	FailListDomains func() error
	// FailAttachDisk / FailDetachDisk inject a live disk hot-plug primitive failure so
	// scenarios can exercise attach-rollback / detach-forward compensation.
	FailAttachDisk func(domain, path, targetDev, bus string) error
	FailDetachDisk func(domain, targetDev string) error
	// FailAttachNIC / FailDetachNIC are the NIC-hotplug equivalent.
	FailAttachNIC func(domain, bridge, model, mac string) error
	FailDetachNIC func(domain, mac string) error
	// FailReloadCDROM injects a live cdrom media reload failure.
	FailReloadCDROM func(domain, path string) error
	// SkipConfigOnDiskMutation, when true, makes AttachDisk/DetachDisk update ONLY the
	// live view (diskSources) and NOT the persistent (inactive) config — modeling a
	// libvirt DomainDeviceModifyLive-succeeded-but-Config-not-applied divergence so a
	// both-state (live+persistent) verification can be exercised.
	SkipConfigOnDiskMutation bool
	// SkipConfigOnNICMutation is the NIC-hotplug equivalent: AttachNIC/DetachNIC
	// update ONLY the live view (activeXML) and NOT the persistent (inactive) xml.
	SkipConfigOnNICMutation bool
	// SkipConfigOnHostdevMutation is the PCI-hostdev equivalent: AttachHostdev*/
	// DetachHostdev update ONLY the live view (activeXML) and NOT the persistent
	// (inactive) xml — modeling a live-succeeded-but-config-not-applied divergence
	// so a both-state (live+persistent) hostdev verification can be exercised.
	SkipConfigOnHostdevMutation bool
	// FailAttachHostdev / FailDetachHostdev inject a live hostdev hot-plug primitive
	// failure so scenarios can exercise attach-rollback / detach-forward compensation.
	FailAttachHostdev func(domain, pciAddress, alias string) error
	FailDetachHostdev func(domain, pciAddress string) error
	// FailDetachHostdevConfig injects a CONFIG-only hostdev detach failure (the
	// shut-off reclaim path), symmetric with FailDetachHostdev for the live path.
	FailDetachHostdevConfig func(domain, pciAddress string) error
	FailShutdownDomain      func(name string) error
	// FailDestroyDomain injects a forced-stop failure, so a scenario can reach the
	// path where a domain cannot be taken off a name at all.
	FailDestroyDomain   func(name string) error
	FailUndefineDomain  func(name string, removeStorage bool) error
	FailUndefinePreserv func(name string) error
	// OnUndefined runs after an undefine of name has taken effect (either
	// flavour), outside the fake's lock, so a scenario can run another
	// component in the window between a teardown's undefine and its later
	// steps — e.g. the reconciler racing a DeleteVM (lab 2 run c713, N-2).
	OnUndefined func(name string)
	// FailDumpXML injects a live-domain read failure so a scenario can exercise a
	// fail-closed path that must NOT proceed when the live membership is unreadable
	// (e.g. PCI detach recovery refusing to release without confirming the hostdev
	// left the live domain).
	FailDumpXML func(name string) error
	// FailDumpXMLInactive is the PERSISTENT-view twin of FailDumpXML, for a
	// fail-closed path that reads both views of a domain and must treat an
	// unreadable persistent config as a gap rather than an absence.
	FailDumpXMLInactive func(name string) error
	// FailRunningDomainTaps, when set, runs at the start of RunningDomainTaps
	// and its error is returned — a dead or restarting libvirt connection. It
	// may also block, to model a hung libvirtd.
	FailRunningDomainTaps func() error
	// FailConfigureVLANTap, when set, runs at the start of ConfigureVLANTap
	// and fails it with what it returns: a tap the host cannot put on its
	// access VLAN.
	FailConfigureVLANTap func(domain, mac string, vlan int) error
	// FailCreateLiveSnapshot fires AFTER the disk overlay has cut over, modeling a
	// RAM-save/capture failure that leaves the VM on an overlay.
	FailCreateLiveSnapshot func(domain, snap string) error
	// OnRevertSnapshot runs inside RevertToSnapshot and RevertToLiveSnapshot,
	// while the revert holds the domain down, as libvirt's revert does.
	OnRevertSnapshot func(domain, snap string)
	// FailDomainDiskSources, when set, runs at the start of
	// DomainDiskSources and its error is returned.
	FailDomainDiskSources func(domain string) error
	// RevertNotCurrent makes a revert succeed but report that libvirt would
	// not take the snapshot back as current (libvirt.RestoredNotCurrentError).
	RevertNotCurrent bool
	// DeleteSnapshotKeeps, when set, makes a snapshot delete remove only the
	// metadata and report these files kept (libvirt.SnapshotFilesKeptError),
	// as a delete libvirt cannot merge safely does.
	DeleteSnapshotKeeps []string
	// snapshotFiles is, per domain and snapshot, the files the snapshot's
	// overlay cutover named: each disk's overlay and the disk it was taken of.
	snapshotFiles         map[string]map[string][]string
	FailDomainState       func(name string) error
	FailDomainStateReason func(name string) error
	// conns is the connection model of the state calls (conn_model.go).
	conns connModel
	// FailHasManagedSaveImage makes HasManagedSaveImage unreadable, for the
	// fail-closed paths that must not treat "cannot tell" as "no saved RAM".
	FailHasManagedSaveImage func(name string) error
	// FailSetVCPUs / FailSetMemory inject a resize primitive failure so scenarios
	// can exercise partial-apply recovery (e.g. cpu ok, mem fails).
	FailSetVCPUs  func(name string, count int) error
	FailSetMemory func(name string, memMiB int) error
	// FailSetVirtioMem injects a memory hot-add primitive failure.
	FailSetVirtioMem    func(name string, requestedMiB int) error
	FailSetCPUTune      func(name string, limit float64, shares int) error
	FailSetNICRate      func(name, mac string, rateMBps float64) error
	FailMigrateToTarget func(name, dconnuri string) error
	// FailSetDiskIOTune injects a failure from the disk I/O throttle primitive.
	FailSetDiskIOTune func(name, dev string) error
	// FailSetDiskIOTuneLive fails AFTER the persistent definition took the
	// throttle, as libvirt does when the live call is refused (a job-lock
	// timeout during a backup).
	FailSetDiskIOTuneLive func(name, dev string) error
	FailBlockPull         func(domain, disk string) error
	FailPoolDestroy       func(name string) error
	// FailDefineSecret, when set, makes DefineCephSecret fail for a UUID.
	FailDefineSecret func(uuid string) error
	// BlockJobStatusFn lets a scenario script block-job progress. Nil =
	// "no job in progress" (Found=false), i.e. the pull is already done —
	// the simplest happy path for the live-restore blockpull poll.
	BlockJobStatusFn func(domain, disk string) (libvirt.BlockJobStatus, error)

	// DeferLiveUnplug models libvirt's ASYNCHRONOUS device unplug, which the default
	// (immediate) behavior does NOT: a real DetachDisk/DetachNIC/DetachHostdev returns
	// success once the unplug has been REQUESTED, and the device leaves the LIVE domain
	// only when the guest acknowledges — possibly much later, possibly never. The
	// PERSISTENT definition is unaffected; a config change applies synchronously.
	//
	// With this set, a detach removes the device from the inactive view immediately and
	// parks the live-view removal until AckLiveUnplug is called.
	//
	// This exists because the fake's default synchronous removal defines away the exact
	// window a caller has to wait through: verification that reads the live domain once,
	// straight after the detach, passes here for every backend that removes the device
	// inside the call and fails against real qemu. A test that does not set this cannot
	// distinguish a verifier that waits from one that does not.
	DeferLiveUnplug bool

	// HonorUnplugOnRequest models a guest that IGNORES the first N-1 unplug requests
	// and honors the Nth — the real behaviour behind the disk-detach failure found on
	// hardware. A guest that has not yet enumerated a just-hot-added device never
	// answers the ACPI/PCI eject, so the request is DROPPED rather than queued: no
	// amount of waiting clears it, and only a re-request does. Measured on a 4-node
	// lab, the device was still present 120s after the first request and left within
	// 5s of the second.
	//
	// Requires DeferLiveUnplug. 0 means "never honor without an explicit
	// AckLiveUnplug". Counted per domain across ALL device kinds, since it stands in
	// for one guest's readiness rather than one device's.
	HonorUnplugOnRequest int

	// savedImageXML is the definition each memory snapshot's saved image
	// carries (SetSavedImageXML).
	savedImageXML map[string]string

	// pendingUnplug holds live-view removals that a deferred unplug has requested but
	// the guest has not yet acknowledged, per domain, in request order.
	pendingUnplug map[string][]func()
	// unplugRequests counts detach requests per domain, for HonorUnplugOnRequest.
	unplugRequests map[string]int

	// OnAbortMigration runs on every AbortMigration, after it is recorded.
	OnAbortMigration func(name string)
	// FailAbortMigration, when it returns an error, fails that AbortMigration
	// (recorded, OnAbortMigration not run), as libvirt fails an abort that
	// finds no job yet.
	FailAbortMigration func(name string) error
	abortedMigrations  map[string]int

	// mem is each domain's memory-snapshot model, memClock the fake clock
	// its pause windows are on (memsnap.go). Guarded by f.mu.
	mem      map[string]*memState
	memClock time.Duration
}

// New returns a Fake ready to use. Safe for concurrent use.
func New() *Fake {
	return &Fake{
		domains:     make(map[string]State),
		xml:         make(map[string]string),
		activeXML:   make(map[string]string),
		snapshots:   make(map[string]map[string]struct{}),
		diskSources: make(map[string]map[string]string),
		stats:       make(map[string]*libvirt.DomainStats),
		reasons:     make(map[string]string),
		managedSave: make(map[string]bool),
		starts:      make(map[string]int),
		taps:        make(map[tapKey]string),

		pendingUnplug:  make(map[string][]func()),
		unplugRequests: make(map[string]int),

		Now: time.Now,
	}
}

// applyLiveUnplug performs a live-view removal now, or parks it for AckLiveUnplug
// when DeferLiveUnplug models an unacknowledged guest. With HonorUnplugOnRequest
// set, the Nth request is honored immediately and every earlier one is DROPPED —
// parked removals from ignored requests are discarded, because a guest that never
// saw the eject has nothing queued to deliver later. Caller holds f.mu.
func (f *Fake) applyLiveUnplug(domain string, remove func()) {
	if !f.DeferLiveUnplug {
		remove()
		return
	}
	f.unplugRequests[domain]++
	if n := f.HonorUnplugOnRequest; n > 0 && f.unplugRequests[domain] >= n {
		delete(f.pendingUnplug, domain)
		remove()
		f.record("unplug-honored", domain, "request="+strconv.Itoa(f.unplugRequests[domain]))
		return
	}
	f.pendingUnplug[domain] = append(f.pendingUnplug[domain], remove)
}

// UnplugRequests reports how many detach requests domain has received — the
// assertion that a verifier really did RE-REQUEST rather than only poll.
func (f *Fake) UnplugRequests(domain string) int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unplugRequests[domain]
}

// AckLiveUnplug is the guest acknowledging every unplug requested so far on domain:
// it applies the parked live-view removals in request order and returns how many.
// A no-op when nothing is pending, so a test can call it unconditionally.
func (f *Fake) AckLiveUnplug(domain string) int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	pending := f.pendingUnplug[domain]
	for _, remove := range pending {
		remove()
	}
	delete(f.pendingUnplug, domain)
	if n := len(pending); n > 0 {
		f.record("ack-live-unplug", domain, "applied="+strconv.Itoa(n))
		return n
	}
	return 0
}

// PendingUnplugs reports how many requested-but-unacknowledged live removals domain
// is carrying — the assertion that a detach really did leave the device in the live
// view rather than removing it synchronously.
func (f *Fake) PendingUnplugs(domain string) int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pendingUnplug[domain])
}

// Events returns a copy of the event log (safe to read while
// scenario test code continues to drive the fake).
func (f *Fake) EventLog() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Event, len(f.events))
	copy(out, f.events)
	return out
}

// SetState forces a domain into a particular state. Scenarios use
// this to simulate "the VM is already running" without rolling
// through DefineDomain + StartDomain. A domain it takes into running from
// any other state starts running, as far as OnRunning is concerned.
func (f *Fake) SetState(name string, s State) {
	defer f.daemon()()
	f.mu.Lock()
	if s != StatePaused {
		delete(f.pendingNvram, name)
	}
	delete(f.ioPaused, name)
	if s != StateShutdown {
		delete(f.offReason, name)
	}
	if prev := f.domains[name]; (s != StateRunning && s != StatePaused) || (prev != StateRunning && prev != StatePaused) {
		delete(f.ppMark, name) // a new QEMU process, or none: the live mark is gone
	}
	started := s == StateRunning && f.domains[name] != StateRunning
	f.domains[name] = s
	f.mu.Unlock()
	if started {
		f.running(name)
	}
}

// SetStats sets the GetDomainStats / GetAllDomainStats response for
// a domain. Scenarios use this to feed deterministic stats into
// metrics + monitoring paths.
func (f *Fake) SetStats(name string, s *libvirt.DomainStats) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats[name] = s
}

func (f *Fake) record(op, domain, note string) {
	f.events = append(f.events, Event{Op: op, Domain: domain, Note: note, When: f.Now()})
}

// ── grpcapi.LibvirtBackend implementation ───────────────────────────────

func (f *Fake) DefineDomain(xmlConfig string) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpDefine, Name: domainNameFromXML(xmlConfig), UUID: libvirt.UUIDFromXML(xmlConfig)}); err != nil {
		return fmt.Errorf("define domain: %w", err)
	}
	if f.FailDefineDomain != nil {
		if err := f.FailDefineDomain(xmlConfig); err != nil {
			return err
		}
	}
	name := domainNameFromXML(xmlConfig)
	if name == "" {
		return errors.New("libvirtfake: no <name> in domain XML")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// libvirt gives every domain a uuid: one whose XML names none gets a
	// generated one, so a redefine of an existing name with no uuid is
	// refused there (the generated one is not the domain's: the name check
	// below), and so it is here. A test then sees the identity a real host
	// would report.
	if domainUUIDFromXML(xmlConfig) == "" {
		xmlConfig = insertUUID(xmlConfig, name, randomUUID())
	}
	// libvirt refuses a definition whose UUID is already held by an ACTIVE domain
	// under a different name. That is exactly what happens after undefining a
	// RUNNING domain — it survives as a transient one, still holding its UUID — so
	// a caller that undefines a running VM and then redefines it under a new name
	// gets a failure here, not a rename. The fake modelled the rename, which hid a
	// live defect in the cutover handoff.
	if uuid := domainUUIDFromXML(xmlConfig); uuid != "" {
		for other, st := range f.domains {
			if other == name || (st != StateRunning && st != StatePaused) {
				continue
			}
			if domainUUIDFromXML(f.liveXMLLocked(other)) == uuid {
				return fmt.Errorf("libvirtfake: domain %q is already active with uuid %s", other, uuid)
			}
		}
		// An inactive domain of another name holds its uuid just as firmly:
		// libvirt refuses it too ("already defined with uuid").
		for other := range f.domains {
			if other != name && domainUUIDFromXML(f.liveXMLLocked(other)) == uuid {
				return fmt.Errorf("libvirtfake: domain %q is already defined with uuid %s", other, uuid)
			}
		}
		// libvirt also refuses a definition that reuses an existing domain's NAME
		// with a DIFFERENT uuid — a name is not a slot you can overwrite. A caller
		// whose undefine of the old occupant failed therefore cannot quietly
		// replace it, which is what this fake used to model.
		//
		// Read through the LIVE view, not the persistent one: undefining an active
		// domain leaves it transient, at which point its identity lives only in the
		// active XML — and a transient domain holds its name just as firmly.
		if _, ok := f.domains[name]; ok {
			if cur := domainUUIDFromXML(f.liveXMLLocked(name)); cur != "" && cur != uuid {
				return fmt.Errorf("libvirtfake: domain %q already exists with uuid %s", name, cur)
			}
		}
	}
	// As libvirt.Client.DefineDomain: every define applies the console
	// password policy (fresh passwords on, none off).
	if f.consolePolicy != nil {
		applied, err := libvirt.ApplyConsolePasswords(xmlConfig, libvirt.ConsoleModeFor(f.consolePolicy(), true), f.vncUnavailable != "")
		if err != nil {
			return fmt.Errorf("define domain: %w", err)
		}
		xmlConfig = applied
	}
	if st := f.domains[name]; st != StateRunning && st != StatePaused {
		// A new persistent definition of an inactive domain is what its next
		// start opens: it stays on an overlay only if it names it.
		f.dropPITLocked(name, xmlConfig)
	}
	if f.FillDefine != nil {
		xmlConfig = f.FillDefine(xmlConfig)
	}
	// virDomainDefineXML on an ACTIVE domain updates only its persistent
	// config (qemuDomainDefineXMLFlags stores it as vm->newDef, applied at the
	// next boot): the domain keeps running or paused, and its live XML stays
	// the one it booted with. Only an inactive (or new) domain becomes defined.
	if st := f.domains[name]; st == StateRunning || st == StatePaused {
		if _, ok := f.activeXML[name]; !ok {
			if prev, had := f.xml[name]; had {
				f.activeXML[name] = prev
			}
		}
	} else {
		f.domains[name] = StateDefined
	}
	f.xml[name] = xmlConfig
	f.record("define", name, "")
	return nil
}

// dropPITLocked takes domain name off every point-in-time overlay
// (pit_snapshot.go) that keepXML does not name as a disk source. Caller
// holds f.mu.
func (f *Fake) dropPITLocked(name, keepXML string) {
	for overlay, dom := range f.pitOn {
		if dom != name {
			continue
		}
		if keepXML != "" && (strings.Contains(keepXML, "file='"+overlay+"'") || strings.Contains(keepXML, `file="`+overlay+`"`)) {
			continue
		}
		delete(f.pitOn, overlay)
	}
}

// liveXMLLocked is the live view of a domain, caller holds f.mu.
func (f *Fake) liveXMLLocked(name string) string {
	if x, ok := f.activeXML[name]; ok {
		return x
	}
	return f.xml[name]
}

// domainUUIDFromXML extracts <uuid>…</uuid>.
func domainUUIDFromXML(xmlConfig string) string {
	const open, close = "<uuid>", "</uuid>"
	i := strings.Index(xmlConfig, open)
	if i < 0 {
		return ""
	}
	rest := xmlConfig[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// SetFirmwareMoveGuard mirrors libvirt.Client.SetFirmwareMoveGuard.
func (f *Fake) SetFirmwareMoveGuard(g libvirt.FirmwareMoveGuard) {
	defer f.daemon()()
	f.mu.Lock()
	f.fwGuard = g
	f.mu.Unlock()
}

// fwCheck asks the firmware move guard, outside the fake's lock (the guard
// reads records, not the fake).
func (f *Fake) fwCheck(c libvirt.FirmwareCall) error {
	f.mu.Lock()
	g := f.fwGuard
	f.mu.Unlock()
	if g.Check == nil {
		return nil
	}
	return g.Check(c)
}

// boundDomain refuses a domain of name whose uuid is not uuid, as
// libvirt.Client's exempt entry points do; ok is false when there is no
// domain of the name.
func (f *Fake) boundDomain(name, uuid string) (State, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return "", false, nil
	}
	if got := domainUUIDFromXML(f.liveXMLLocked(name)); uuid == "" || !strings.EqualFold(got, uuid) {
		return st, true, fmt.Errorf("libvirtfake: domain %s has uuid %q, not %q", name, got, uuid)
	}
	return st, true, nil
}

// fwExemptResume mirrors the client's exempt resumes.
func (f *Fake) fwExemptResume(c libvirt.FirmwareCall) error {
	if err := f.fwCheck(c); err != nil {
		return fmt.Errorf("resume domain %s: %w", c.Name, err)
	}
	if c.UUID != "" {
		if _, ok, err := f.boundDomain(c.Name, c.UUID); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("libvirtfake: domain %q not defined", c.Name)
		}
	}
	return f.resumeDomain(c.Name)
}

// ResumeFirmwareMoveSource mirrors libvirt.Client.ResumeFirmwareMoveSource.
func (f *Fake) ResumeFirmwareMoveSource(name, uuid, attempt string) error {
	defer f.daemon()()
	return f.fwExemptResume(libvirt.FirmwareCall{Op: libvirt.OpResume, Name: name, UUID: uuid, Attempt: attempt, Via: libvirt.ViaResumeFirmwareMoveSource})
}

// ResumeFirmwareMoveSourceForOperator mirrors
// libvirt.Client.ResumeFirmwareMoveSourceForOperator.
func (f *Fake) ResumeFirmwareMoveSourceForOperator(name, uuid, attempt string) error {
	defer f.daemon()()
	return f.fwExemptResume(libvirt.FirmwareCall{Op: libvirt.OpResume, Name: name, UUID: uuid, Attempt: attempt, Via: libvirt.ViaResumeFirmwareMoveSourceOperator})
}

// ResumePartitionPaused mirrors libvirt.Client.ResumePartitionPaused.
func (f *Fake) ResumePartitionPaused(name, uuid string) error {
	defer f.daemon()()
	return f.fwExemptResume(libvirt.FirmwareCall{Op: libvirt.OpResume, Name: name, UUID: uuid, Via: libvirt.ViaResumePartitionPaused})
}

// KillPartitionPaused mirrors libvirt.Client.KillPartitionPaused: the
// domain's QEMU is killed without libvirt (so the firmware move guard is not
// asked; the daemon gate is, since a dead daemon kills nothing), and the
// domain is shut off, crashed. A
// domain that is not running or paused has no QEMU, which is success; one
// that is not defined, or whose uuid is not uuid, has no pid file to prove
// it, which is an error. FailKillPartitionPaused fails it.
func (f *Fake) KillPartitionPaused(name, uuid string) error {
	defer f.daemon()()
	if f.FailKillPartitionPaused != nil {
		if err := f.FailKillPartitionPaused(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return fmt.Errorf("libvirtfake: kill qemu of %s: no pid file", name)
	}
	if uuid != "" {
		if got := domainUUIDFromXML(f.liveXMLLocked(name)); !strings.EqualFold(got, uuid) {
			return fmt.Errorf("libvirtfake: kill qemu of %s: its QEMU has uuid %q, not %q", name, got, uuid)
		}
	}
	if st != StateRunning && st != StatePaused {
		return nil
	}
	f.leftStateLocked(name)
	f.domains[name] = StateShutdown
	delete(f.liveConsolePw, name)
	if f.offReason == nil {
		f.offReason = map[string]string{}
	}
	f.offReason[name] = "crashed"
	f.record("kill", name, "")
	return nil
}

// ResumeFirmwareMoveTarget mirrors libvirt.Client.ResumeFirmwareMoveTarget.
func (f *Fake) ResumeFirmwareMoveTarget(name, uuid, attempt string) error {
	defer f.daemon()()
	return f.fwExemptResume(libvirt.FirmwareCall{Op: libvirt.OpResume, Name: name, UUID: uuid, Attempt: attempt, Via: libvirt.ViaResumeFirmwareMoveTarget})
}

// DiscardFirmwareMoveTarget mirrors libvirt.Client.DiscardFirmwareMoveTarget:
// destroy a paused domain, then undefine keeping its state; a running one is
// refused, an absent one is nothing to discard.
func (f *Fake) DiscardFirmwareMoveTarget(name, uuid, attempt string) error {
	defer f.daemon()()
	c := libvirt.FirmwareCall{Name: name, UUID: uuid, Attempt: attempt, Via: libvirt.ViaDiscardFirmwareMoveTarget}
	for _, op := range []libvirt.FirmwareOp{libvirt.OpStop, libvirt.OpUndefine} {
		c.Op = op
		if err := f.fwCheck(c); err != nil {
			return fmt.Errorf("discard %s: %w", name, err)
		}
	}
	st, ok, err := f.boundDomain(name, uuid)
	if err != nil || !ok {
		return err
	}
	switch st {
	case StateShutdown:
	case StatePaused:
		if err := f.destroyDomain(name); err != nil {
			return fmt.Errorf("discard %s: destroy: %w", name, err)
		}
	default:
		return fmt.Errorf("%w: discard %s: the domain is %s, not paused or shut off", libvirt.ErrFirmwareMoveInFlight, name, st)
	}
	return f.undefinePreservingState(name)
}

// UndefineFirmwareMoveLeftover mirrors
// libvirt.Client.UndefineFirmwareMoveLeftover: the domain must be shut off.
func (f *Fake) UndefineFirmwareMoveLeftover(name, uuid, attempt string) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpUndefine, Name: name, UUID: uuid, Attempt: attempt, Via: libvirt.ViaUndefineFirmwareMoveLeftover}); err != nil {
		return fmt.Errorf("undefine leftover %s: %w", name, err)
	}
	st, ok, err := f.boundDomain(name, uuid)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	if st != StateShutdown {
		return fmt.Errorf("undefine leftover %s: the domain is not shut off (%s)", name, st)
	}
	return f.undefinePreservingState(name)
}

// StopFirmwareMoveTargetForOperator mirrors
// libvirt.Client.StopFirmwareMoveTargetForOperator.
func (f *Fake) StopFirmwareMoveTargetForOperator(name, uuid, attempt string, force bool) error {
	defer f.daemon()()
	return f.stopForOperator(name, uuid, attempt, force, libvirt.ViaStopFirmwareMoveTargetForOperator)
}

// StopOwedFirmwareLeftover mirrors libvirt.Client.StopOwedFirmwareLeftover.
func (f *Fake) StopOwedFirmwareLeftover(name, uuid, attempt string, force bool) error {
	defer f.daemon()()
	return f.stopForOperator(name, uuid, attempt, force, libvirt.ViaStopOwedFirmwareLeftover)
}

// UndefineOwedFirmwareLeftover mirrors
// libvirt.Client.UndefineOwedFirmwareLeftover: the domain must be shut off.
func (f *Fake) UndefineOwedFirmwareLeftover(name, uuid, attempt string) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpUndefine, Name: name, UUID: uuid, Attempt: attempt, Via: libvirt.ViaUndefineOwedFirmwareLeftover}); err != nil {
		return fmt.Errorf("undefine leftover %s: %w", name, err)
	}
	st, ok, err := f.boundDomain(name, uuid)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	if st != StateShutdown {
		return fmt.Errorf("undefine leftover %s: the domain is not shut off (%s)", name, st)
	}
	return f.undefinePreservingState(name)
}

func (f *Fake) stopForOperator(name, uuid, attempt string, force bool, via libvirt.FirmwareExemption) error {
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpStop, Name: name, UUID: uuid, Attempt: attempt, Via: via}); err != nil {
		return fmt.Errorf("stop %s: %w", name, err)
	}
	if _, ok, err := f.boundDomain(name, uuid); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	if force {
		return f.destroyDomain(name)
	}
	return f.shutdownDomain(name)
}

// SetStartGuard mirrors libvirt.Client.SetStartGuard.
func (f *Fake) SetStartGuard(g libvirt.StartGuard) {
	defer f.daemon()()
	f.mu.Lock()
	f.startGuard, f.guardSet = g, true
	ready := f.guardReady
	f.guardReady = nil
	f.mu.Unlock()
	if ready != nil {
		close(ready)
	}
}

// RequireStartGuard mirrors libvirt.Client.RequireStartGuard: starts of a
// domain needs reports true for (nil: every start) wait for the next
// SetStartGuard, up to wait.
func (f *Fake) RequireStartGuard(wait time.Duration, needs func(name string) bool) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.guardReady, f.guardWait, f.guardNeeds = make(chan struct{}), wait, needs
}

func (f *Fake) running(name string) {
	if cb := f.OnRunning; cb != nil {
		cb(name)
	}
}

// StartDomain mirrors libvirt.Client.StartDomain, guard included: a start the
// guard asks to pause runs AfterPaused while the domain is paused (its taps
// already assigned), then resumes it.
//
// The firmware move guard is asked first, whatever the start guard's
// readiness, as libvirt.Client's guard() does.
func (f *Fake) StartDomain(name string) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpStart, Name: name}); err != nil {
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	f.mu.Lock()
	ready, wait, needs := f.guardReady, f.guardWait, f.guardNeeds
	f.mu.Unlock()
	unguarded := false
	if ready != nil {
		select {
		case <-ready:
		default:
			if needs != nil && !needs(name) {
				unguarded = true
				break
			}
			select {
			case <-ready:
			case <-time.After(wait):
				return fmt.Errorf("start domain %s: the NIC firewall is not ready yet", name)
			}
		}
	}
	f.mu.Lock()
	g := f.startGuard
	f.mu.Unlock()
	if unguarded {
		g = libvirt.StartGuard{}
	}
	pause := false
	if g.Before != nil {
		p, err := g.Before(name)
		if err != nil {
			return fmt.Errorf("start domain %s: %w", name, err)
		}
		pause = p
	}
	if err := f.startDomain(name, pause); err != nil {
		// As libvirt.Client.StartDomain (startWithConsoleBackstop): a start QEMU
		// refuses for a console password it cannot do is retried once without
		// the passwords, and the host stops setting VNC passwords.
		if !libvirt.IsConsolePasswordRefusal(err) || !f.stripConsoleForBackstop(name, err) {
			return err
		}
		if err := f.startDomain(name, pause); err != nil {
			return err
		}
	}
	if !pause {
		f.running(name)
		return nil
	}
	if g.AfterPaused != nil {
		if err := g.AfterPaused(name); err != nil {
			f.mu.Lock()
			f.domains[name] = StateShutdown
			f.mu.Unlock()
			return fmt.Errorf("start domain %s: %w", name, err)
		}
	}
	if err := f.resumeDomain(name); err != nil {
		// As libvirt.Client does (re-review m5): a domain that cannot be
		// resumed is stopped, not left paused.
		f.mu.Lock()
		f.domains[name] = StateShutdown
		f.mu.Unlock()
		return err
	}
	return nil
}

func (f *Fake) startDomain(name string, paused bool) error {
	return f.lockedStart(name, func() error { return f.startDomainUnlocked(name, paused) })
}

func (f *Fake) startDomainUnlocked(name string, paused bool) error {
	if f.FailStartDomain != nil {
		if err := f.FailStartDomain(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	// A definition left on a point-in-time overlay (pit_snapshot.go) whose
	// file is gone cannot start, as in libvirt: qemu cannot open the source.
	for overlay, dom := range f.pitOn {
		if dom != name {
			continue
		}
		if _, err := os.Stat(overlay); err != nil {
			return fmt.Errorf("libvirtfake: start domain %q: Cannot access storage file '%s': %v", name, overlay, err)
		}
	}
	if n, ok := f.lateWaits[name]; ok && n > 0 && f.domains[name] == StateRunning {
		// A ShutdownLate guest still going down: libvirt refuses to start a
		// running domain, and the guest then completes its shutdown.
		delete(f.lateWaits, name)
		f.domains[name] = StateShutdown
		f.record("shutoff-late", name, "")
		return fmt.Errorf("libvirtfake: domain %q is already running", name)
	}
	f.leftStateLocked(name)
	f.domains[name] = StateRunning
	if paused {
		f.domains[name] = StatePaused
	}
	// The guest starts with the console passwords its definition carries,
	// and keeps them until it stops, whatever a later define says.
	f.captureConsolePasswordsLocked(name, f.liveXMLLocked(name))
	f.starts[name]++
	ms := f.memLocked(name)
	ms.qemuStarts++
	ms.gen++
	f.record("start", name, "")
	return nil
}

// SuspendDomain pauses a RUNNING domain: it stays active (StatePaused) and
// DomainStateReason reports reason "paused", as libvirt does. Suspending a
// paused domain succeeds and changes nothing; suspending one that is not
// active is an error, as in libvirt.
func (f *Fake) SuspendDomain(name string) error {
	defer f.daemon()()
	if f.FailSuspendDomain != nil {
		if err := f.FailSuspendDomain(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	if st == StatePaused {
		// As libvirt's qemuDomainSuspend: a paused domain is left as it is,
		// and the call succeeds.
		f.record("suspend", name, "already paused")
		return nil
	}
	if st != StateRunning {
		return fmt.Errorf("libvirtfake: domain %q is not running (%s)", name, st)
	}
	f.stopCPUsLocked(name)
	delete(f.ioPaused, name)
	f.record("suspend", name, "")
	// A suspend during a live capture's memory write is the job's too
	// (libvirt admits it): QEMU finishes the write with the vCPUs stopped.
	if m := f.memLocked(name); m.liveJob != nil {
		m.suspended = true
		close(m.liveJob)
		m.liveJob = nil
	}
	return nil
}

// PauseOnIOError pauses a RUNNING domain as QEMU does when a guest disk
// write fails — ENOSPC on a full storage pool, or EIO — under libvirt's
// default error policy: the domain stays active (StatePaused) and
// DomainStateReason reports Reason "paused" with PausedReason io-error.
// Scenario helper; resuming it (ResumeDomain) or any other state change
// clears the I/O error.
func (f *Fake) PauseOnIOError(name string) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	if st != StateRunning {
		return fmt.Errorf("libvirtfake: domain %q is not running (%s)", name, st)
	}
	f.domains[name] = StatePaused
	if f.ioPaused == nil {
		f.ioPaused = map[string]bool{}
	}
	f.ioPaused[name] = true
	f.record("io-error-pause", name, "")
	return nil
}

// ResumeDomain resumes a PAUSED domain. Resuming a domain that is not paused
// is an error, as in libvirt. The firmware move guard is asked first.
func (f *Fake) ResumeDomain(name string) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpResume, Name: name}); err != nil {
		return fmt.Errorf("resume domain %s: %w", name, err)
	}
	return f.resumeDomain(name)
}

func (f *Fake) resumeDomain(name string) error {
	if f.FailResumeDomain != nil {
		if err := f.FailResumeDomain(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	if st != StatePaused {
		return fmt.Errorf("libvirtfake: domain %q is not paused (%s)", name, st)
	}
	f.domains[name] = StateRunning
	delete(f.ioPaused, name)
	f.record("resume", name, "")
	f.flushPendingNvramLocked(name)
	defer f.outsideLock(func() { f.running(name) })
	return nil
}

// RawState reports the fake's own state for a domain — running, paused or
// shutoff — without libvirt's coarse folding. ok=false when undefined.
// Scenario helper: "is this copy executing right now" is RawState == running.
func (f *Fake) RawState(name string) (State, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.domains[name]
	return s, ok
}

func (f *Fake) BlockPull(domain, disk string) error {
	defer f.daemon()()
	if f.FailBlockPull != nil {
		if err := f.FailBlockPull(domain, disk); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("blockpull", domain, disk)
	return nil
}

func (f *Fake) BlockJobStatus(domain, disk string) (libvirt.BlockJobStatus, error) {
	defer f.daemon()()
	if f.BlockJobStatusFn != nil {
		return f.BlockJobStatusFn(domain, disk)
	}
	return libvirt.BlockJobStatus{Found: false}, nil
}

func (f *Fake) ShutdownDomain(name string) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpStop, Name: name}); err != nil {
		return fmt.Errorf("shutdown domain %s: %w", name, err)
	}
	return f.shutdownDomain(name)
}

func (f *Fake) shutdownDomain(name string) error {
	if f.FailShutdownDomain != nil {
		if err := f.FailShutdownDomain(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	if st == StateShutdown {
		return notRunning("shutdown", name)
	}
	f.record("shutdown", name, "")
	if f.IgnoreShutdown != nil && f.IgnoreShutdown(name) {
		return nil
	}
	if f.ShutdownLate != nil && f.ShutdownLate(name) {
		if f.lateWaits == nil {
			f.lateWaits = map[string]int{}
		}
		f.lateWaits[name] = 0
		return nil
	}
	f.leftStateLocked(name)
	f.domains[name] = StateShutdown
	delete(f.liveConsolePw, name)
	return nil
}

func (f *Fake) DestroyDomain(name string) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpStop, Name: name}); err != nil {
		return fmt.Errorf("destroy domain %s: %w", name, err)
	}
	return f.destroyDomain(name)
}

func (f *Fake) destroyDomain(name string) error {
	if f.FailDestroyDomain != nil {
		if err := f.FailDestroyDomain(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	if st == StateShutdown {
		return notRunning("destroy", name)
	}
	f.leftStateLocked(name)
	f.domains[name] = StateShutdown
	delete(f.liveConsolePw, name)
	f.record("destroy", name, "")
	return nil
}

// noDomain is libvirt's VIR_ERR_NO_DOMAIN for a lookup of name, wrapped as
// libvirt.Client wraps it.
func noDomain(name string) error {
	return fmt.Errorf("lookup domain %s: %w", name, golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain),
		Message: fmt.Sprintf("Domain not found: no domain with matching name '%s'", name)})
}

// notRunning is libvirt's refusal to stop a domain that is not active
// (VIR_ERR_OPERATION_INVALID), wrapped as libvirt.Client wraps it.
func notRunning(op, name string) error {
	return fmt.Errorf("%s domain %s: %w", op, name, golibvirt.Error{Code: uint32(golibvirt.ErrOperationInvalid),
		Message: "Requested operation is not valid: domain is not running"})
}

// undefineRefusalLocked is libvirt's refusal of an undefine without
// MANAGED_SAVE and SNAPSHOTS_METADATA (qemuDomainUndefineFlags), which only
// the client's UndefineDomain(removeStorage=true) passes: a domain with a
// managed-save image is refused ("Refusing to undefine while domain managed
// save image exists"), and so is an INACTIVE domain that still holds snapshot
// metadata ("cannot delete inactive domain with %d snapshots"). An active
// domain with snapshots is not refused: it survives as a transient one.
// Called with f.mu held.
func (f *Fake) undefineRefusalLocked(op, name string) error {
	if f.managedSave[name] {
		return fmt.Errorf("%s domain %s: %w", op, name, golibvirt.Error{Code: uint32(golibvirt.ErrOperationInvalid),
			Message: "Requested operation is not valid: Refusing to undefine while domain managed save image exists"})
	}
	n := len(f.snapshots[name])
	if n == 0 {
		return nil
	}
	if st := f.domains[name]; st == StateRunning || st == StatePaused {
		return nil
	}
	return fmt.Errorf("%s domain %s: %w", op, name, golibvirt.Error{Code: uint32(golibvirt.ErrOperationInvalid),
		Message: fmt.Sprintf("Requested operation is not valid: cannot delete inactive domain with %d snapshots", n)})
}

func (f *Fake) UndefineDomain(name string, removeStorage bool) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpUndefine, Name: name}); err != nil {
		return fmt.Errorf("undefine domain %s: %w", name, err)
	}
	// As libvirt.Client: the lookup comes first, and an absent name is
	// libvirt's no-domain error, with nothing deleted (review I-1).
	if !f.DomainExists(name) {
		return noDomain(name)
	}
	if f.FailUndefineDomain != nil {
		if err := f.FailUndefineDomain(name, removeStorage); err != nil {
			return err
		}
	}
	// The state is read and acted on under one hold of the lock (re-review
	// N-3): the hook above may have changed it.
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		return noDomain(name)
	}
	// libvirt.Client passes MANAGED_SAVE and SNAPSHOTS_METADATA only with
	// removeStorage.
	if !removeStorage {
		if err := f.undefineRefusalLocked("undefine", name); err != nil {
			return err
		}
	}
	if st == StateRunning || st == StatePaused {
		// An active domain survives as a transient one (see
		// undefinePreservingState). libvirt unlinks the NVRAM file for
		// UNDEFINE_NVRAM before it looks at whether the domain is active
		// (qemuDomainUndefineFlags; not probed): the running QEMU keeps its
		// open descriptor, the file is gone.
		if _, ok := f.activeXML[name]; !ok {
			f.activeXML[name] = f.xml[name]
		}
		delete(f.xml, name)
		f.record("undefine", name, fmt.Sprintf("remove_storage=%v transient=true", removeStorage))
		f.deleteNvramLocked(name)
		return nil
	}
	f.dropPITLocked(name, "")
	delete(f.domains, name)
	delete(f.ppMark, name)
	delete(f.xml, name)
	delete(f.activeXML, name)
	delete(f.liveConsolePw, name)
	delete(f.snapshots, name)
	delete(f.stats, name)
	delete(f.managedSave, name)
	// Domain metadata lives and dies with the definition, as in libvirt: a later
	// domain that reuses the name starts with none.
	delete(f.ownerEpochs, name)
	delete(f.managed, name)
	delete(f.managedInc, name)
	f.leftStateLocked(name)
	f.record("undefine", name, fmt.Sprintf("remove_storage=%v", removeStorage))
	// Probe (g): the NVRAM goes with the definition, the swtpm tree stays.
	f.deleteNvramLocked(name)
	if hook := f.OnUndefined; hook != nil {
		f.outsideLock(func() { hook(name) })
	}
	return nil
}

// UndefineDomainPreservingState mirrors UndefineDomain but keeps the domain's
// NVRAM and swtpm state (KEEP_NVRAM|KEEP_TPM, probe (b)).
func (f *Fake) UndefineDomainPreservingState(name string) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpUndefine, Name: name}); err != nil {
		return fmt.Errorf("undefine (keep state) domain %s: %w", name, err)
	}
	return f.undefinePreservingState(name)
}

func (f *Fake) undefinePreservingState(name string) error {
	if f.FailUndefinePreserv != nil {
		if err := f.FailUndefinePreserv(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// KEEP_NVRAM|KEEP_TPM carries neither MANAGED_SAVE nor
	// SNAPSHOTS_METADATA: refused as libvirt refuses it.
	if err := f.undefineRefusalLocked("undefine (keep state)", name); err != nil {
		return err
	}
	// An ACTIVE domain survives an undefine as a TRANSIENT one: it keeps running,
	// keeps its UUID, and loses only its persistent definition. Deleting it
	// outright — as this fake used to — is what made the cutover handoff look like
	// it could undefine a running replacement and redefine it under a new name.
	if st := f.domains[name]; st == StateRunning || st == StatePaused {
		if _, ok := f.activeXML[name]; !ok {
			f.activeXML[name] = f.xml[name]
		}
		delete(f.xml, name)
		f.record("undefine", name, "keep_state=true transient=true")
		return nil
	}
	f.dropPITLocked(name, "")
	delete(f.domains, name)
	delete(f.ppMark, name)
	delete(f.xml, name)
	delete(f.activeXML, name)
	delete(f.snapshots, name)
	delete(f.stats, name)
	delete(f.ownerEpochs, name)
	delete(f.managed, name)
	f.leftStateLocked(name)
	f.record("undefine", name, "keep_state=true")
	if hook := f.OnUndefined; hook != nil {
		f.outsideLock(func() { hook(name) })
	}
	return nil
}

// DomainIsActive mirrors libvirt's activity question. StateRunning and
// StatePaused are both ACTIVE; only an undefined or shut-off domain is not.
func (f *Fake) DomainIsActive(name string) (bool, error) {
	defer f.daemon()()
	var active bool
	var err error
	_ = f.mainConn().callAs(false, "", name, func() { active, err = f.domainIsActive(name) })
	return active, err
}

func (f *Fake) domainIsActive(name string) (bool, error) {
	if f.FailDomainState != nil {
		if err := f.FailDomainState(name); err != nil {
			return false, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[name]
	if !ok {
		// libvirt's own VIR_ERR_NO_DOMAIN, so lv.IsNoDomain reads it as the
		// positive "no such domain" a dropped connection never is.
		return false, golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: fmt.Sprintf("libvirtfake: domain %q not found", name)}
	}
	return st == StateRunning || st == StatePaused, nil
}

// DomainState is a call on the Fake's own connection (conn_model.go).
func (f *Fake) DomainState(name string) (string, error) {
	defer f.daemon()()
	var st string
	var err error
	if cerr := f.mainConn().call(name, func() { st, err = f.domainState(name) }); cerr != nil {
		return "unknown", cerr
	}
	return st, err
}

func (f *Fake) domainState(name string) (string, error) {
	if f.FailDomainState != nil {
		if err := f.FailDomainState(name); err != nil {
			return "", err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.domains[name]
	if !ok {
		return string(StateNoDomain), nil
	}
	// The fake's raw vocabulary ("shutoff") is historical and callers cope with
	// it, but StatePaused has no raw analogue — reporting it verbatim would
	// invent a state real libvirt never surfaces here. Report it the way
	// libvirt.coarseDomainState does, so a scenario built on it exercises the
	// real ambiguity: paused and shut-off are the SAME string.
	if s == StatePaused {
		return "stopped", nil
	}
	return string(s), nil
}

// SetPaused puts a domain into the ACTIVE-but-not-running state, which
// DomainState cannot distinguish from shut off. Scenario helper.
func (f *Fake) SetPaused(name string) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains[name] = StatePaused
}

func (f *Fake) DomainExists(name string) bool {
	defer f.daemon()()
	var ok bool
	_ = f.mainConn().callAs(false, "", name, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		_, ok = f.domains[name]
	})
	return ok
}

// SetStateReason injects the Reason returned by DomainStateReason for a domain
// (e.g. "crashed" to drive an on-failure restart decision). Scenario helper.
func (f *Fake) SetStateReason(name, reason string) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reasons[name] = reason
}

// SetManagedSaveImage injects whether a domain carries a managed-save
// (suspend-to-disk) image, as reported by HasManagedSaveImage.
func (f *Fake) SetManagedSaveImage(name string, has bool) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.managedSave[name] = has
}

// HasManagedSaveImage reports an injected managed-save image (default: none),
// satisfying health.LibvirtBackend. Like the real client, an undefined domain
// is a lookup error, never a confident "no image".
func (f *Fake) HasManagedSaveImage(name string) (bool, error) {
	defer f.daemon()()
	if f.FailHasManagedSaveImage != nil {
		if err := f.FailHasManagedSaveImage(name); err != nil {
			return false, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return false, fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	return f.managedSave[name], nil
}

// DomainStateReason returns the coarse state + a reason, satisfying
// health.LibvirtBackend (the restart-policy path). The coarse vocabulary matches
// libvirt.coarseDomainState: shutoff→"stopped", running→"running", else
// "unknown". Reason defaults to "running" for a running domain (or an injected
// value via SetStateReason), else "unknown".
//
// It is a call on the Fake's own connection (conn_model.go).
func (f *Fake) DomainStateReason(name string) (libvirt.DomainStatus, error) {
	defer f.daemon()()
	var st libvirt.DomainStatus
	var err error
	if cerr := f.mainConn().call(name, func() { st, err = f.domainStateReason(name) }); cerr != nil {
		return libvirt.DomainStatus{State: "unknown", Reason: "unknown"}, cerr
	}
	return st, err
}

func (f *Fake) domainStateReason(name string) (libvirt.DomainStatus, error) {
	if f.FailDomainStateReason != nil {
		if err := f.FailDomainStateReason(name); err != nil {
			return libvirt.DomainStatus{State: "unknown", Reason: "unknown"}, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.domains[name]
	if !ok {
		return libvirt.DomainStatus{State: "unknown", Reason: "unknown"}, nil
	}
	coarse := "unknown"
	switch s {
	case StateRunning:
		coarse = "running"
	case StateShutdown, StatePaused: // == StateDefined == "shutoff"; paused folds in too
		coarse = "stopped"
	}
	reason := f.reasons[name]
	if reason == "" && s == StateShutdown {
		reason = f.offReason[name]
	}
	if reason == "" {
		switch s {
		case StateRunning:
			reason = "running"
		case StatePaused:
			reason = "paused" // libvirt.normalizeDomainReason's value for DomainPaused
		default:
			reason = "unknown"
		}
	}
	paused := ""
	if s == StatePaused {
		paused = "user"
		if f.ioPaused[name] {
			paused = libvirt.PausedReasonIOError
		}
	}
	return libvirt.DomainStatus{State: coarse, Reason: reason, PausedReason: paused}, nil
}

func (f *Fake) ListDomains() ([]string, error) {
	defer f.daemon()()
	var names []string
	var err error
	_ = f.mainConn().callAs(false, "", "", func() { names, err = f.listDomains() })
	return names, err
}

func (f *Fake) listDomains() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailListDomains != nil {
		if err := f.FailListDomains(); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(f.domains))
	for n := range f.domains {
		out = append(out, n)
	}
	sort.Strings(out) // a test can tell which domain a list reaches last
	return out, nil
}

// DumpXML returns the domain's LIVE view: activeXML's override when NIC hotplug (or
// SetActiveXML) has diverged it, else the persistent xml — the fake's historical
// "single XML per domain" default (active mirrors persistent until something
// diverges them). Disk hotplug's live view is tracked separately (diskSources) and
// never touches activeXML, so this default is unaffected by disk attach/detach.
func (f *Fake) DumpXML(name string) (string, error) {
	defer f.daemon()()
	var x string
	var err error
	_ = f.mainConn().callAs(false, "", name, func() { x, err = f.dumpXML(name) })
	return x, err
}

func (f *Fake) dumpXML(name string) (string, error) {
	if f.FailDumpXML != nil {
		if err := f.FailDumpXML(name); err != nil {
			return "", err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if x, ok := f.activeXML[name]; ok {
		return withoutConsolePasswords(x), nil
	}
	if x, ok := f.xml[name]; ok {
		return withoutConsolePasswords(x), nil
	}
	return f.synthesizeXMLLocked(name)
}

// synthesizeXMLLocked stands in for the definition a domain seeded via SetState
// alone never got. REAL libvirt cannot have a domain without one, so erroring
// here made every SetState-only rig read as an incomplete runtime inventory,
// which is a fake artifact, not a modeled failure — and both dump paths need the
// same answer, because a caller that reads the live AND persistent view of every
// domain would otherwise see one half of the same domain fail. A domain the fake
// has never heard of is still an error. Tests that want a broken read inject one
// via FailDumpXML / FailDumpXMLInactive. Caller holds f.mu.
//
// The stub carries an EMPTY <devices> element because real libvirt always emits
// one: a document without it is not a device-less domain, it is a document no
// device patcher can add to, and omitting it turned a SetState-only rig into a
// synthetic "cannot add devices" failure that production cannot produce.
func (f *Fake) synthesizeXMLLocked(name string) (string, error) {
	if _, ok := f.domains[name]; ok {
		return `<domain type='kvm'><name>` + name +
			`</name><memory unit='MiB'>1024</memory><vcpu>1</vcpu><devices></devices></domain>`, nil
	}
	// libvirt's own VIR_ERR_NO_DOMAIN, as DomainIsActive gives it.
	return "", golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: fmt.Sprintf("libvirtfake: domain %q not found", name)}
}

// DumpXMLInactive returns the domain's PERSISTENT (inactive) view — what a cold boot
// loads. Tests that need to model a post-pivot live/persistent divergence set them
// explicitly via SetInactiveXML/SetActiveXML. A domain with no configured XML is a
// valid empty domain, not an error: it synthesizes exactly as DumpXML does.
func (f *Fake) DumpXMLInactive(name string) (string, error) {
	defer f.daemon()()
	if f.FailDumpXMLInactive != nil {
		if err := f.FailDumpXMLInactive(name); err != nil {
			return "", err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if x, ok := f.xml[name]; ok {
		return withoutConsolePasswords(x), nil
	}
	return f.synthesizeXMLLocked(name)
}

// activeBaseline returns the current live-view baseline for domain: the tracked
// override if one exists, else the persistent config. Caller holds f.mu.
func (f *Fake) activeBaseline(domain string) string {
	if x, ok := f.activeXML[domain]; ok {
		return x
	}
	return f.xml[domain]
}

// SetActiveXML sets a domain's LIVE (active) XML directly, independent of its
// persistent config — the NIC-hotplug divergence-modeling counterpart to
// SetInactiveXML. A real running domain's live view always exists; this lets a
// scenario seed it explicitly before exercising a live/persistent divergence.
func (f *Fake) SetActiveXML(name, xml string) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeXML[name] = xml
}

// DefinedXML returns the last XML DefineDomain captured for name, or "" if the
// domain was never defined. A test accessor (no error) so assertions can inspect
// the domain a reconcile/redefine produced without the DumpXML not-found error.
func (f *Fake) DefinedXML(name string) string {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.xml[name]
}

// SetInactiveXML sets a domain's persistent (inactive) XML directly, without altering
// its lifecycle state. Scenarios use it to model a RUNNING domain that already has a
// persistent definition (which a real running domain always does) so a live-vs-config
// divergence can be exercised. Mirrors SetDiskSource/SetState.
func (f *Fake) SetInactiveXML(name, xml string) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.xml[name] = xml
}

func (f *Fake) WaitForShutdown(name string, timeout time.Duration) bool {
	defer f.daemon()()
	// The fake transitions synchronously; the wait succeeds unless the guest
	// ignored the shutdown (IgnoreShutdown) and still runs.
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.domains[name]; ok && s == StateRunning && f.IgnoreShutdown != nil && f.IgnoreShutdown(name) {
		return false
	}
	if n, ok := f.lateWaits[name]; ok && f.domains[name] == StateRunning {
		if n == 0 {
			f.lateWaits[name] = 1
			return false // the stop timeout passes; the guest is still going down
		}
		delete(f.lateWaits, name)
		f.domains[name] = StateShutdown
		f.record("shutoff-late", name, "")
	}
	return true
}

// VNC / SPICE / console — return deterministic placeholders.

func (f *Fake) GetVMVNCPort(name string) (int, error) {
	defer f.daemon()()
	port := -1
	var err error
	_ = f.mainConn().callAs(false, CallVNCPort, name, func() { port, err = f.vncPort(name) })
	return port, err
}

func (f *Fake) vncPort(name string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.vncPorts[name]; ok {
		return p, nil
	}
	return 5901, nil
}

// SetVNCPort points a domain's VNC console at port, so a scenario can stand a
// real listener behind ProxyVNC.
func (f *Fake) SetVNCPort(name string, port int) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.vncPorts == nil {
		f.vncPorts = map[string]int{}
	}
	f.vncPorts[name] = port
}

// SetConsolePasswordPolicy mirrors libvirt.Client.SetConsolePasswordPolicy.
func (f *Fake) SetConsolePasswordPolicy(fn func() libvirt.ConsolePolicy) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consolePolicy = fn
}

// SetVNCPasswordUnavailable mirrors libvirt.Client.SetVNCPasswordUnavailable:
// a scenario models a host whose QEMU cannot do VNC passwords (FIPS).
func (f *Fake) SetVNCPasswordUnavailable(reason string) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vncUnavailable = reason
}

// SetSpiceUnusable models a host where SPICE cannot connect (a FIPS-mode
// kernel), as libvirt.Client.SpiceUnusable reports it.
func (f *Fake) SetSpiceUnusable(reason string) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spiceUnusable = reason
}

// SpiceUnusable mirrors libvirt.Client.SpiceUnusable.
func (f *Fake) SpiceUnusable() string {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.spiceUnusable
}

// VNCPasswordUnavailable mirrors libvirt.Client.VNCPasswordUnavailable.
func (f *Fake) VNCPasswordUnavailable() string {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vncUnavailable
}

// DumpXMLSecure is the live definition WITH its console passwords, as
// libvirt's VIR_DOMAIN_XML_SECURE dump (and the migratable XML a live
// migration hands the destination) carries them. DumpXML and DumpXMLInactive
// leave them out, as libvirt's ordinary dumps do.
func (f *Fake) DumpXMLSecure(name string) (string, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if x, ok := f.activeXML[name]; ok {
		return x, nil
	}
	if x, ok := f.xml[name]; ok {
		return x, nil
	}
	return f.synthesizeXMLLocked(name)
}

// withoutConsolePasswords is what an ordinary (not secure) libvirt dump shows.
func withoutConsolePasswords(x string) string {
	if out, err := libvirt.StripConsolePasswords(x); err == nil {
		return out
	}
	return x
}

// stripConsoleForBackstop is startWithConsoleBackstop's redefine: the domain
// loses its console passwords and the host stops setting VNC ones. False when
// the domain had none, so the start error stands.
func (f *Fake) stripConsoleForBackstop(name string, cause error) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Only a password litevirt set: before the latch, an operator's stays.
	if f.consolePolicy == nil || f.consolePolicy() == libvirt.PolicyLeave {
		return false
	}
	x, ok := f.xml[name]
	if !ok || !libvirt.HasConsolePassword(x) {
		return false
	}
	stripped, err := libvirt.StripConsolePasswords(x)
	if err != nil {
		return false
	}
	f.xml[name] = stripped
	f.vncUnavailable = cause.Error()
	f.record("console-password-backstop", name, "")
	return true
}

// ConsolePassword mirrors libvirt.Client.ConsolePassword: the password the
// running guest started with, else its definition's. A domain the fake has
// never heard of has none (its console placeholders answer for any name).
func (f *Fake) ConsolePassword(name, kind string) (string, error) {
	defer f.daemon()()
	var pw string
	var err error
	_ = f.mainConn().callAs(false, CallConsolePassword, name, func() { pw, err = f.consolePassword(name, kind) })
	return pw, err
}

func (f *Fake) consolePassword(name, kind string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if pw, ok := f.liveConsolePw[name]; ok {
		return pw[kind], nil
	}
	x, ok := f.xml[name]
	if !ok {
		return "", nil
	}
	return libvirt.ConsolePasswordFromXML(x, kind)
}

// LandMigrated lands a live-migrated guest here as libvirt does: the
// destination takes the source's secure migratable definition AS IT IS — no
// define of ours runs, so no console password policy applies — and the guest
// runs with the passwords it already had.
func (f *Fake) LandMigrated(domXML string) {
	f.LandMigratedState(domXML, false)
}

// LandMigratedState is LandMigrated for a guest that arrives paused when
// paused is set (VIR_MIGRATE_PAUSED), running otherwise.
func (f *Fake) LandMigratedState(domXML string, paused bool) {
	name := domainNameFromXML(domXML)
	f.mu.Lock()
	f.leftStateLocked(name)
	f.xml[name] = domXML
	f.domains[name] = StateRunning
	note := ""
	if paused {
		f.domains[name] = StatePaused
		note = "paused=true"
	}
	f.captureConsolePasswordsLocked(name, domXML)
	f.record("migrate-in", name, note)
	f.mu.Unlock()
	// A guest that lands running starts running here (OnRunning), however
	// it arrived.
	if !paused {
		f.running(name)
	}
}

// captureConsolePasswordsLocked records the console passwords a guest runs
// with. Caller holds f.mu.
func (f *Fake) captureConsolePasswordsLocked(name, domXML string) {
	if f.liveConsolePw == nil {
		f.liveConsolePw = map[string]map[string]string{}
	}
	pw := map[string]string{}
	for _, kind := range []string{"vnc", "spice"} {
		if p, err := libvirt.ConsolePasswordFromXML(domXML, kind); err == nil && p != "" {
			pw[kind] = p
		}
	}
	f.liveConsolePw[name] = pw
}
func (f *Fake) GetVMSpicePort(name string) (int, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.spicePorts[name]; ok {
		return p, nil
	}
	return 5930, nil
}

// SetSpicePort points a domain's SPICE console at port, so a scenario can
// stand a real listener behind ProxySpice.
func (f *Fake) SetSpicePort(name string, port int) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.spicePorts == nil {
		f.spicePorts = map[string]int{}
	}
	f.spicePorts[name] = port
}

// SetConsolePTYPath points a domain's serial console at path (a FIFO, say),
// so a scenario can carry a real serial console through ConsoleVM.
func (f *Fake) SetConsolePTYPath(name, path string) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.consolePTYs == nil {
		f.consolePTYs = map[string]string{}
	}
	f.consolePTYs[name] = path
}

func (f *Fake) ConsolePTYPath(name string) (string, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.consolePTYs[name]; ok {
		return p, nil
	}
	return "/dev/pts/fake", nil
}

// Hot-plug — record and succeed.

func (f *Fake) AttachDisk(domainName, path, targetDev, bus string) error {
	defer f.daemon()()
	if f.FailAttachDisk != nil {
		if err := f.FailAttachDisk(domainName, path, targetDev, bus); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Track the live disk source so DomainDiskSources reflects the attach (the
	// authoritative check a running-attach verification uses).
	if f.diskSources[domainName] == nil {
		f.diskSources[domainName] = map[string]string{}
	}
	f.diskSources[domainName][targetDev] = path
	// The real AttachDisk applies DomainDeviceModifyLive|Config, so the disk lands in
	// the persistent (inactive) definition too. Reflect that in f.xml (what
	// DumpXMLInactive reads) unless a scenario is modeling a live-only divergence.
	if !f.SkipConfigOnDiskMutation {
		f.xml[domainName] = insertDiskIntoDomainXML(f.xml[domainName], domainName, path, targetDev, bus)
	}
	f.attachDiskN++
	f.record("attach-disk", domainName, fmt.Sprintf("path=%s target=%s bus=%s", path, targetDev, bus))
	return nil
}
func (f *Fake) DetachDisk(domainName, targetDev string) error {
	defer f.daemon()()
	if f.FailDetachDisk != nil {
		if err := f.FailDetachDisk(domainName, targetDev); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachDiskN++
	f.record("detach-disk", domainName, "target="+targetDev)
	// The real DetachDisk runs libvirt.DetachLiveAndConfig over
	// DomainDetachDeviceFlags; so does this, over a model of that call.
	return libvirt.DetachLiveAndConfig(func(flags uint32) error {
		_, inLive := f.liveDiskSourcesLocked(domainName)[targetDev]
		return f.detachFlagsLocked(domainName, flags, f.SkipConfigOnDiskMutation,
			inLive, diskDevInDomainXML(f.xml[domainName], targetDev),
			"disk "+targetDev+" not found", "no target device "+targetDev,
			func() {
				if f.diskSources[domainName] != nil {
					delete(f.diskSources[domainName], targetDev)
				}
			},
			func() { f.xml[domainName] = removeDiskFromDomainXML(f.xml[domainName], targetDev) })
	})
}

// detachFlagsLocked models ONE virDomainDetachDeviceFlags call against a running
// domain, as qemuDomainDetachDeviceLiveAndConfig does it:
//
//   - VIR_DOMAIN_AFFECT_CONFIG needs the device in the persistent definition, and
//     VIR_DOMAIN_AFFECT_LIVE needs it in the live instance; a copy that lacks it
//     fails the call with VIR_ERR_DEVICE_MISSING ("device not found: ...").
//   - The call is ALL-OR-NOTHING: both halves are checked before either applies, so
//     a LIVE|CONFIG detach whose persistent copy is already gone does not re-issue
//     the live unplug. That is lab finding N1, and the fake used to define it away
//     by succeeding on any detach.
//   - The live half only REQUESTS the unplug (applyLiveUnplug); the config half
//     applies at once.
//
// skipConfig is a scenario's SkipConfigOn*Mutation knob: the config half is
// neither checked nor applied.
//
// A guest that ignores every request is DeferLiveUnplug with
// HonorUnplugOnRequest 0: each LIVE request is parked, none applies until
// AckLiveUnplug.
//
// Not modeled:
//   - libvirt refuses AFFECT_LIVE on a domain that is not running
//     (VIR_ERR_OPERATION_INVALID);
//   - QEMU >= 6.2 refuses a device_del for a PCIe device already "in the process
//     of unplug" for ~5 s after the last request, a non-DEVICE_MISSING error. The
//     fake accepts every re-request. Callers' re-request loops already treat a
//     failed re-request as non-fatal (waitDeviceGone), so no test depends on it.
//
// Caller holds f.mu.
func (f *Fake) detachFlagsLocked(domain string, flags uint32, skipConfig, inLive, inConfig bool,
	liveMissing, configMissing string, removeLive, removeConfig func()) error {
	config := flags&libvirt.ModifyConfig != 0 && !skipConfig
	live := flags&libvirt.ModifyLive != 0
	if config && !inConfig {
		return deviceMissingError(configMissing)
	}
	if live && !inLive {
		return deviceMissingError(liveMissing)
	}
	if live {
		// A parked live removal must act on the live view as it stands NOW. Until
		// something diverges them the fake reads the live view from the persistent
		// one, which the config half below is about to change.
		if _, ok := f.activeXML[domain]; !ok && f.DeferLiveUnplug {
			f.activeXML[domain] = f.xml[domain]
		}
		f.applyLiveUnplug(domain, removeLive)
	}
	if config {
		removeConfig()
	}
	return nil
}

// deviceMissingError is libvirt's VIR_ERR_DEVICE_MISSING as go-libvirt delivers it.
func deviceMissingError(what string) error {
	return golibvirt.Error{Code: uint32(golibvirt.ErrDeviceMissing), Message: "device not found: " + what}
}

// liveDiskSourcesLocked is DomainDiskSources' view, for a caller holding f.mu.
func (f *Fake) liveDiskSourcesLocked(domain string) map[string]string {
	out := map[string]string{}
	for k, v := range f.diskSources[domain] {
		out[k] = v
	}
	if len(out) == 0 {
		out["vda"] = "/var/lib/litevirt/disks/" + domain + "-root.qcow2"
	}
	return out
}

// diskDevInDomainXML reports whether a domain XML carries a <target dev='X'.../>
// (either quote style). Mirrors grpcapi.diskDevInXML — the substring the
// running-path membership verification keys off.
func diskDevInDomainXML(domainXML, targetDev string) bool {
	if domainXML == "" || targetDev == "" {
		return false
	}
	return strings.Contains(domainXML, "dev='"+targetDev+"'") || strings.Contains(domainXML, `dev="`+targetDev+`"`)
}

// insertDiskIntoDomainXML adds a <disk> element carrying <target dev='X'.../> to a
// domain's persistent XML, synthesizing a minimal skeleton when the domain has no
// stored XML yet (a running fake VM seeded without DefineDomain). Idempotent: an
// already-present target dev is left untouched.
func insertDiskIntoDomainXML(domainXML, domainName, path, targetDev, bus string) string {
	if domainXML == "" {
		domainXML = "<domain type='kvm'><name>" + domainName + "</name><devices></devices></domain>"
	}
	if diskDevInDomainXML(domainXML, targetDev) {
		return domainXML
	}
	disk := "<disk type='file' device='disk'><source file='" + path + "'/><target dev='" + targetDev + "' bus='" + bus + "'/></disk>"
	if strings.Contains(domainXML, "</devices>") {
		return strings.Replace(domainXML, "</devices>", disk+"</devices>", 1)
	}
	return domainXML + disk
}

// removeDiskFromDomainXML removes the <disk>…</disk> element whose <target dev>
// matches targetDev from a domain's persistent XML, leaving any other disks intact.
func removeDiskFromDomainXML(domainXML, targetDev string) string {
	if domainXML == "" {
		return domainXML
	}
	needleA := "dev='" + targetDev + "'"
	needleB := `dev="` + targetDev + `"`
	from := 0
	for {
		rel := strings.Index(domainXML[from:], "<disk")
		if rel < 0 {
			return domainXML
		}
		start := from + rel
		endRel := strings.Index(domainXML[start:], "</disk>")
		if endRel < 0 {
			return domainXML
		}
		end := start + endRel + len("</disk>")
		if block := domainXML[start:end]; strings.Contains(block, needleA) || strings.Contains(block, needleB) {
			return domainXML[:start] + domainXML[end:]
		}
		from = end
	}
}

// AttachDiskCount / DetachDiskCount return how many times the disk hot-plug
// primitives have been invoked — test accessors for at-most-once assertions.
func (f *Fake) AttachDiskCount() int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attachDiskN
}
func (f *Fake) DetachDiskCount() int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detachDiskN
}

// AttachNIC hot-attaches a NIC to domainName, tracking both the live view
// (activeXML — ALWAYS updated, mirroring a real live attach landing immediately)
// and, unless SkipConfigOnNICMutation models a live-succeeded-but-config-not-
// applied divergence, the persistent view (xml) too — the real AttachNIC applies
// DomainDeviceModifyLive|Config.
func (f *Fake) AttachNIC(domainName, bridge, model, mac string) error {
	defer f.daemon()()
	if f.FailAttachNIC != nil {
		if err := f.FailAttachNIC(domainName, bridge, model, mac); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeXML[domainName] = insertNICIntoDomainXML(f.activeBaseline(domainName), domainName, bridge, model, mac)
	if !f.SkipConfigOnNICMutation {
		f.xml[domainName] = insertNICIntoDomainXML(f.xml[domainName], domainName, bridge, model, mac)
	}
	f.attachNICN++
	f.record("attach-nic", domainName, fmt.Sprintf("bridge=%s mac=%s", bridge, mac))
	return nil
}

// DetachNIC hot-detaches a NIC from domainName by MAC, mirroring AttachNIC's
// live/persistent tracking split.
func (f *Fake) DetachNIC(domainName, mac string) error {
	defer f.daemon()()
	if f.FailDetachNIC != nil {
		if err := f.FailDetachNIC(domainName, mac); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachNICN++
	f.record("detach-nic", domainName, "mac="+mac)
	missing := "no device found at address '(<null>)' matching MAC address '" + mac + "' and alias '(<null>)'"
	return libvirt.DetachLiveAndConfig(func(flags uint32) error {
		return f.detachFlagsLocked(domainName, flags, f.SkipConfigOnNICMutation,
			nicMacInDomainXML(f.activeBaseline(domainName), mac), nicMacInDomainXML(f.xml[domainName], mac),
			missing, missing,
			func() { f.activeXML[domainName] = removeNICFromDomainXML(f.activeBaseline(domainName), mac) },
			func() { f.xml[domainName] = removeNICFromDomainXML(f.xml[domainName], mac) })
	})
}

// SetNICBridge moves domainName's NIC with MAC mac onto bridge in both the
// persistent and the live view, as the real update-device does. It records a
// "set-nic-bridge" event and never a define.
func (f *Fake) SetNICBridge(domainName, mac, bridge string) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	x, ok := libvirt.RetargetDomainXML(f.xml[domainName], mac, bridge)
	if !ok {
		return fmt.Errorf("domain %s has no bridge interface with MAC %s", domainName, mac)
	}
	f.xml[domainName] = x
	if live, ok := f.activeXML[domainName]; ok && live != "" {
		if lx, ok := libvirt.RetargetDomainXML(live, mac, bridge); ok {
			f.activeXML[domainName] = lx
		}
	}
	f.record("set-nic-bridge", domainName, fmt.Sprintf("mac=%s bridge=%s", mac, bridge))
	return nil
}

// SetNICBridgeConfig retargets the NIC in the persistent definition only.
func (f *Fake) SetNICBridgeConfig(domainName, mac, bridge string) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	x, ok := libvirt.RetargetDomainXML(f.xml[domainName], mac, bridge)
	if !ok {
		return fmt.Errorf("domain %s has no bridge interface with MAC %s", domainName, mac)
	}
	f.xml[domainName] = x
	f.record("set-nic-bridge-config", domainName, fmt.Sprintf("mac=%s bridge=%s", mac, bridge))
	return nil
}

// ReloadCDROMMedia records a live media reload of the domain's cdrom whose
// source is path ("reload-cdrom", note "path=<path>"). Like libvirt, it
// refuses a domain that is not active (running or paused).
func (f *Fake) ReloadCDROMMedia(domainName, path string) error {
	defer f.daemon()()
	if f.FailReloadCDROM != nil {
		if err := f.FailReloadCDROM(domainName, path); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if st := f.domains[domainName]; st != StateRunning && st != StatePaused {
		return fmt.Errorf("domain %s is not active", domainName)
	}
	f.record("reload-cdrom", domainName, "path="+path)
	return nil
}

// nicMacInDomainXML reports whether a domain XML carries an <interface> with the
// given MAC address (case-insensitive — real libvirt normalizes MAC case, and
// callers may supply either). Mirrors grpcapi.nicMacInXML — the substring the
// hotplug NIC membership verification keys off.
func nicMacInDomainXML(domainXML, mac string) bool {
	if domainXML == "" || mac == "" {
		return false
	}
	lx := strings.ToLower(domainXML)
	lm := strings.ToLower(mac)
	return strings.Contains(lx, "address='"+lm+"'") || strings.Contains(lx, `address="`+lm+`"`)
}

// insertNICIntoDomainXML adds an <interface> element carrying the given MAC to a
// domain's XML, synthesizing a minimal skeleton when the domain has no XML yet.
// Idempotent: an already-present MAC is left untouched.
func insertNICIntoDomainXML(domainXML, domainName, bridge, model, mac string) string {
	if domainXML == "" {
		domainXML = "<domain type='kvm'><name>" + domainName + "</name><devices></devices></domain>"
	}
	if nicMacInDomainXML(domainXML, mac) {
		return domainXML
	}
	target := ""
	if tap := nictap.Name(mac); tap != "" {
		target = "<target dev='" + tap + "'/>" // as libvirt.Client.AttachNIC names it
	}
	iface := "<interface type='bridge'><source bridge='" + bridge + "'/>" +
		"<mac address='" + mac + "'/>" + target + "<model type='" + model + "'/></interface>"
	if strings.Contains(domainXML, "</devices>") {
		return strings.Replace(domainXML, "</devices>", iface+"</devices>", 1)
	}
	return domainXML + iface
}

// removeNICFromDomainXML removes the <interface>…</interface> element whose <mac
// address> matches mac from a domain's XML, leaving any other interfaces intact.
// Case-insensitive matching mirrors nicMacInDomainXML; indices are computed on a
// lower-cased copy but sliced from the original (ASCII-only XML, so byte offsets
// align) to preserve the original text's casing.
func removeNICFromDomainXML(domainXML, mac string) string {
	if domainXML == "" {
		return domainXML
	}
	lm := strings.ToLower(mac)
	needleA := "address='" + lm + "'"
	needleB := `address="` + lm + `"`
	lx := strings.ToLower(domainXML)
	from := 0
	for {
		rel := strings.Index(lx[from:], "<interface")
		if rel < 0 {
			return domainXML
		}
		start := from + rel
		endRel := strings.Index(lx[start:], "</interface>")
		if endRel < 0 {
			return domainXML
		}
		end := start + endRel + len("</interface>")
		if block := lx[start:end]; strings.Contains(block, needleA) || strings.Contains(block, needleB) {
			return domainXML[:start] + domainXML[end:]
		}
		from = end
	}
}

// AttachNICCount / DetachNICCount return how many times the NIC hot-plug primitives
// have been invoked — test accessors for at-most-once assertions.
func (f *Fake) AttachNICCount() int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attachNICN
}
func (f *Fake) DetachNICCount() int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detachNICN
}

// AttachHostdev hot-attaches a PCI passthrough device WITHOUT a user alias — the
// legacy SR-IOV/type running-only path. It models the live+persistent membership
// (keyed on the pci address for later detach) exactly like AttachHostdevWithAlias
// with an empty alias.
func (f *Fake) AttachHostdev(domainName, pciAddress string) error {
	defer f.daemon()()
	return f.AttachHostdevWithAlias(domainName, pciAddress, "")
}

// AttachHostdevWithAlias hot-attaches a PCI passthrough device carrying a stable
// user alias (ua-<device>-<member>), tracking both the live view (activeXML —
// always updated, mirroring a real live attach landing immediately) and, unless
// SkipConfigOnHostdevMutation models a live-succeeded-but-config-not-applied
// divergence, the persistent view (xml) too — the real attach applies
// DomainDeviceModifyLive|Config.
func (f *Fake) AttachHostdevWithAlias(domainName, pciAddress, alias string) error {
	defer f.daemon()()
	if f.FailAttachHostdev != nil {
		if err := f.FailAttachHostdev(domainName, pciAddress, alias); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeXML[domainName] = insertHostdevIntoDomainXML(f.activeBaseline(domainName), domainName, pciAddress, alias)
	if !f.SkipConfigOnHostdevMutation {
		f.xml[domainName] = insertHostdevIntoDomainXML(f.xml[domainName], domainName, pciAddress, alias)
	}
	f.attachHostdevN++
	f.record("attach-hostdev", domainName, fmt.Sprintf("pci=%s alias=%s", pciAddress, alias))
	return nil
}

// DetachHostdev hot-detaches a PCI passthrough device by its pci address,
// mirroring AttachHostdevWithAlias's live/persistent tracking split.
func (f *Fake) DetachHostdev(domainName, pciAddress string) error {
	defer f.daemon()()
	if f.FailDetachHostdev != nil {
		if err := f.FailDetachHostdev(domainName, pciAddress); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachHostdevN++
	f.record("detach-hostdev", domainName, "pci="+pciAddress)
	return libvirt.DetachLiveAndConfig(func(flags uint32) error {
		return f.detachFlagsLocked(domainName, flags, f.SkipConfigOnHostdevMutation,
			hostdevPCIInDomainXML(f.activeBaseline(domainName), pciAddress),
			hostdevPCIInDomainXML(f.xml[domainName], pciAddress),
			"host pci device "+pciAddress+" not found", "device not present in domain configuration",
			func() {
				f.activeXML[domainName] = removeHostdevFromDomainXML(f.activeBaseline(domainName), pciAddress)
			},
			func() { f.xml[domainName] = removeHostdevFromDomainXML(f.xml[domainName], pciAddress) })
	})
}

// hostdevPCIInDomainXML reports whether a domain XML carries the <hostdev> whose
// data-pci attribute is pciAddress — the key DetachHostdev removes by.
func hostdevPCIInDomainXML(domainXML, pciAddress string) bool {
	return removeHostdevFromDomainXML(domainXML, pciAddress) != domainXML
}

// DetachHostdevConfig removes a PCI passthrough device from the PERSISTENT (inactive)
// view ONLY — the config-only detach a shut-off domain requires. Unlike DetachHostdev it
// never touches the live view (activeXML): there is no live instance to modify. It counts
// separately (detachHostdevConfigN) so a test can assert the config path (not the live
// one) was used on a shut-off domain.
func (f *Fake) DetachHostdevConfig(domainName, pciAddress string) error {
	defer f.daemon()()
	if f.FailDetachHostdevConfig != nil {
		if err := f.FailDetachHostdevConfig(domainName, pciAddress); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.xml[domainName] = removeHostdevFromDomainXML(f.xml[domainName], pciAddress)
	f.detachHostdevConfigN++
	f.record("detach-hostdev-config", domainName, "pci="+pciAddress)
	return nil
}

// AttachHostdevCount / DetachHostdevCount return how many times the hostdev
// hot-plug primitives have been invoked — test accessors for at-most-once
// assertions.
func (f *Fake) AttachHostdevCount() int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attachHostdevN
}
func (f *Fake) DetachHostdevCount() int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detachHostdevN
}

// DetachHostdevConfigCount returns how many times the CONFIG-only hostdev detach has been
// invoked — the shut-off reclaim path's at-most-once / config-vs-live test accessor.
func (f *Fake) DetachHostdevConfigCount() int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detachHostdevConfigN
}

// hostdevAliasInDomainXML reports whether a domain XML carries a <hostdev> whose
// <alias name=...> matches alias (either quote style). Mirrors
// grpcapi.hostdevAliasInXML — the substring the running-path hostdev membership
// verification keys off.
func hostdevAliasInDomainXML(domainXML, alias string) bool {
	if domainXML == "" || alias == "" {
		return false
	}
	return strings.Contains(domainXML, "name='"+alias+"'") || strings.Contains(domainXML, `name="`+alias+`"`)
}

// insertHostdevIntoDomainXML adds a <hostdev> element carrying the pci address
// (as a data-pci attribute so DetachHostdev can match it) and, when non-empty, an
// <alias> child, to a domain's XML — synthesizing a minimal skeleton when the
// domain has no XML yet. Idempotent on the alias when one is set.
func insertHostdevIntoDomainXML(domainXML, domainName, pciAddress, alias string) string {
	if domainXML == "" {
		domainXML = "<domain type='kvm'><name>" + domainName + "</name><devices></devices></domain>"
	}
	if alias != "" && hostdevAliasInDomainXML(domainXML, alias) {
		return domainXML
	}
	hd := "<hostdev mode='subsystem' type='pci' managed='yes' data-pci='" + pciAddress + "'>"
	// Emit the <source><address> the way real libvirt does so
	// libvirt.HostdevSourcePCIAddresses (the by-source-BDF membership authority the
	// legacy detach path reads — legacy hostdevs carry no alias) can find this device.
	if p, ok := libvirt.ParsePCIAddress(pciAddress); ok {
		hd += "<source><address domain='" + p.Domain + "' bus='" + p.Bus +
			"' slot='" + p.Slot + "' function='" + p.Function + "'/></source>"
	}
	if alias != "" {
		hd += "<alias name='" + alias + "'/>"
	}
	hd += "</hostdev>"
	if strings.Contains(domainXML, "</devices>") {
		return strings.Replace(domainXML, "</devices>", hd+"</devices>", 1)
	}
	return domainXML + hd
}

// removeHostdevFromDomainXML removes the <hostdev>…</hostdev> element whose
// data-pci attribute matches pciAddress, leaving any other hostdevs intact.
func removeHostdevFromDomainXML(domainXML, pciAddress string) string {
	if domainXML == "" {
		return domainXML
	}
	needleA := "data-pci='" + pciAddress + "'"
	needleB := `data-pci="` + pciAddress + `"`
	from := 0
	for {
		rel := strings.Index(domainXML[from:], "<hostdev")
		if rel < 0 {
			return domainXML
		}
		start := from + rel
		endRel := strings.Index(domainXML[start:], "</hostdev>")
		if endRel < 0 {
			return domainXML
		}
		end := start + endRel + len("</hostdev>")
		if block := domainXML[start:end]; strings.Contains(block, needleA) || strings.Contains(block, needleB) {
			return domainXML[:start] + domainXML[end:]
		}
		from = end
	}
}
func (f *Fake) BlockResize(domainName, path string, sizeBytes int64) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("block-resize", domainName, fmt.Sprintf("path=%s size=%d", path, sizeBytes))
	return nil
}

// SetDiskIOTune models the real client: the persistent definition takes the
// throttle, and so does the live view of a running domain, so a test reads
// either back with DumpXML / DumpXMLInactive. Like libvirt it refuses a disk
// the definition does not carry and a throttle libvirt would refuse.
func (f *Fake) SetDiskIOTune(domainName, dev string, t libvirt.IOTune) error {
	defer f.daemon()()
	if f.FailSetDiskIOTune != nil {
		if err := f.FailSetDiskIOTune(domainName, dev); err != nil {
			return err
		}
	}
	if err := t.Validate(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[domainName]
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not found", domainName)
	}
	persisted, err := libvirt.PatchDiskIOTune(f.xml[domainName], dev, t)
	if err != nil {
		return fmt.Errorf("libvirtfake: set I/O limits on %q: %w", domainName, err)
	}
	f.xml[domainName] = persisted
	if f.FailSetDiskIOTuneLive != nil && (st == StateRunning || st == StatePaused) {
		if err := f.FailSetDiskIOTuneLive(domainName, dev); err != nil {
			return err
		}
	}
	if live, ok := f.activeXML[domainName]; ok && (st == StateRunning || st == StatePaused) {
		if patched, perr := libvirt.PatchDiskIOTune(live, dev, t); perr == nil {
			f.activeXML[domainName] = patched
		}
	}
	f.record("set-iotune", domainName, fmt.Sprintf("dev=%s %+v", dev, t))
	return nil
}

func (f *Fake) SetBootOrder(domainName, bootOrder string) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpDefine, Name: domainName}); err != nil {
		return fmt.Errorf("redefine domain %s: %w", domainName, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("boot-order", domainName, bootOrder)
	return nil
}

// Migration — record and pretend success.

func (f *Fake) MigrateToTarget(name, dconnuri string, p libvirt.MigrateParams) error {
	// p stays reachable until this frame's last deferred call has run. A
	// goroutine ended inside the hook (OnMigrateToTarget) runs them with p
	// unread since the hook was called, and the Go runtime then scans p
	// through the Goexit's _panic record (its fp is p's address): what p
	// held must not have been freed by then.
	defer runtime.KeepAlive(&p)
	defer f.daemon()()
	// The flags libvirt.Client would send: what it refuses never reaches
	// libvirt, a guest it asks libvirt to pause arrives paused (D2-4 m-2),
	// and a source it does not ask libvirt to undefine stays defined.
	paused, undefineSource, err := libvirt.MigrationOutcome(p)
	if err != nil {
		return fmt.Errorf("domain %q: %w", name, err)
	}
	p.Paused = paused
	if f.FailMigrateToTarget != nil {
		if err := f.FailMigrateToTarget(name, dconnuri); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// The parameters a test asserts on: whether the disks were copied, and
	// which ones (libvirt's migrate_disks; empty means every writable disk).
	note := fmt.Sprintf("to=%s with_storage=%t disks=%s tls=%t tls_dest=%s addr=%s direct=%t",
		dconnuri, p.WithStorage, strings.Join(p.DiskTargets, ","), p.TLS, p.TLSDestination, p.TargetAddress, p.Direct)
	note += fmt.Sprintf(" shares_weight=%d target_cgroup=%s", p.SharesWeight, p.TargetCgroup)
	if p.StripVNCPassword {
		note += " strip_vnc_password=true"
	}
	if len(p.CDROMSources) > 0 {
		// As libvirt would: the destination definition must still carry each
		// CD-ROM being pointed elsewhere.
		live := f.activeBaseline(name)
		if _, _, err := libvirt.MigrationCDROMXML(live, f.xml[name], p.CDROMSources); err != nil {
			return err
		}
		var pairs []string
		for from, to := range p.CDROMSources {
			pairs = append(pairs, from+"->"+to)
		}
		sort.Strings(pairs)
		note += " cdroms=" + strings.Join(pairs, ",")
	}
	if p.Paused {
		note += " paused=true"
	}
	if p.FirmwareLive {
		note += " firmware_live=true"
	}
	if len(p.RBDLocators) > 0 {
		var names []string
		for n := range p.RBDLocators {
			names = append(names, n)
		}
		sort.Strings(names)
		note += " rbd=" + strings.Join(names, ",")
	}
	if len(p.NICBridges) > 0 {
		var pairs []string
		for mac, b := range p.NICBridges {
			pairs = append(pairs, mac+"->"+b)
		}
		sort.Strings(pairs)
		note += " nic_bridges=" + strings.Join(pairs, ",")
	}
	f.record("migrate", name, note)
	// The destination and persistent definitions libvirt.Client.MigrateToTarget
	// would hand libvirt (from the secure migratable XML), so a hook can land
	// exactly those. Empty: libvirt carries the domain as it is. Only for a
	// move that strips the VNC password or moves NICs: the other rewrites
	// resolve against the host (rbd monitors, the cgroup scale).
	if p.DestXML == "" && (p.StripVNCPassword || len(p.NICBridges) > 0) {
		dest, persist, err := libvirt.MigrationDefinitionsFor(libvirt.MigrateParams{StripVNCPassword: p.StripVNCPassword, NICBridges: p.NICBridges},
			f.liveXMLLocked(name), f.xml[name])
		if err != nil {
			return err
		}
		p.DestXML, p.PersistXML = dest, persist
	}
	if cb := f.OnMigrateToTarget; cb != nil {
		var err error
		f.outsideLock(func() { err = cb(name, dconnuri, p) })
		if err != nil {
			return err
		}
	}
	// Probe (b): without UNDEFINE_SOURCE the source stays defined, shut off,
	// reason migrated. The source of an ordinary migrate is not modelled:
	// the fake leaves it as it was.
	if !undefineSource {
		f.migratedOutLocked(name)
	}
	return nil
}

func (f *Fake) DomainJobProgress(name string) (memPct, diskPct float32) {
	defer f.daemon()()
	return 100, 100
}

// DomainJobActive answers JobActive when it is set, else no job: the fake's
// MigrateToTarget returns before anything could ask.
func (f *Fake) DomainJobActive(name string) (bool, error) {
	defer f.daemon()()
	f.mu.Lock()
	job := f.JobActive
	f.mu.Unlock()
	if job != nil {
		return job(name)
	}
	return false, nil
}

// Snapshots.

func (f *Fake) CreateSnapshot(domainName, snapshotName string) (int64, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snapshots[domainName] == nil {
		f.snapshots[domainName] = map[string]struct{}{}
	}
	f.snapshots[domainName][snapshotName] = struct{}{}
	f.cutoverDisks(domainName, snapshotName)
	f.record("snapshot", domainName, snapshotName)
	return time.Now().UnixNano(), nil
}
func (f *Fake) RevertToSnapshot(domainName, snapshotName string, restorePreDefine func() error) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpStart, Name: domainName}); err != nil {
		return fmt.Errorf("revert %s: %w", domainName, err)
	}
	f.mu.Lock()
	if _, ok := f.snapshots[domainName][snapshotName]; !ok {
		f.mu.Unlock()
		return fmt.Errorf("libvirtfake: no snapshot %q for %q", snapshotName, domainName)
	}
	f.record("revert", domainName, snapshotName)
	hook, notCurrent := f.OnRevertSnapshot, f.RevertNotCurrent
	f.mu.Unlock()
	if hook != nil {
		hook(domainName, snapshotName)
	}
	if restorePreDefine != nil {
		if err := restorePreDefine(); err != nil {
			return err
		}
	}
	if notCurrent {
		return &libvirt.RestoredNotCurrentError{Snapshot: snapshotName, Registered: true, Err: errors.New("libvirtfake: CURRENT refused")}
	}
	return nil
}
func (f *Fake) DeleteSnapshot(domainName, snapshotName string) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.snapshots[domainName], snapshotName)
	delete(f.snapshotFiles[domainName], snapshotName)
	f.record("snapshot-delete", domainName, snapshotName)
	if len(f.DeleteSnapshotKeeps) > 0 {
		return &libvirt.SnapshotFilesKeptError{Snapshot: snapshotName, Reason: "libvirtfake: metadata only",
			Files: append([]string(nil), f.DeleteSnapshotKeeps...)}
	}
	return nil
}
func (f *Fake) FlattenSnapshot(domainName, snapshotName string) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.snapshots[domainName][snapshotName]; !ok {
		return fmt.Errorf("libvirtfake: no snapshot %q for %q", snapshotName, domainName)
	}
	delete(f.snapshots[domainName], snapshotName)
	delete(f.snapshotFiles[domainName], snapshotName)
	f.record("snapshot-flatten", domainName, snapshotName)
	return nil
}

// CreateLiveSnapshot mirrors libvirt.Client.CreateLiveSnapshot: the firmware
// move guard is asked for a start and a resume, then the production capture
// runs over the fake's model of libvirt (memsnap.go).
func (f *Fake) CreateLiveSnapshot(domainName, snapshotName, vmstatePath string, o libvirt.CaptureOptions) (diskBytes, vmstateBytes int64, err error) {
	defer f.daemon()()
	for _, op := range []libvirt.FirmwareOp{libvirt.OpStart, libvirt.OpResume} {
		if err := f.fwCheck(libvirt.FirmwareCall{Op: op, Name: domainName}); err != nil {
			return 0, 0, libvirt.NotTakenCapture(fmt.Errorf("memory snapshot of %q: %w", domainName, err))
		}
	}
	return libvirt.CaptureMemorySnapshot(captureAPI{f}, domainName, snapshotName, vmstatePath, o)
}

// SetDiskSource sets a domain's disk source (test helper).
func (f *Fake) SetDiskSource(domain, dev, src string) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.diskSources[domain] == nil {
		f.diskSources[domain] = map[string]string{}
	}
	f.diskSources[domain][dev] = src
}

// DomainDiskSources returns target-dev → live source. Defaults to a single
// vda disk if nothing was configured for the domain.
func (f *Fake) DomainDiskSources(domain string) (map[string]string, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if fail := f.FailDomainDiskSources; fail != nil {
		if err := fail(domain); err != nil {
			return nil, err
		}
	}
	return f.liveDiskSourcesLocked(domain), nil
}

// cutoverDisks simulates libvirt's external-snapshot overlay rename: each disk
// source <stem>.<ext> becomes <stem>.<snapname>. Caller holds f.mu.
func (f *Fake) cutoverDisks(domain, snapname string) {
	if f.diskSources[domain] == nil {
		f.diskSources[domain] = map[string]string{"vda": "/var/lib/litevirt/disks/" + domain + "-root.qcow2"}
	}
	if f.snapshotFiles == nil {
		f.snapshotFiles = map[string]map[string][]string{}
	}
	if f.snapshotFiles[domain] == nil {
		f.snapshotFiles[domain] = map[string][]string{}
	}
	var files []string
	for dev, src := range f.diskSources[domain] {
		ov := strings.TrimSuffix(src, filepath.Ext(src)) + "." + snapname
		f.diskSources[domain][dev] = ov
		files = append(files, ov, src)
	}
	sort.Strings(files)
	f.snapshotFiles[domain][snapname] = files
}

// SetFailDomainDiskSources sets FailDomainDiskSources under the fake's lock,
// for a test that changes it while the server may be reading it.
func (f *Fake) SetFailDomainDiskSources(fn func(domain string) error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.FailDomainDiskSources = fn
}

// DomainDiskFormats returns the disks of the domain's definition as source
// file → driver type; a domain the fake has no definition of is not found.
func (f *Fake) DomainDiskFormats(domainName string) (map[string]string, error) {
	defer f.daemon()()
	f.mu.Lock()
	x := f.liveXMLLocked(domainName)
	f.mu.Unlock()
	if x == "" {
		return nil, fmt.Errorf("libvirtfake: domain %q not found", domainName)
	}
	return libvirt.DiskFormatsFromXML(x), nil
}

// SnapshotDiskFiles returns the overlay and base of each disk the snapshot
// cut over, as recorded at its creation.
func (f *Fake) SnapshotDiskFiles(domainName, snapshotName string) ([]string, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.snapshots[domainName][snapshotName]; !ok {
		return nil, fmt.Errorf("libvirtfake: no domain snapshot with matching name %q for %q", snapshotName, domainName)
	}
	return append([]string(nil), f.snapshotFiles[domainName][snapshotName]...), nil
}

// SetSavedImageXML sets the definition a memory snapshot's saved image at
// vmstatePath carries (default: the domain's definition when reverted).
func (f *Fake) SetSavedImageXML(vmstatePath, xml string) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.savedImageXML == nil {
		f.savedImageXML = map[string]string{}
	}
	f.savedImageXML[vmstatePath] = xml
}

func (f *Fake) RevertToLiveSnapshot(domainName, snapshotName, vmstatePath string, restorePreDefine func() error, rewriteSaved func(savedXML string) (string, error)) error {
	defer f.daemon()()
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpStart, Name: domainName}); err != nil {
		return fmt.Errorf("revert %s: %w", domainName, err)
	}
	// As libvirt.revertToLiveSnapshot: nothing is torn down when the RAM
	// image is gone, and the restore reads it back.
	gen, err := readVMState(vmstatePath, domainName)
	if err != nil {
		return fmt.Errorf("vmstate image %q missing — cannot restore memory snapshot: %w", vmstatePath, err)
	}
	f.mu.Lock()
	if _, ok := f.snapshots[domainName][snapshotName]; !ok {
		f.mu.Unlock()
		return fmt.Errorf("libvirtfake: no snapshot %q for %q", snapshotName, domainName)
	}
	saved, ok := f.savedImageXML[vmstatePath]
	if !ok {
		saved = f.xml[domainName]
	}
	hook := f.OnRevertSnapshot
	f.mu.Unlock()
	if hook != nil {
		hook(domainName, snapshotName)
	}
	restoreXML := ""
	if rewriteSaved != nil {
		rewritten, err := rewriteSaved(saved)
		if err != nil {
			return err
		}
		if rewritten != saved {
			restoreXML, saved = rewritten, rewritten
		}
	}
	if restorePreDefine != nil {
		if err := restorePreDefine(); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("revert-live", domainName, snapshotName+" dxml="+restoreXML)
	// The restore is a new QEMU process, holding the image's memory.
	ms := f.memLocked(domainName)
	ms.qemuStarts++
	if gen >= 0 {
		ms.gen = gen
	}
	if saved != "" {
		f.xml[domainName] = saved
	}
	if f.RevertNotCurrent {
		return &libvirt.RestoredNotCurrentError{Snapshot: snapshotName, Registered: true, Err: errors.New("libvirtfake: CURRENT refused")}
	}
	return nil
}

func (f *Fake) FreezeGuest(domainName string) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("fs-freeze", domainName, "")
	return nil
}

func (f *Fake) ThawGuest(domainName string) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("fs-thaw", domainName, "")
	return nil
}

func (f *Fake) SetMemory(domainName string, memMiB int) error {
	defer f.daemon()()
	if f.FailSetMemory != nil {
		if err := f.FailSetMemory(domainName, memMiB); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("set-memory", domainName, fmt.Sprintf("%d", memMiB))
	return nil
}

// SetVirtioMemRequested models plugging memory into a hot-add domain: the
// virtio-mem element's <requested> is rewritten in the persistent definition
// and, when one is tracked, the live view — so DumpXML shows what libvirt
// would. A domain with no virtio-mem device errors, as libvirt does.
func (f *Fake) SetVirtioMemRequested(domainName string, requestedMiB int) error {
	defer f.daemon()()
	if f.FailSetVirtioMem != nil {
		if err := f.FailSetVirtioMem(domainName, requestedMiB); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.xml[domainName]
	if !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", domainName)
	}
	rewrite := func(doc string) (string, error) {
		elem, err := libvirt.VirtioMemUpdateXML(doc, requestedMiB)
		if err != nil {
			return "", err
		}
		return virtioMemElemRe.ReplaceAllLiteralString(doc, elem), nil
	}
	next, err := rewrite(cur)
	if err != nil {
		return err
	}
	f.xml[domainName] = next
	if live, ok := f.activeXML[domainName]; ok {
		if nl, lerr := rewrite(live); lerr == nil {
			f.activeXML[domainName] = nl
		}
	}
	f.record("set-virtio-mem", domainName, fmt.Sprintf("%d", requestedMiB))
	return nil
}

// virtioMemElemRe matches the virtio-mem element SetVirtioMemRequested
// rewrites (the same shape libvirt.VirtioMemUpdateXML reads).
var virtioMemElemRe = regexp.MustCompile(`(?s)<memory\b[^>]*\bmodel=['"]virtio-mem['"][^>]*>.*?</memory>`)

func (f *Fake) SetVCPUs(name string, count int) error {
	defer f.daemon()()
	if f.FailSetVCPUs != nil {
		if err := f.FailSetVCPUs(name, count); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("set-vcpus", name, fmt.Sprintf("%d", count))
	return nil
}

// SetCPUTune models the libvirt scheduler-parameter write: it patches the
// persistent XML and, for a running domain with a live override, the live XML,
// exactly as the real primitive's config-then-live apply does.
func (f *Fake) SetCPUTune(name string, limit float64, shares int) error {
	defer f.daemon()()
	// Refuse what the real primitive refuses, so a caller cannot pass a value the
	// fake accepts and libvirt would not.
	if err := libvirt.ValidateCPUShares(shares); err != nil {
		return err
	}
	if limit < 0 {
		return fmt.Errorf("libvirtfake: negative cpu limit %v", limit)
	}
	if f.FailSetCPUTune != nil {
		if err := f.FailSetCPUTune(name, limit, shares); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("libvirtfake: domain %q not found", name)
	}
	patch := func(x string) string {
		out, err := libvirt.PatchInactiveCPUTune(x, limit, shares)
		if err != nil {
			return x
		}
		return out
	}
	if x, ok := f.xml[name]; ok {
		f.xml[name] = patch(x)
	}
	if x, ok := f.activeXML[name]; ok {
		f.activeXML[name] = patch(x)
	}
	f.record("set-cputune", name, fmt.Sprintf("limit=%g shares=%d", limit, shares))
	return nil
}

// SetNICRate models the libvirt interface-parameter write (see SetCPUTune).
func (f *Fake) SetNICRate(name, mac string, rateMBps float64) error {
	defer f.daemon()()
	if err := libvirt.ValidateNICRate(rateMBps); err != nil {
		return err
	}
	if f.FailSetNICRate != nil {
		if err := f.FailSetNICRate(name, mac, rateMBps); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("libvirtfake: domain %q not found", name)
	}
	found := false
	if x, ok := f.xml[name]; ok {
		if out, hit := libvirt.PatchInterfaceBandwidth(x, mac, rateMBps); hit {
			f.xml[name], found = out, true
		}
	}
	if x, ok := f.activeXML[name]; ok {
		if out, hit := libvirt.PatchInterfaceBandwidth(x, mac, rateMBps); hit {
			f.activeXML[name], found = out, true
		}
	}
	if !found {
		return fmt.Errorf("libvirtfake: domain %q has no interface %s", name, mac)
	}
	f.record("set-nic-rate", name, fmt.Sprintf("%s=%g", mac, rateMBps))
	return nil
}

// Stats / introspection.

func (f *Fake) NodeInfo() (cpus int, memMiB int, err error) {
	defer f.daemon()()
	return 8, 32 * 1024, nil
}

// CompareCPU answers the migration CPU preflight. The default is Superset — a
// fake host runs anything — so no existing scenario changes behavior. Set
// CPUCompareResult (or FailCompareCPU) to model a destination whose CPU is
// poorer than the guest needs.
func (f *Fake) CompareCPU(cpuXML, machine string) (libvirt.CPUCompare, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.comparedCPUXML = append(f.comparedCPUXML, cpuXML)
	f.comparedMachines = append(f.comparedMachines, machine)
	if f.FailCompareCPU != nil {
		if err := f.FailCompareCPU(cpuXML); err != nil {
			return libvirt.CPUCompareIncompatible, err
		}
	}
	if f.CPUCompareResult != nil {
		return *f.CPUCompareResult, nil
	}
	if f.HostModelFeatures != nil {
		have := make(map[string]bool, len(f.HostModelFeatures))
		for _, name := range f.HostModelFeatures {
			have[name] = true
		}
		for _, name := range requiredCPUFeatures(cpuXML) {
			if !have[name] {
				return libvirt.CPUCompareIncompatible, nil
			}
		}
		return libvirt.CPUCompareIdentical, nil
	}
	return libvirt.CPUCompareSuperset, nil
}

// HostModelCPUFeatures reports HostModelFeatures as the host's domcapabilities
// host-model list. Without one set it errors, as a host whose host-model
// cannot be read would, so the source keeps the guest's requirement verbatim.
func (f *Fake) HostModelCPUFeatures(machine string) (map[string]bool, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.HostModelFeatures == nil {
		return nil, errors.New("libvirtfake: no host-model features configured")
	}
	out := make(map[string]bool, len(f.HostModelFeatures))
	for _, name := range f.HostModelFeatures {
		out[name] = true
	}
	return out, nil
}

// ComparedMachines returns, in order, the machine type of every CompareCPU.
func (f *Fake) ComparedMachines() []string {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.comparedMachines...)
}

// requiredCPUFeatures lists the names of a <cpu> element's
// <feature policy='require'> children.
func requiredCPUFeatures(cpuXML string) []string {
	var cpu struct {
		Features []struct {
			Policy string `xml:"policy,attr"`
			Name   string `xml:"name,attr"`
		} `xml:"feature"`
	}
	if err := xml.Unmarshal([]byte(cpuXML), &cpu); err != nil {
		return nil
	}
	var out []string
	for _, ft := range cpu.Features {
		if ft.Policy == "require" {
			out = append(out, ft.Name)
		}
	}
	return out
}

// HostCPUXML returns the fake host's CPU element. HostCPUModel (default
// "fake-host-cpu") names the model, so two fakes in one fleet test can be given
// deliberately different host CPUs.
func (f *Fake) HostCPUXML() (string, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailHostCPUXML != nil {
		if err := f.FailHostCPUXML(); err != nil {
			return "", err
		}
	}
	model := f.HostCPUModel
	if model == "" {
		model = "fake-host-cpu"
	}
	return "<cpu mode='custom' match='exact'><model>" + model + "</model></cpu>", nil
}

// ComparedCPUXML returns, in order, every cpu XML CompareCPU was asked about —
// so a test can prove the preflight asked the DESTINATION, and asked it about
// the right CPU, rather than passing because nothing was checked.
func (f *Fake) ComparedCPUXML() []string {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.comparedCPUXML...)
}
func (f *Fake) GetDomainStats(name string) (*libvirt.DomainStats, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.stats[name]; ok {
		return s, nil
	}
	return &libvirt.DomainStats{Name: name}, nil
}
func (f *Fake) GetAllDomainStats() ([]*libvirt.DomainStats, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*libvirt.DomainStats, 0, len(f.domains))
	for n := range f.domains {
		if s, ok := f.stats[n]; ok {
			out = append(out, s)
		} else {
			out = append(out, &libvirt.DomainStats{Name: n})
		}
	}
	return out, nil
}

// SetExecResult programs what the next ExecInGuestDetailed calls report. A
// non-zero code is a command that RAN and failed, not a failure to run it —
// the distinction `lv exec` depends on.
func (f *Fake) SetExecResult(stdout, stderr string, exitCode int32) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execStdout, f.execStderr, f.execExitCode = stdout, stderr, exitCode
}

func (f *Fake) ExecInGuestDetailed(name, command string, args []string) ([]byte, []byte, int32, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("exec-in-guest", name, command)
	return []byte(f.execStdout), []byte(f.execStderr), f.execExitCode, nil
}

func (f *Fake) ExecInGuest(name, command string, args []string) (string, error) {
	defer f.daemon()()
	out, errOut, code, err := f.ExecInGuestDetailed(name, command, args)
	combined := string(out) + string(errOut)
	if err != nil {
		return combined, err
	}
	if code != 0 {
		return combined, fmt.Errorf("guest command exited %d", code)
	}
	return combined, nil
}

func (f *Fake) EnsureStoragePool(name, driver, source, target string, opts map[string]string) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ensure-pool", name, driver)
	return nil
}

// PoolDestroyIfDefined records the libvirt-undefine belt-and-suspenders step on
// pool delete. Idempotent in the real client (no-op when the pool isn't defined);
// here it always records so a test can assert the delete path reached it. A
// FailPoolDestroy hook lets a scenario model an undefine failure.
func (f *Fake) PoolDestroyIfDefined(name string) error {
	defer f.daemon()()
	if f.FailPoolDestroy != nil {
		if err := f.FailPoolDestroy(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("pool-destroy", name, "")
	return nil
}

// ConfigureVLANTap mirrors libvirt.Client.ConfigureVLANTap: it needs the
// domain active (only then has its NIC a tap), and FailConfigureVLANTap can
// refuse it.
func (f *Fake) ConfigureVLANTap(domainName, bridge, mac string, vlanID int) error {
	defer f.daemon()()
	if hook := f.FailConfigureVLANTap; hook != nil {
		if err := hook(domainName, mac, vlanID); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if st := f.domains[domainName]; st != StateRunning && st != StatePaused {
		return fmt.Errorf("find tap for %s/%s: libvirtfake: domain is not active, so its NIC has no tap", domainName, mac)
	}
	f.record("vlan-tap", domainName, fmt.Sprintf("bridge=%s mac=%s vlan=%d", bridge, mac, vlanID))
	return nil
}

// NegotiateTrunkVLANs mirrors libvirt.Client.NegotiateTrunkVLANs, the domain
// active as ConfigureVLANTap needs it.
func (f *Fake) NegotiateTrunkVLANs(domainName, bridge, mac string, vlanIDs []int) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if st := f.domains[domainName]; st != StateRunning && st != StatePaused {
		return fmt.Errorf("find tap for %s/%s: libvirtfake: domain is not active, so its NIC has no tap", domainName, mac)
	}
	f.record("trunk-tap", domainName, fmt.Sprintf("bridge=%s mac=%s vlans=%v", bridge, mac, vlanIDs))
	return nil
}

// fakeMACAttr finds the MACs in a fake domain XML (xmlgen output or the
// fake's own string-built NICs).
var fakeMACAttr = regexp.MustCompile(`<mac\s+address=["']([^"']+)["']`)

// RunningDomainTaps is libvirt.Client.RunningDomainTaps over the fake: every
// active domain, every MAC in its live XML, each with the tap TapDevice
// would report.
func (f *Fake) RunningDomainTaps() (map[string]map[string]string, error) {
	defer f.daemon()()
	if f.FailRunningDomainTaps != nil {
		if err := f.FailRunningDomainTaps(); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]map[string]string{}
	for name, st := range f.domains {
		if st != StateRunning && st != StatePaused {
			continue
		}
		taps := map[string]string{}
		for _, m := range fakeMACAttr.FindAllStringSubmatch(f.liveXMLLocked(name), -1) {
			mac := strings.ToLower(m[1])
			taps[mac] = f.tapLocked(name, mac)
		}
		out[name] = taps
	}
	return out, nil
}

// tapKey names one NIC in one run of a domain.
type tapKey struct {
	domain string
	run    int
	mac    string
}

// TapDevice returns the host device of the domain's NIC with this MAC, as
// libvirt reports it in the live XML: only while the domain is active, only for
// a NIC the live definition has, and a fresh vnetN for every run of the
// domain. A real libvirt hands out the next free vnetN at each start, so a
// recorded name goes stale on a stop and start; returning the same name for
// ever would hide exactly that.
func (f *Fake) TapDevice(domainName, mac string) (string, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.domains[domainName]
	if !ok {
		return "", fmt.Errorf("libvirtfake: domain %q not defined", domainName)
	}
	if st != StateRunning && st != StatePaused {
		return "", fmt.Errorf("libvirtfake: domain %q is not active (%s): no target dev for interface %s", domainName, st, mac)
	}
	mac = strings.ToLower(mac)
	if !strings.Contains(strings.ToLower(f.liveXMLLocked(domainName)), mac) {
		return "", fmt.Errorf("libvirtfake: interface with MAC %s not found in domain %s", mac, domainName)
	}
	return f.tapLocked(domainName, mac), nil
}

// tapLocked returns the tap of an active domain's NIC in its current run,
// handing out the next vnetN on first use. mac is lower-cased. Caller holds f.mu.
func (f *Fake) tapLocked(domainName, mac string) string {
	k := tapKey{domain: domainName, run: f.starts[domainName], mac: mac}
	if tap, ok := f.taps[k]; ok {
		return tap
	}
	// A NIC whose definition names its tap (<target dev>, as litevirt's do —
	// nictap.Name) gets that name, as libvirt gives it; any other gets the
	// next vnetN.
	tap := targetDevForMAC(f.liveXMLLocked(domainName), mac)
	if tap == "" {
		tap = fmt.Sprintf("vnet%d", f.nextTap)
		f.nextTap++
	}
	f.taps[k] = tap
	return tap
}

var (
	reFakeIface     = regexp.MustCompile(`(?s)<interface\b.*?</interface>`)
	reFakeTargetDev = regexp.MustCompile(`<target\b[^>]*\bdev=['"]([^'"]+)['"]`)
)

// targetDevForMAC is the <target dev> of the interface with mac in domainXML,
// or "" when it names none.
func targetDevForMAC(domainXML, mac string) string {
	for _, el := range reFakeIface.FindAllString(domainXML, -1) {
		if !nicMacInDomainXML(el, mac) {
			continue
		}
		if m := reFakeTargetDev.FindStringSubmatch(el); m != nil {
			return m[1]
		}
		return ""
	}
	return ""
}

// Lifecycle hooks — daemon-only paths. Connection management is a no-op (there
// is no connection to lose); domain events are recorded so a scenario can drive
// them via FireEvent.

func (f *Fake) StartReconnectLoop(ctx context.Context) { defer f.daemon()() }

// RegisterDomainEventCallback stores the callback the daemon would install on a
// real libvirt client. Storing it has no effect on its own — the fake dispatches
// nothing until a scenario calls FireEvent — so this stays inert for harnesses
// that never drive events. A second registration replaces the first, matching
// libvirt.Client.
func (f *Fake) RegisterDomainEventCallback(cb libvirt.DomainEventCallback) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.eventCB = cb
}

// FireEvent delivers a libvirt domain lifecycle event to the registered
// callback, so a scenario can drive the crash/stop path without a real
// libvirtd. A no-op when nothing is registered.
//
// The callback is copied out and f.mu is RELEASED before it runs: it is
// arbitrary daemon code that may call back into the fake (DomainExists,
// SetState, DomainState, …), and f.mu is not reentrant. Do NOT "simplify" this
// to `defer f.mu.Unlock()` — that is a self-deadlock.
//
// FireEvent deliberately does not touch f.domains; a scenario that wants the
// fake's domain state to agree with the event calls SetState itself, keeping
// event injection and state orthogonal (same split as SetStateReason).
func (f *Fake) FireEvent(domainName string, event libvirt.DomainEventType, detail int) {
	defer f.daemon()()
	f.mu.Lock()
	f.record("fire-event", domainName, fmt.Sprintf("event=%d detail=%d", int(event), detail))
	cb := f.eventCB
	f.mu.Unlock()
	if cb == nil {
		return
	}
	cb(domainName, event, detail)
}

// Close marks the Fake closed (Closing); its calls go on answering.
func (f *Fake) Close() error {
	defer f.daemon()()
	f.conns.mu.Lock()
	f.conns.closing = true
	f.conns.mu.Unlock()
	return nil
}

// Closing mirrors libvirt.Client.Closing: whether Close has been called.
func (f *Fake) Closing() bool {
	defer f.daemon()()
	f.conns.mu.Lock()
	defer f.conns.mu.Unlock()
	return f.conns.closing
}

// SetDomainOwnerEpoch / GetDomainOwnerEpoch mirror the Phase 4 runtime marker
// stored in domain metadata. The fake records them per domain so fleet and
// unit tests can assert write-through and convergence without libvirt.
func (f *Fake) SetDomainOwnerEpoch(name string, epoch int64, running bool) error {
	defer f.daemon()()
	// The real client refuses a pre-epoch value (a generation starts at 1); the
	// fake must too, or a test could pass against a marker state production
	// cannot produce.
	if epoch < 1 {
		return fmt.Errorf("refusing to set owner-epoch metadata %d on %q: a generation starts at 1", epoch, name)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("domain %q not found", name)
	}
	if f.ownerEpochs == nil {
		f.ownerEpochs = make(map[string]int64)
	}
	f.ownerEpochs[name] = epoch
	return nil
}

func (f *Fake) GetDomainOwnerEpoch(name string) (int64, bool, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return 0, false, fmt.Errorf("domain %q not found", name)
	}
	e, ok := f.ownerEpochs[name]
	return e, ok, nil
}

// SetDomainManaged / GetDomainManaged mirror the managed-stamp metadata
// element (internal/libvirt/managed_stamp.go). It dies with the domain on
// undefine, as the real metadata does.
func (f *Fake) SetDomainManaged(name string, running bool) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("domain %q not found", name)
	}
	if f.managed == nil {
		f.managed = make(map[string]bool)
	}
	f.managed[name] = true
	return nil
}

// SetDomainManagedIncarnation writes the managed stamp with its incarnation
// attribute; GetDomainManagedIncarnation reads it back.
func (f *Fake) SetDomainManagedIncarnation(name, incarnation string, running bool) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("domain %q not found", name)
	}
	if f.managed == nil {
		f.managed = make(map[string]bool)
	}
	if f.managedInc == nil {
		f.managedInc = make(map[string]string)
	}
	f.managed[name] = true
	f.managedInc[name] = incarnation
	return nil
}

func (f *Fake) GetDomainManagedIncarnation(name string) (string, bool, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return "", false, fmt.Errorf("domain %q not found", name)
	}
	inc := f.managedInc[name]
	return inc, inc != "", nil
}

func (f *Fake) GetDomainManaged(name string) (bool, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return false, fmt.Errorf("domain %q not found", name)
	}
	return f.managed[name], nil
}

// AbortMigration records an abort of name's migration job and runs
// OnAbortMigration, which a scenario uses to make its blocked MigrateToTarget
// return the way a real abort makes it return.
func (f *Fake) AbortMigration(name string) error {
	defer f.daemon()()
	f.mu.Lock()
	if f.abortedMigrations == nil {
		f.abortedMigrations = map[string]int{}
	}
	f.abortedMigrations[name]++
	hook, fail := f.OnAbortMigration, f.FailAbortMigration
	f.mu.Unlock()
	if fail != nil {
		if err := fail(name); err != nil {
			return err
		}
	}
	if hook != nil {
		hook(name)
	}
	return nil
}

// AbortedMigrations is how many times AbortMigration was called for name.
func (f *Fake) AbortedMigrations(name string) int {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.abortedMigrations[name]
}

// fakeSecret is one ceph secret in the fake's store.
type fakeSecret struct {
	clientID string
	value    []byte
}

// DefineCephSecret defines or redefines a ceph secret and sets its value. The
// event recorded carries the client, never the value.
func (f *Fake) DefineCephSecret(secretUUID, clientID string, value []byte) error {
	defer f.daemon()()
	if f.FailDefineSecret != nil {
		if err := f.FailDefineSecret(secretUUID); err != nil {
			return err
		}
	}
	if len(value) == 0 {
		return fmt.Errorf("ceph secret %s: empty value", secretUUID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.secrets == nil {
		f.secrets = map[string]fakeSecret{}
	}
	f.secrets[secretUUID] = fakeSecret{clientID: clientID, value: append([]byte(nil), value...)}
	f.record("secret-define", secretUUID, "client="+clientID)
	return nil
}

// HasSecret reports whether the secret is defined.
func (f *Fake) HasSecret(secretUUID string) (bool, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.secrets[secretUUID]
	return ok, nil
}

// ListCephSecrets returns every defined secret's UUID (the fake holds only
// litevirt's).
func (f *Fake) ListCephSecrets() ([]string, error) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.secrets))
	for u := range f.secrets {
		out = append(out, u)
	}
	sort.Strings(out)
	return out, nil
}

// UndefineSecret removes a secret; one not defined is not an error.
func (f *Fake) UndefineSecret(secretUUID string) error {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.secrets[secretUUID]; ok {
		delete(f.secrets, secretUUID)
		f.record("secret-undefine", secretUUID, "")
	}
	return nil
}

// CephSecret returns a defined secret's client and value (test accessor).
func (f *Fake) CephSecret(secretUUID string) (clientID string, value []byte, ok bool) {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[secretUUID]
	return s.clientID, append([]byte(nil), s.value...), ok
}

// DropSecrets forgets every secret, as a libvirtd restart does to ephemeral
// ones.
func (f *Fake) DropSecrets() {
	defer f.daemon()()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets = nil
}

// randomUUID is a version-4 uuid, as libvirt generates for a domain whose XML
// names none.
func randomUUID() string {
	var b [16]byte
	_, _ = cryptorand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// insertUUID puts <uuid>u</uuid> right after the domain's <name>, or, where
// that is not spelled so, right after the <domain> element's opening tag.
func insertUUID(xmlConfig, name, u string) string {
	tag := "<name>" + name + "</name>"
	if i := strings.Index(xmlConfig, tag); i >= 0 {
		j := i + len(tag)
		return xmlConfig[:j] + "<uuid>" + u + "</uuid>" + xmlConfig[j:]
	}
	if i := strings.Index(xmlConfig, "<domain"); i >= 0 {
		if j := strings.Index(xmlConfig[i:], ">"); j >= 0 {
			k := i + j + 1
			return xmlConfig[:k] + "<uuid>" + u + "</uuid>" + xmlConfig[k:]
		}
	}
	return xmlConfig
}
