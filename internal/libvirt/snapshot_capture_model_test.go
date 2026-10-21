package libvirt

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// The libvirt10 model's QEMU process and vCPUs, for memory snapshots. It
// follows libvirt v10.0.0 src/qemu/qemu_snapshot.c:
//
//   - VIR_DOMAIN_SNAPSHOT_CREATE_LIVE is refused unless the domain is active
//     and the memory location is external (qemuSnapshotPrepare, 1533-1539);
//   - qemuSnapshotCreateActiveExternal (1287-1480): a RUNNING domain is to be
//     resumed at the end (resume = true); without LIVE its vCPUs are stopped
//     up front; with LIVE QEMU runs a precopy into the file and stops the
//     vCPUs itself once the remainder fits its downtime limit. The memory is
//     written BEFORE the disks switch over, so the image's definition names
//     the disks as they were; a PAUSED domain is left paused;
//   - while the memory is written, the job mask admits SUSPEND (1389-1392),
//     and qemuDomainSuspend (qemu_driver.c:1663) stops the vCPUs with reason
//     PAUSED_SNAPSHOT; the snapshot still ends by resuming a domain that was
//     running when it began.
//
// Time is a fake clock advanced by what the model does: writing or reading
// RAM takes ramBytes/writeBps. Nothing in the model sleeps, except a LIVE
// capture that cannot converge, which waits (in real time, with m.mu
// released) for a DomainSuspend.
type qemuModel struct {
	ram      uint64  // guest RAM bytes (0 = 1 GiB)
	writeBps float64 // image write/read bandwidth, bytes/s (0 = 1 GiB/s)
	// dirtyBps is how fast the guest really dirties memory while it runs.
	dirtyBps float64
	// reportBps is what a dirty-rate calculation reports; < 0 makes the
	// stats call fail.
	reportBps float64
	// firmware adds <os><nvram> to the domain's XML (a UEFI VM).
	firmware bool

	now       time.Duration // the fake clock
	stoppedAt time.Duration // when the vCPUs stopped; < 0 while they run
	pauses    []time.Duration
	restarts  int // QEMU processes started (start, restore)
	pid       int // the QEMU process; changes on every start or restore

	creates     []createCall
	liveJob     bool          // a LIVE memory write is in progress
	jobSuspend  chan struct{} // closed by a DomainSuspend during liveJob
	suspendInJb bool          // a DomainSuspend arrived during a live job
	dirtyCalcs  int           // DomainStartDirtyRateCalc calls
	memGen      int           // bumps on every write of guest memory image
}

// createCall is one DomainSnapshotCreateXML and the vCPU state it ran in.
type createCall struct {
	flags        uint32
	memory       string
	pausedBefore bool // the vCPUs were stopped when it began
}

var errLiveNeedsMemory = errors.New("Operation not supported: live snapshot creation is supported only during full system snapshots")

// qemuDowntime is QEMU's default downtime-limit (300 ms): a precopy stops
// the vCPUs once the remainder can be written within it.
const qemuDowntime = 300 * time.Millisecond

func (m *libvirt10) ramBytes() uint64 {
	if m.qemu.ram == 0 {
		return 1 << 30
	}
	return m.qemu.ram
}

func (m *libvirt10) bps() float64 {
	if m.qemu.writeBps == 0 {
		return 1 << 30
	}
	return m.qemu.writeBps
}

func (m *libvirt10) ramTime(bytes uint64) time.Duration {
	return time.Duration(float64(bytes) / m.bps() * float64(time.Second))
}

func (m *libvirt10) qemuStarted() {
	m.qemu.restarts++
	m.qemu.pid = m.qemu.restarts
}

// stopCPUs stops a running domain's vCPUs. Caller holds m.mu.
func (m *libvirt10) stopCPUs(d *modelDomain) {
	if d.state != golibvirt.DomainRunning {
		return
	}
	d.state = golibvirt.DomainPaused
	if m.qemu.stoppedAt < 0 {
		m.qemu.stoppedAt = m.qemu.now
	}
}

// startCPUs runs the domain's vCPUs and records the pause it ends. Caller
// holds m.mu.
func (m *libvirt10) startCPUs(d *modelDomain) {
	d.state = golibvirt.DomainRunning
	if m.qemu.stoppedAt >= 0 {
		m.qemu.pauses = append(m.qemu.pauses, m.qemu.now-m.qemu.stoppedAt)
	}
	m.qemu.stoppedAt = -1
}

// totalPause is every pause the guest saw.
func (m *libvirt10) totalPause() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	var t time.Duration
	for _, p := range m.qemu.pauses {
		t += p
	}
	return t
}

// decorate adds what the model's domain XML says about its guest: RAM
// size and, for a UEFI VM, its NVRAM. Caller holds m.mu.
func (m *libvirt10) decorate(x string) string {
	extra := fmt.Sprintf("<memory unit='KiB'>%d</memory>", m.ramBytes()/1024)
	if m.qemu.firmware {
		extra += "<os><type>hvm</type><loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.fd</loader>" +
			"<nvram>/var/lib/libvirt/qemu/nvram/vm_VARS.fd</nvram></os>"
	}
	i := strings.Index(x, "</name>")
	if i < 0 {
		return x
	}
	i += len("</name>")
	return x[:i] + extra + x[i:]
}

func (m *libvirt10) DomainSuspend(dom golibvirt.Domain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.lookup(dom.Name)
	if err != nil {
		return err
	}
	if d.state == golibvirt.DomainShutoff {
		return fmt.Errorf("Requested operation is not valid: domain is not running")
	}
	m.stopCPUs(d)
	if m.qemu.liveJob && m.qemu.jobSuspend != nil {
		m.qemu.suspendInJb = true
		close(m.qemu.jobSuspend)
		m.qemu.jobSuspend = nil
	}
	return nil
}

func (m *libvirt10) DomainGetBlockInfo(golibvirt.Domain, string, uint32) (uint64, uint64, uint64, error) {
	return 4096, 4 << 20, 4096, nil
}

// DomainSaveFlags is virDomainSaveFlags: QEMU writes all RAM, then EXITS.
func (m *libvirt10) DomainSaveFlags(dom golibvirt.Domain, to string, _ golibvirt.OptString, _ uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.lookup(dom.Name)
	if err != nil {
		return err
	}
	if d.state == golibvirt.DomainShutoff {
		return fmt.Errorf("Requested operation is not valid: domain is not running")
	}
	m.stopCPUs(d)
	m.qemu.now += m.ramTime(m.ramBytes())
	if err := m.writeImage(to, d); err != nil {
		return err
	}
	d.state = golibvirt.DomainShutoff
	m.qemu.pid = 0
	if !d.persistent {
		m.dom = nil
	}
	return nil
}

// writeImage writes a save image of d's current definition to path: real
// bytes, derived from the memory generation. Caller holds m.mu.
func (m *libvirt10) writeImage(path string, d *modelDomain) error {
	m.qemu.memGen++
	if err := os.WriteFile(path, []byte(fmt.Sprintf("LibvirtQemudSave gen=%d", m.qemu.memGen)), 0o600); err != nil {
		return err
	}
	m.saved[path] = domainXMLWithChains(d.name, d.disks, nil, d.metadata)
	return nil
}

var memoryFileRe = regexp.MustCompile(`<memory\s+snapshot=['"]external['"]\s+file=['"]([^'"]+)['"]`)

// createFullSystem is DomainSnapshotCreateXML of an active domain with
// external memory (qemuSnapshotCreateActiveExternal). Caller holds m.mu;
// it is released while a non-converging LIVE capture waits for a suspend.
func (m *libvirt10) createFullSystem(d *modelDomain, dom golibvirt.Domain, x string, flags uint32) (golibvirt.DomainSnapshot, error) {
	live := flags&uint32(golibvirt.DomainSnapshotCreateLive) != 0
	mm := memoryFileRe.FindStringSubmatch(x)
	if d.state == golibvirt.DomainShutoff || len(mm) < 2 {
		if live {
			return golibvirt.DomainSnapshot{}, errLiveNeedsMemory
		}
		return golibvirt.DomainSnapshot{}, fmt.Errorf("the model takes external snapshots only")
	}
	file := mm[1]
	m.qemu.creates = append(m.qemu.creates, createCall{flags: flags, memory: file, pausedBefore: d.state != golibvirt.DomainRunning})
	name := xmlName(x)
	if _, ok := m.snaps[name]; ok {
		return golibvirt.DomainSnapshot{}, fmt.Errorf("snapshot %s exists", name)
	}
	resume := d.state == golibvirt.DomainRunning
	if resume && !live {
		m.stopCPUs(d)
	}
	remaining := m.ramBytes()
	if live && d.state == golibvirt.DomainRunning {
		// Precopy: passes over the dirtied memory while the guest runs.
		set := float64(remaining)
		converged := false
		for i := 0; i < 64; i++ {
			pass := m.ramTime(uint64(set))
			m.qemu.now += pass
			next := m.qemu.dirtyBps * pass.Seconds()
			if next > float64(m.ramBytes()) {
				next = float64(m.ramBytes())
			}
			set = next
			if m.ramTime(uint64(set)) <= qemuDowntime {
				converged = true
				break
			}
		}
		if !converged {
			// Never fits the downtime limit: QEMU keeps copying until
			// someone stops the vCPUs.
			ch := make(chan struct{})
			m.qemu.liveJob, m.qemu.jobSuspend = true, ch
			m.mu.Unlock()
			select {
			case <-ch:
			case <-time.After(10 * time.Second):
			}
			m.mu.Lock()
			m.qemu.liveJob = false
			if !m.qemu.suspendInJb {
				m.qemu.jobSuspend = nil
				return golibvirt.DomainSnapshot{}, fmt.Errorf("model: the live capture never converged and nobody suspended the guest")
			}
		}
		remaining = uint64(set)
		m.stopCPUs(d) // QEMU stops the vCPUs at switch-over
	}
	m.qemu.now += m.ramTime(remaining)
	// The image carries the definition as it is now: before the disks
	// switch over.
	if err := m.writeImage(file, d); err != nil {
		return golibvirt.DomainSnapshot{}, err
	}
	s, err := m.switchDisks(d, name, x)
	if err != nil {
		_ = os.Remove(file)
		delete(m.saved, file)
		if resume {
			m.startCPUs(d)
		}
		return golibvirt.DomainSnapshot{}, err
	}
	s.memory = file
	m.snaps[name] = s
	m.current = name
	if resume {
		m.startCPUs(d)
	}
	return golibvirt.DomainSnapshot{Name: name, Dom: dom}, nil
}

// unlinkMemory removes a deleted snapshot's memory image, as
// qemuSnapshotDiscardExternal does on a plain delete. Caller holds m.mu.
func (m *libvirt10) unlinkMemory(s *modelSnap) {
	if s.memory == "" {
		return
	}
	_ = os.Remove(s.memory)
	m.unlinks = append(m.unlinks, s.memory)
}

func (m *libvirt10) DomainStartDirtyRateCalc(golibvirt.Domain, int32, uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.qemu.dirtyCalcs++
	return nil
}

func (m *libvirt10) ConnectGetAllDomainStats(doms []golibvirt.Domain, stats uint32, _ uint32) ([]golibvirt.DomainStatsRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if stats != uint32(golibvirt.DomainStatsDirtyrate) {
		return nil, fmt.Errorf("model: stats %#x", stats)
	}
	if m.qemu.reportBps < 0 {
		return nil, fmt.Errorf("Operation not supported: dirty rate")
	}
	var out []golibvirt.DomainStatsRecord
	for _, d := range doms {
		out = append(out, golibvirt.DomainStatsRecord{Dom: d, Params: []golibvirt.TypedParam{
			{Field: golibvirt.DomainStatsDirtyrateCalcStatus, Value: golibvirt.TypedParamValue{D: 1, I: int32(2)}},
			{Field: golibvirt.DomainStatsDirtyrateMegabytesPerSecond, Value: golibvirt.TypedParamValue{D: 3, I: int64(m.qemu.reportBps / (1 << 20))}},
		}})
	}
	return out, nil
}
