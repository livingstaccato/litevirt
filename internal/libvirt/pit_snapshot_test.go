package libvirt

import (
	"errors"
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// pitModel is libvirt as the point-in-time snapshot sees it: one domain whose
// live and persistent definitions name each disk's top file.
type pitModel struct {
	live, inactive map[string]string // dev → source file
	backing        map[string]string // dev → backing file of the inactive entry (libvirt's post-snapshot form)
	state          golibvirt.DomainState
	agent          bool // a guest agent answers quiesce
	jobRunning     bool // a job is already on vda (a dead daemon started it)
	jobType        golibvirt.DomainBlockJobType
	pivotFails     int // the next pivots that fail
	aborts         int // job aborts without pivot
	snapFlags      []uint32
	snapXML        string
	commits        []string
	pivots         int
	defined        string
	// pivotKeepsPersistent models a libvirt that pivots the live disk but
	// leaves the persistent definition on the overlay.
	pivotKeepsPersistent bool
}

func newPITModel() *pitModel {
	return &pitModel{
		live:     map[string]string{"vda": "/pool/web-root.qcow2", "vdb": "/pool/web-data.qcow2"},
		inactive: map[string]string{"vda": "/pool/web-root.qcow2", "vdb": "/pool/web-data.qcow2"},
		backing:  map[string]string{},
		state:    golibvirt.DomainRunning,
		jobType:  golibvirt.DomainBlockJobTypeActiveCommit,
	}
}

func pitDomXML(disks, backing map[string]string) string {
	var b strings.Builder
	b.WriteString("<domain><name>web</name><devices>")
	for _, dev := range sortedDevs(disks) {
		b.WriteString("<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='" + disks[dev] + "'/>")
		if bf := backing[dev]; bf != "" {
			// libvirt's post-snapshot entry: the overlay, its base as a
			// nested backing chain.
			b.WriteString("<backingStore type='file'><format type='qcow2'/><source file='" + bf + "'/><backingStore/></backingStore>")
		}
		b.WriteString("<target dev='" + dev + "'/></disk>")
	}
	b.WriteString("</devices></domain>")
	return b.String()
}

func (m *pitModel) DomainLookupByName(name string) (golibvirt.Domain, error) {
	return golibvirt.Domain{Name: name}, nil
}
func (m *pitModel) DomainGetState(golibvirt.Domain, uint32) (int32, int32, error) {
	return int32(m.state), 0, nil
}
func (m *pitModel) DomainGetXMLDesc(_ golibvirt.Domain, f golibvirt.DomainXMLFlags) (string, error) {
	if f&golibvirt.DomainXMLInactive != 0 {
		return pitDomXML(m.inactive, m.backing), nil
	}
	return pitDomXML(m.live, nil), nil
}
func (m *pitModel) DomainDefineXML(x string) (golibvirt.Domain, error) {
	m.defined = x
	m.inactive = parseDomainDiskSources(x)
	m.backing = map[string]string{}
	if strings.Contains(x, "<backingStore type=") {
		m.backing["vda"] = "kept"
	}
	return golibvirt.Domain{}, nil
}
func (m *pitModel) DomainSnapshotCreateXML(_ golibvirt.Domain, x string, flags uint32) (golibvirt.DomainSnapshot, error) {
	m.snapFlags = append(m.snapFlags, flags)
	if flags&uint32(golibvirt.DomainSnapshotCreateQuiesce) != 0 && !m.agent {
		return golibvirt.DomainSnapshot{}, errors.New("guest agent is not responding")
	}
	m.snapXML = x
	overlay := x[strings.Index(x, "<source file='")+len("<source file='"):]
	overlay = overlay[:strings.Index(overlay, "'")]
	m.backing["vda"] = m.inactive["vda"]
	m.live["vda"], m.inactive["vda"] = overlay, overlay
	return golibvirt.DomainSnapshot{}, nil
}
func (m *pitModel) DomainBlockCommit(_ golibvirt.Domain, disk string, base, _ golibvirt.OptString, _ uint64, flags golibvirt.DomainBlockCommitFlags) error {
	if flags&golibvirt.DomainBlockCommitActive == 0 {
		return errors.New("not an active commit")
	}
	m.commits = append(m.commits, disk+"→"+base[0])
	return nil
}
func (m *pitModel) DomainGetBlockJobInfo(golibvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
	if !m.jobRunning && len(m.commits) == 0 {
		return 0, 0, 0, 0, 0, nil
	}
	return 1, int32(m.jobType), 0, 10, 10, nil
}
func (m *pitModel) DomainBlockJobAbort(_ golibvirt.Domain, dev string, flags golibvirt.DomainBlockJobAbortFlags) error {
	if flags&golibvirt.DomainBlockJobAbortPivot == 0 {
		m.aborts++
		m.jobRunning, m.commits = false, nil
		return nil
	}
	if m.pivotFails > 0 {
		m.pivotFails--
		return errors.New("block job not ready for pivot")
	}
	m.pivots++
	base := "/pool/web-root.qcow2"
	if len(m.commits) > 0 {
		base = m.commits[len(m.commits)-1]
		base = base[strings.Index(base, "→")+len("→"):]
	}
	m.jobRunning = false
	m.live[dev] = base
	if !m.pivotKeepsPersistent {
		m.inactive[dev] = base
		delete(m.backing, dev)
	}
	return nil
}

var _ pitAPI = (*pitModel)(nil)

// Only the replicated disk is snapshotted; every other disk is named with
// snapshot='no', or libvirt would give each of them an overlay too.
func TestPITSnapshot_OnlyTheOneDisk(t *testing.T) {
	m := newPITModel()
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/.web-root.qcow2.lv-pit"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !strings.Contains(m.snapXML, "<disk name='vdb' snapshot='no'/>") {
		t.Errorf("the other disk is not excluded: %s", m.snapXML)
	}
	if !strings.Contains(m.snapXML, "<disk name='vda' snapshot='external' type='file'><driver type='qcow2'/><source file='/pool/.web-root.qcow2.lv-pit'/>") {
		t.Errorf("the disk is not snapshotted onto the overlay: %s", m.snapXML)
	}
	want := uint32(golibvirt.DomainSnapshotCreateDiskOnly | golibvirt.DomainSnapshotCreateAtomic | golibvirt.DomainSnapshotCreateNoMetadata)
	for _, f := range m.snapFlags {
		if f&want != want {
			t.Errorf("snapshot flags %#x lack disk-only|atomic|no-metadata", f)
		}
	}
}

// With a guest agent the snapshot is quiesced; without one it is taken
// crash-consistent rather than not at all.
func TestPITSnapshot_QuiescesWhenItCan(t *testing.T) {
	m := newPITModel()
	m.agent = true
	q, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov")
	if err != nil || !q {
		t.Fatalf("with an agent: quiesced=%v err=%v, want a quiesced snapshot", q, err)
	}
	m = newPITModel()
	q, err = snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov")
	if err != nil || q {
		t.Fatalf("without an agent: quiesced=%v err=%v, want a crash-consistent snapshot", q, err)
	}
	if len(m.snapFlags) != 2 {
		t.Errorf("snapshot attempts %d, want the quiesced try and the plain one", len(m.snapFlags))
	}
}

// The commit leaves the domain where it started, live AND persistent. A
// libvirt that pivots the live disk but leaves the persistent definition on
// the overlay would boot the next start from a stale overlay, losing every
// write made after the pivot.
func TestPITCommit_PersistentDefinitionEndsOnTheDisk(t *testing.T) {
	m := newPITModel()
	m.pivotKeepsPersistent = true
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
		t.Fatal(err)
	}
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov", "qcow2", nil); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if m.pivots != 1 || len(m.commits) != 1 || m.commits[0] != "vda→/pool/web-root.qcow2" {
		t.Errorf("commits %v pivots %d, want one active commit of vda into its own file", m.commits, m.pivots)
	}
	if m.live["vda"] != "/pool/web-root.qcow2" {
		t.Errorf("live disk on %q after the commit", m.live["vda"])
	}
	if m.inactive["vda"] != "/pool/web-root.qcow2" {
		t.Errorf("persistent disk on %q after the commit; a restart would boot the stale overlay", m.inactive["vda"])
	}
	if strings.Contains(m.defined, "<backingStore") || !strings.Contains(m.defined, "<driver name='qemu' type='qcow2'/><source file='/pool/web-root.qcow2'/>") {
		t.Errorf("the repaired persistent entry keeps the overlay's backing chain or loses its driver: %s", m.defined)
	}
	if used, _ := domainUsesFile(m, "web", "/pool/ov"); used {
		t.Error("the domain still names the overlay")
	}
}

// A domain not on the overlay is left alone: no commit is started.
func TestPITCommit_NotOnTheOverlayIsANoOp(t *testing.T) {
	m := newPITModel()
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov", "qcow2", nil); err != nil {
		t.Fatal(err)
	}
	if len(m.commits) != 0 || m.defined != "" {
		t.Errorf("commits %v, defined %q on a domain that never used the overlay", m.commits, m.defined)
	}
}

// A commit job a dead daemon left running is resumed — waited for and
// pivoted — not started again ("disk vda already in active block job").
//
// Mutation "always start a new commit": activeCommitAndPivot ignores the job
// already there — red.
func TestPITCommit_ResumesACommitJobAlreadyRunning(t *testing.T) {
	m := newPITModel()
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
		t.Fatal(err)
	}
	m.jobRunning = true
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov", "qcow2", nil); err != nil {
		t.Fatalf("commit with a job already running: %v", err)
	}
	if len(m.commits) != 0 {
		t.Errorf("a second commit was started over the running one: %v", m.commits)
	}
	if m.pivots != 1 || m.live["vda"] != "/pool/web-root.qcow2" {
		t.Errorf("pivots %d, live disk %q: the running commit was not finished", m.pivots, m.live["vda"])
	}
}

// A pivot that fails now and then is retried; one that keeps failing is
// aborted, leaving the domain on the overlay with no job, so the next commit
// can start afresh.
//
// Mutation "no abort after the last pivot": activeCommitAndPivot returns
// without aborting — red.
func TestPITCommit_AFailedPivotIsRetriedThenAborted(t *testing.T) {
	prevPoll := pitCommitPoll
	pitCommitPoll = 0
	defer func() { pitCommitPoll = prevPoll }()

	m := newPITModel()
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
		t.Fatal(err)
	}
	m.pivotFails = 2
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov", "qcow2", nil); err != nil || m.pivots != 1 {
		t.Fatalf("two transient pivot failures: err %v pivots %d, want a retry that lands", err, m.pivots)
	}

	m = newPITModel()
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
		t.Fatal(err)
	}
	m.pivotFails = 100
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov", "qcow2", nil); err == nil {
		t.Fatal("a pivot that never lands reported success")
	}
	if m.aborts != 1 {
		t.Errorf("job aborts %d, want the failed commit's job aborted", m.aborts)
	}
	if found, _, _, _, _, _ := m.DomainGetBlockJobInfo(golibvirt.Domain{}, "vda", 0); found != 0 {
		t.Error("a block job is left on the disk")
	}
	if m.live["vda"] != "/pool/ov" {
		t.Errorf("live disk on %q; it must stay on the overlay that holds the writes", m.live["vda"])
	}
}

// An inactive domain is never snapshotted: libvirt would create an offline
// overlay that no live commit can merge.
//
// Mutation "snapshot any domain": snapshotDiskExternal skips the state check —
// red.
func TestPITSnapshot_NeverAnInactiveDomain(t *testing.T) {
	m := newPITModel()
	m.state = golibvirt.DomainShutoff
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err == nil {
		t.Fatal("a shut-off domain was snapshotted")
	}
	if len(m.snapFlags) != 0 {
		t.Errorf("snapshot attempted on a shut-off domain: %v", m.snapFlags)
	}
}

// On an inactive domain the commit only repairs the persistent entry (the
// overlay itself is committed offline by the caller); no live job is tried.
func TestPITCommit_InactiveDomainOnlyRepairsTheDefinition(t *testing.T) {
	m := newPITModel()
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
		t.Fatal(err)
	}
	m.state = golibvirt.DomainShutoff
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov", "qcow2", nil); err != nil {
		t.Fatalf("commit on an inactive domain: %v", err)
	}
	if len(m.commits) != 0 {
		t.Errorf("a live commit was tried on an inactive domain: %v", m.commits)
	}
	if m.inactive["vda"] != "/pool/web-root.qcow2" || strings.Contains(m.defined, "<backingStore") {
		t.Errorf("persistent entry not repaired: %s", m.defined)
	}
}

// Another kind of job on the disk (a copy a live move left) is never resumed
// or pivoted as if it were the commit.
//
// Mutation "resume any job": activeCommitAndPivot ignores the job type — red.
func TestPITCommit_NeverTouchesAnotherKindOfJob(t *testing.T) {
	m := newPITModel()
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
		t.Fatal(err)
	}
	m.jobRunning, m.jobType = true, golibvirt.DomainBlockJobTypeCopy
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov", "qcow2", nil); err == nil {
		t.Fatal("a commit ran over another kind of block job")
	}
	if m.pivots != 0 || m.aborts != 0 || len(m.commits) != 0 {
		t.Errorf("pivots %d aborts %d commits %v: the other job was touched", m.pivots, m.aborts, m.commits)
	}
}

// N3 of the round-4 review: a ready commit records, durably, that it is about
// to pivot — before the pivot, never after — so a daemon that dies right
// after the pivot is known to have pivoted. A record that fails stops the
// pivot: the job is aborted and the domain stays on the overlay.
//
// Mutation "pivot not recorded" (beforePivot never called) — red. Mutation
// "pivot despite a failed record" — red.
func TestPITCommit_RecordsThePivotBeforeIt(t *testing.T) {
	m := newPITModel()
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
		t.Fatal(err)
	}
	pivotsAtRecord := -1
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov", "qcow2", func() error {
		pivotsAtRecord = m.pivots
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if pivotsAtRecord != 0 || m.pivots != 1 {
		t.Fatalf("recorded with %d pivots done (want 0, before it), %d pivots in all", pivotsAtRecord, m.pivots)
	}

	m = newPITModel()
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
		t.Fatal(err)
	}
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov", "qcow2", func() error {
		return errors.New("ENOSPC")
	}); err == nil {
		t.Fatal("a commit whose pivot could not be recorded reported success")
	}
	if m.pivots != 0 || m.live["vda"] != "/pool/ov" {
		t.Fatalf("pivots %d, live disk %q: it pivoted without the record", m.pivots, m.live["vda"])
	}
	if found, _, _, _, _, _ := m.DomainGetBlockJobInfo(golibvirt.Domain{}, "vda", 0); found != 0 {
		t.Error("the unpivoted commit's job was left on the disk")
	}
}
