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
	agent          bool              // a guest agent answers quiesce
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
	}
}

func pitDomXML(disks map[string]string) string {
	var b strings.Builder
	b.WriteString("<domain><name>web</name><devices>")
	for _, dev := range sortedDevs(disks) {
		b.WriteString("<disk type='file' device='disk'><source file='" + disks[dev] + "'/><target dev='" + dev + "'/></disk>")
	}
	b.WriteString("</devices></domain>")
	return b.String()
}

func (m *pitModel) DomainLookupByName(name string) (golibvirt.Domain, error) {
	return golibvirt.Domain{Name: name}, nil
}
func (m *pitModel) DomainGetXMLDesc(_ golibvirt.Domain, f golibvirt.DomainXMLFlags) (string, error) {
	if f&golibvirt.DomainXMLInactive != 0 {
		return pitDomXML(m.inactive), nil
	}
	return pitDomXML(m.live), nil
}
func (m *pitModel) DomainDefineXML(x string) (golibvirt.Domain, error) {
	m.defined = x
	m.inactive = parseDomainDiskSources(x)
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
	return 1, 0, 0, 10, 10, nil
}
func (m *pitModel) DomainBlockJobAbort(_ golibvirt.Domain, dev string, flags golibvirt.DomainBlockJobAbortFlags) error {
	if flags&golibvirt.DomainBlockJobAbortPivot != 0 {
		m.pivots++
		base := m.commits[len(m.commits)-1]
		base = base[strings.Index(base, "→")+len("→"):]
		m.live[dev] = base
		if !m.pivotKeepsPersistent {
			m.inactive[dev] = base
		}
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
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
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
	if used, _ := domainUsesFile(m, "web", "/pool/ov"); used {
		t.Error("the domain still names the overlay")
	}
}

// A domain not on the overlay is left alone: no commit is started.
func TestPITCommit_NotOnTheOverlayIsANoOp(t *testing.T) {
	m := newPITModel()
	if err := commitDiskOverlay(m, "web", "/pool/web-root.qcow2", "/pool/ov"); err != nil {
		t.Fatal(err)
	}
	if len(m.commits) != 0 || m.defined != "" {
		t.Errorf("commits %v, defined %q on a domain that never used the overlay", m.commits, m.defined)
	}
}
