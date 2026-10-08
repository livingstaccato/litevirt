package libvirt

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// libvirt10 models what libvirt 10.0.0 (src/qemu/qemu_snapshot.c) does with
// one domain's external disk-only snapshots, over real qcow2 files, as the
// lab reproduction observed it (snapshot-repro.md, 2026-10-08):
//
//   - creating a snapshot cuts each disk over to a new overlay <stem>.<name>
//     backed by the disk, and makes the snapshot current;
//   - a METADATA_ONLY delete moves "current" to the parent and hands the
//     snapshot's children to its parent; a REDEFINE sets "current" only
//     with VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT;
//   - a plain delete (flags 0) of a snapshot that is not current and has no
//     children takes merge=false and UNLINKS the disk recorded in the
//     snapshot's own <domain> (parentDomDisk), with no chain check;
//   - otherwise it merges: the snapshot's overlay must be in the live chain
//     with parentDomDisk as its backing, is committed into it, and is
//     removed; a current snapshot with children is refused;
//   - an inactive domain with snapshots cannot be undefined; a start opens
//     every layer of every disk's chain.
type libvirt10 struct {
	t   *testing.T
	dir string

	mu      sync.Mutex
	dom     *modelDomain
	snaps   map[string]*modelSnap
	current string
	saved   map[string]string // vmstate path → domain XML it restores
	unlinks []string          // files the model's libvirt unlinked
}

type modelDomain struct {
	name       string
	disks      map[string]string // dev → active layer
	state      golibvirt.DomainState
	persistent bool
}

type modelSnap struct {
	name, parent string
	overlays     map[string]string // dev → the overlay the snapshot created (<disks>)
	bases        map[string]string // dev → the disk it was taken of (<domain>)
}

var _ snapshotAPI = (*libvirt10)(nil)

// newLibvirt10 is a model with one running domain "vm" on a fresh 4 MiB
// qcow2 root disk.
func newLibvirt10(t *testing.T) *libvirt10 {
	t.Helper()
	for _, bin := range []string{"qemu-img", "qemu-io"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	oldPoll, oldSettle := revertUndefinePoll, revertUndefineSettle
	revertUndefinePoll, revertUndefineSettle = 0, 0
	t.Cleanup(func() { revertUndefinePoll, revertUndefineSettle = oldPoll, oldSettle })
	dir := t.TempDir()
	root := filepath.Join(dir, "vm-root.qcow2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", root, "4M")
	return &libvirt10{
		t: t, dir: dir,
		dom:   &modelDomain{name: "vm", disks: map[string]string{"vda": root}, state: golibvirt.DomainRunning, persistent: true},
		snaps: map[string]*modelSnap{},
		saved: map[string]string{},
	}
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func noDomain() error {
	return golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "Domain not found"}
}

func noSnapshot(name string) error {
	return golibvirt.Error{Code: uint32(golibvirt.ErrNoDomainSnapshot), Message: "Domain snapshot not found: no domain snapshot with matching name '" + name + "'"}
}

func (m *libvirt10) lookup(name string) (*modelDomain, error) {
	if m.dom == nil || m.dom.name != name {
		return nil, noDomain()
	}
	return m.dom, nil
}

func (m *libvirt10) DomainLookupByName(name string) (golibvirt.Domain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.lookup(name); err != nil {
		return golibvirt.Domain{}, err
	}
	return golibvirt.Domain{Name: name}, nil
}

func (m *libvirt10) DomainGetState(dom golibvirt.Domain, _ uint32) (int32, int32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.lookup(dom.Name)
	if err != nil {
		return 0, 0, err
	}
	return int32(d.state), 0, nil
}

func domainXMLOf(name string, disks map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<domain type='kvm'><name>%s</name><devices>", name)
	for _, dev := range sortedKeys(disks) {
		fmt.Fprintf(&b, "<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='%s'/><target dev='%s' bus='virtio'/></disk>", disks[dev], dev)
	}
	b.WriteString("</devices></domain>")
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m *libvirt10) DomainGetXMLDesc(dom golibvirt.Domain, _ golibvirt.DomainXMLFlags) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.lookup(dom.Name)
	if err != nil {
		return "", err
	}
	return domainXMLOf(d.name, d.disks), nil
}

func (m *libvirt10) DomainDestroy(dom golibvirt.Domain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.lookup(dom.Name)
	if err != nil {
		return err
	}
	if d.state == golibvirt.DomainShutoff {
		return fmt.Errorf("Requested operation is not valid: domain is not running")
	}
	d.state = golibvirt.DomainShutoff
	if !d.persistent {
		m.dom = nil
	}
	return nil
}

func (m *libvirt10) DomainUndefineFlags(dom golibvirt.Domain, _ golibvirt.DomainUndefineFlagsValues) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.lookup(dom.Name)
	if err != nil {
		return err
	}
	if d.state != golibvirt.DomainShutoff {
		d.persistent = false
		return nil
	}
	if n := len(m.snaps); n > 0 {
		return fmt.Errorf("Requested operation is not valid: cannot delete inactive domain with %d snapshots", n)
	}
	m.dom = nil
	return nil
}

func (m *libvirt10) DomainDefineXML(x string) (golibvirt.Domain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := xmlName(x)
	disks := parseDomainDiskSources(x)
	if m.dom != nil && m.dom.name == name {
		m.dom.disks, m.dom.persistent = disks, true
	} else {
		m.dom = &modelDomain{name: name, disks: disks, state: golibvirt.DomainShutoff, persistent: true}
	}
	return golibvirt.Domain{Name: name}, nil
}

func xmlName(x string) string {
	var v struct {
		Name string `xml:"name"`
	}
	_ = xml.Unmarshal([]byte(x), &v)
	return v.Name
}

// chain is file and every layer under it, read from the qcow2 headers. A
// layer that cannot be opened is an error, as qemu's open of it is.
func chain(file string) ([]string, error) {
	var out []string
	for p := file; p != ""; {
		info, err := qcow2.Info(p)
		if err != nil {
			return out, fmt.Errorf("Could not open '%s': %w", p, err)
		}
		out = append(out, p)
		b := info.BackingFile
		if b != "" && !filepath.IsAbs(b) {
			b = filepath.Join(filepath.Dir(p), b)
		}
		p = b
	}
	return out, nil
}

func (m *libvirt10) openDisks(d *modelDomain) error {
	for _, dev := range sortedKeys(d.disks) {
		if _, err := chain(d.disks[dev]); err != nil {
			return fmt.Errorf("internal error: qemu unexpectedly closed the monitor: %s: %v", dev, err)
		}
	}
	return nil
}

func (m *libvirt10) DomainCreate(dom golibvirt.Domain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.lookup(dom.Name)
	if err != nil {
		return err
	}
	if d.state != golibvirt.DomainShutoff {
		return fmt.Errorf("Requested operation is not valid: domain is already running")
	}
	if err := m.openDisks(d); err != nil {
		return err
	}
	d.state = golibvirt.DomainRunning
	return nil
}

func (m *libvirt10) DomainResume(dom golibvirt.Domain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.lookup(dom.Name)
	if err != nil {
		return err
	}
	if d.state != golibvirt.DomainPaused {
		return fmt.Errorf("Requested operation is not valid: domain is not paused")
	}
	d.state = golibvirt.DomainRunning
	return nil
}

func (m *libvirt10) DomainRestoreFlags(from string, dxml golibvirt.OptString, _ uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.saved[from]
	if !ok {
		return fmt.Errorf("no saved image %s", from)
	}
	if len(dxml) > 0 && dxml[0] != "" {
		x = dxml[0]
	}
	name := xmlName(x)
	if m.dom != nil && m.dom.name == name && m.dom.state != golibvirt.DomainShutoff {
		return fmt.Errorf("Requested operation is not valid: domain '%s' is already active", name)
	}
	d := &modelDomain{name: name, disks: parseDomainDiskSources(x), state: golibvirt.DomainPaused}
	if m.dom != nil && m.dom.name == name {
		d.persistent = m.dom.persistent
	}
	if err := m.openDisks(d); err != nil {
		return err
	}
	m.dom = d
	return nil
}

func (m *libvirt10) DomainSaveImageGetXMLDesc(file string, _ uint32) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.saved[file]
	if !ok {
		return "", fmt.Errorf("no saved image %s", file)
	}
	return x, nil
}

func (m *libvirt10) DomainSnapshotLookupByName(dom golibvirt.Domain, name string, _ uint32) (golibvirt.DomainSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.snaps[name]; !ok {
		return golibvirt.DomainSnapshot{}, noSnapshot(name)
	}
	return golibvirt.DomainSnapshot{Name: name, Dom: dom}, nil
}

func snapXMLOf(s *modelSnap, domName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<domainsnapshot><name>%s</name>", s.name)
	if s.parent != "" {
		fmt.Fprintf(&b, "<parent><name>%s</name></parent>", s.parent)
	}
	b.WriteString("<state>disk-snapshot</state><memory snapshot='no'/><disks>")
	for _, dev := range sortedKeys(s.overlays) {
		fmt.Fprintf(&b, "<disk name='%s' snapshot='external' type='file'><driver type='qcow2'/><source file='%s'/></disk>", dev, s.overlays[dev])
	}
	b.WriteString("<disk name='sdb' snapshot='no'/></disks>")
	b.WriteString(domainXMLOf(domName, s.bases))
	b.WriteString("</domainsnapshot>")
	return b.String()
}

func parseModelSnap(x string) *modelSnap {
	var v struct {
		Name   string `xml:"name"`
		Parent struct {
			Name string `xml:"name"`
		} `xml:"parent"`
		Disks struct {
			Disk []struct {
				Name     string `xml:"name,attr"`
				Snapshot string `xml:"snapshot,attr"`
				Source   struct {
					File string `xml:"file,attr"`
				} `xml:"source"`
			} `xml:"disk"`
		} `xml:"disks"`
	}
	if err := xml.Unmarshal([]byte(x), &v); err != nil {
		return nil
	}
	s := &modelSnap{name: v.Name, parent: v.Parent.Name, overlays: map[string]string{}, bases: parseSnapshotDomainDisks(x)}
	for _, d := range v.Disks.Disk {
		if d.Snapshot == "external" && d.Source.File != "" {
			s.overlays[d.Name] = d.Source.File
		}
	}
	return s
}

func (m *libvirt10) DomainSnapshotGetXMLDesc(snap golibvirt.DomainSnapshot, _ uint32) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.snaps[snap.Name]
	if !ok {
		return "", noSnapshot(snap.Name)
	}
	return snapXMLOf(s, snap.Dom.Name), nil
}

func (m *libvirt10) DomainSnapshotCreateXML(dom golibvirt.Domain, x string, flags uint32) (golibvirt.DomainSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.lookup(dom.Name)
	if err != nil {
		return golibvirt.DomainSnapshot{}, err
	}
	if flags&uint32(golibvirt.DomainSnapshotCreateRedefine) != 0 {
		s := parseModelSnap(x)
		if s == nil || s.name == "" {
			return golibvirt.DomainSnapshot{}, fmt.Errorf("XML error: bad snapshot")
		}
		m.snaps[s.name] = s
		if flags&uint32(golibvirt.DomainSnapshotCreateCurrent) != 0 {
			m.current = s.name
		}
		return golibvirt.DomainSnapshot{Name: s.name, Dom: dom}, nil
	}
	if flags&uint32(golibvirt.DomainSnapshotCreateDiskOnly) == 0 {
		return golibvirt.DomainSnapshot{}, fmt.Errorf("the model takes disk-only snapshots only")
	}
	name := xmlName(x)
	if _, ok := m.snaps[name]; ok {
		return golibvirt.DomainSnapshot{}, fmt.Errorf("snapshot %s exists", name)
	}
	s := &modelSnap{name: name, parent: m.current, overlays: map[string]string{}, bases: map[string]string{}}
	for dev, src := range d.disks {
		ov := strings.TrimSuffix(src, filepath.Ext(src)) + "." + name
		if _, err := os.Stat(ov); err == nil {
			return golibvirt.DomainSnapshot{}, fmt.Errorf("external snapshot file for disk %s already exists and is not a block device: %s", dev, ov)
		}
		run(m.t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", src, ov)
		s.overlays[dev], s.bases[dev] = ov, src
	}
	for dev, ov := range s.overlays {
		d.disks[dev] = ov
	}
	m.snaps[name] = s
	m.current = name
	return golibvirt.DomainSnapshot{Name: name, Dom: dom}, nil
}

func (m *libvirt10) children(name string) []*modelSnap {
	var out []*modelSnap
	for _, s := range m.snaps {
		if s.parent == name {
			out = append(out, s)
		}
	}
	return out
}

func (m *libvirt10) drop(s *modelSnap) {
	for _, c := range m.children(s.name) {
		c.parent = s.parent
	}
	if m.current == s.name {
		m.current = s.parent
	}
	delete(m.snaps, s.name)
}

func (m *libvirt10) DomainSnapshotDelete(snap golibvirt.DomainSnapshot, flags golibvirt.DomainSnapshotDeleteFlags) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.snaps[snap.Name]
	if !ok {
		return noSnapshot(snap.Name)
	}
	if flags&golibvirt.DomainSnapshotDeleteMetadataOnly != 0 {
		m.drop(s)
		return nil
	}
	kids := m.children(s.name)
	if m.current == s.name && len(kids) > 0 {
		return fmt.Errorf("unsupported configuration: deletion of active external snapshot that is not a leaf snapshot is not supported")
	}
	if len(kids) > 1 {
		return fmt.Errorf("unsupported configuration: deletion of external disk snapshot with multiple children snapshots not supported")
	}
	if m.current != s.name && len(kids) == 0 {
		// "leaf non-active snapshot": no merge, parentDomDisk is unlinked.
		for _, dev := range sortedKeys(s.bases) {
			if s.overlays[dev] == "" {
				continue
			}
			_ = os.Remove(s.bases[dev])
			m.unlinks = append(m.unlinks, s.bases[dev])
		}
		delete(m.snaps, s.name)
		return nil
	}
	// Merge: validated for every disk before anything is written.
	type merge struct{ dev, ov, base, above string }
	var merges []merge
	for _, dev := range sortedKeys(s.overlays) {
		ov, base := s.overlays[dev], s.bases[dev]
		live, err := chain(m.dom.disks[dev])
		if err != nil {
			return fmt.Errorf("operation failed: %v", err)
		}
		idx := -1
		for i, f := range live {
			if f == ov {
				idx = i
			}
		}
		if idx < 0 {
			return fmt.Errorf("operation failed: snapshot VM disk source and snapshot disk source are not the same")
		}
		if idx+1 >= len(live) || live[idx+1] != base {
			return fmt.Errorf("operation failed: snapshot VM disk source and parent disk source are not the same")
		}
		above := ""
		if idx > 0 {
			above = live[idx-1]
		}
		merges = append(merges, merge{dev, ov, base, above})
	}
	for _, mg := range merges {
		run(m.t, "qemu-img", "commit", "-q", "-f", "qcow2", mg.ov)
		if mg.above == "" {
			m.dom.disks[mg.dev] = mg.base
		} else {
			run(m.t, "qemu-img", "rebase", "-q", "-u", "-f", "qcow2", "-F", "qcow2", "-b", mg.base, mg.above)
		}
		if err := os.Remove(mg.ov); err != nil {
			return err
		}
		for _, c := range kids {
			c.bases[mg.dev] = mg.base
		}
	}
	m.drop(s)
	return nil
}

func (m *libvirt10) DomainSnapshotCurrent(dom golibvirt.Domain, _ uint32) (golibvirt.DomainSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == "" {
		return golibvirt.DomainSnapshot{}, golibvirt.Error{Code: uint32(golibvirt.ErrNoDomainSnapshot), Message: "the domain does not have a current snapshot"}
	}
	return golibvirt.DomainSnapshot{Name: m.current, Dom: dom}, nil
}

func (m *libvirt10) DomainSnapshotNumChildren(snap golibvirt.DomainSnapshot, _ uint32) (int32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.snaps[snap.Name]; !ok {
		return 0, noSnapshot(snap.Name)
	}
	return int32(len(m.children(snap.Name))), nil
}

// ── Test helpers ─────────────────────────────────────────────────────────

// snapshot takes a disk-only snapshot as CreateSnapshot does.
func (m *libvirt10) snapshot(name string) {
	m.t.Helper()
	if _, err := m.DomainSnapshotCreateXML(golibvirt.Domain{Name: "vm"},
		fmt.Sprintf(`<domainsnapshot><name>%s</name></domainsnapshot>`, name),
		uint32(golibvirt.DomainSnapshotCreateDiskOnly|golibvirt.DomainSnapshotCreateAtomic)); err != nil {
		m.t.Fatalf("snapshot %s: %v", name, err)
	}
}

// memorySnapshot is snapshot plus the RAM image CreateLiveSnapshot saves,
// which restores the domain onto its new overlays.
func (m *libvirt10) memorySnapshot(name string) string {
	m.t.Helper()
	m.snapshot(name)
	path := filepath.Join(m.dir, "vm-"+name+".save")
	if err := os.WriteFile(path, []byte("ram"), 0o600); err != nil {
		m.t.Fatal(err)
	}
	m.mu.Lock()
	m.saved[path] = domainXMLOf("vm", m.dom.disks)
	m.mu.Unlock()
	return path
}

func (m *libvirt10) active() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dom == nil {
		m.t.Fatal("the domain is gone")
	}
	return m.dom.disks["vda"]
}

func (m *libvirt10) state() golibvirt.DomainState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dom == nil {
		return -1
	}
	return m.dom.state
}

func (m *libvirt10) setState(st golibvirt.DomainState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dom.state = st
}

// write puts a 64 KiB pattern at off MiB through the domain's active layer.
func (m *libvirt10) write(pattern byte, off int) {
	m.t.Helper()
	run(m.t, "qemu-io", "-f", "qcow2", "-c", fmt.Sprintf("write -P 0x%02x %dM 64k", pattern, off), m.active())
}

// has reports whether the domain's disk reads pattern at off MiB.
func (m *libvirt10) has(pattern byte, off int) bool {
	m.t.Helper()
	out, err := exec.Command("qemu-io", "-r", "-f", "qcow2", "-c",
		fmt.Sprintf("read -P 0x%02x %dM 64k", pattern, off), m.active()).CombinedOutput()
	return err == nil && !strings.Contains(string(out), "Pattern verification failed") &&
		!strings.Contains(string(out), "Could not open")
}

// stopAndStart shuts the domain off and starts it: the start opens every
// layer of the disk's chain, as the lab's did.
func (m *libvirt10) stopAndStart() error {
	if m.state() != golibvirt.DomainShutoff {
		if err := m.DomainDestroy(golibvirt.Domain{Name: "vm"}); err != nil {
			return err
		}
	}
	return startDomain(m, "vm")
}
