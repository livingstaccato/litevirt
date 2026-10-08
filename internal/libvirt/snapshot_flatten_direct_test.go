package libvirt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// scriptedLibvirt plays libvirt for flattenSnapshot and snapshotBaseFiles:
// one domain whose live and persistent definitions are kept as XML, a
// snapshot list, and a log of every call in order.
type scriptedLibvirt struct {
	state      golibvirt.DomainState
	live, inac string // domain XML, live and persistent
	snaps      map[string]string
	calls      []string

	// pivotKeepsConfig: a pivot moves the live definition only, as libvirt
	// does when the persistent and live sources differ (review M-2).
	pivotKeepsConfig bool
	commitErr        map[string]error // dev → DomainBlockCommit error
	defineErr        error
	onDelete         func() // runs when the snapshot's metadata is deleted
	pendingBase      map[string]string
}

func (s *scriptedLibvirt) log(f string, a ...any) { s.calls = append(s.calls, fmt.Sprintf(f, a...)) }

func (s *scriptedLibvirt) DomainLookupByName(name string) (golibvirt.Domain, error) {
	return golibvirt.Domain{Name: name}, nil
}
func (s *scriptedLibvirt) DomainSnapshotLookupByName(dom golibvirt.Domain, name string, _ uint32) (golibvirt.DomainSnapshot, error) {
	if _, ok := s.snaps[name]; !ok {
		return golibvirt.DomainSnapshot{}, golibvirt.Error{Code: uint32(golibvirt.ErrNoDomainSnapshot), Message: "no domain snapshot with matching name"}
	}
	return golibvirt.DomainSnapshot{Name: name, Dom: dom}, nil
}
func (s *scriptedLibvirt) DomainSnapshotDelete(snap golibvirt.DomainSnapshot, flags golibvirt.DomainSnapshotDeleteFlags) error {
	s.log("snapshot-delete %s %d", snap.Name, flags)
	if s.onDelete != nil {
		s.onDelete()
	}
	delete(s.snaps, snap.Name)
	return nil
}
func (s *scriptedLibvirt) DomainGetState(golibvirt.Domain, uint32) (int32, int32, error) {
	return int32(s.state), 0, nil
}
func (s *scriptedLibvirt) DomainGetXMLDesc(_ golibvirt.Domain, flags golibvirt.DomainXMLFlags) (string, error) {
	if flags&golibvirt.DomainXMLInactive != 0 {
		return s.inac, nil
	}
	return s.live, nil
}
func (s *scriptedLibvirt) DomainBlockCommit(_ golibvirt.Domain, disk string, base, _ golibvirt.OptString, _ uint64, _ golibvirt.DomainBlockCommitFlags) error {
	s.log("block-commit %s", disk)
	if err := s.commitErr[disk]; err != nil {
		return err
	}
	if s.pendingBase == nil {
		s.pendingBase = map[string]string{}
	}
	s.pendingBase[disk] = base[0]
	return nil
}
func (s *scriptedLibvirt) DomainGetBlockJobInfo(golibvirt.Domain, string, uint32) (int32, int32, uint64, uint64, uint64, error) {
	return 1, 0, 0, 1, 1, nil // synced
}
func (s *scriptedLibvirt) DomainBlockJobAbort(_ golibvirt.Domain, disk string, _ golibvirt.DomainBlockJobAbortFlags) error {
	s.log("pivot %s", disk)
	base := s.pendingBase[disk]
	cur := parseDomainDiskSources(s.live)[disk]
	out, _, err := RewriteDiskSourceFile(s.live, disk, cur, base)
	if err != nil {
		return err
	}
	s.live = out
	if !s.pivotKeepsConfig {
		if o, _, err := RewriteDiskSourceFile(s.inac, disk, cur, base); err == nil {
			s.inac = o
		}
	}
	return nil
}
func (s *scriptedLibvirt) DomainDefineXML(x string) (golibvirt.Domain, error) {
	s.log("define")
	if s.defineErr != nil {
		return golibvirt.Domain{}, s.defineErr
	}
	s.inac = x
	return golibvirt.Domain{}, nil
}
func (s *scriptedLibvirt) DomainListAllSnapshots(dom golibvirt.Domain, _ int32, _ uint32) ([]golibvirt.DomainSnapshot, int32, error) {
	var out []golibvirt.DomainSnapshot
	for n := range s.snaps {
		out = append(out, golibvirt.DomainSnapshot{Name: n, Dom: dom})
	}
	return out, int32(len(out)), nil
}
func (s *scriptedLibvirt) DomainSnapshotGetXMLDesc(snap golibvirt.DomainSnapshot, _ uint32) (string, error) {
	return s.snaps[snap.Name], nil
}

func domainXMLWith(disks map[string]string) string {
	var b strings.Builder
	b.WriteString("<domain type='kvm'><name>vm</name><devices>")
	for dev, f := range disks {
		fmt.Fprintf(&b, "<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='%s'/><target dev='%s' bus='virtio'/></disk>", f, dev)
	}
	b.WriteString("</devices></domain>")
	return b.String()
}

// chainFixture makes base ← top for each dev in dir, with one 4k pattern
// written to each top, and returns dev → [top, base].
func chainFixture(t *testing.T, dir string, devs ...string) map[string][2]string {
	t.Helper()
	out := map[string][2]string{}
	for i, dev := range devs {
		base := filepath.Join(dir, "vm-"+dev+".qcow2")
		top := filepath.Join(dir, "vm-"+dev+".s1")
		run(t, "qemu-img", "create", "-q", "-f", "qcow2", base, "1M")
		run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, top)
		run(t, "qemu-io", "-f", "qcow2", "-c", fmt.Sprintf("write -P %d 0 4k", i+7), top)
		out[dev] = [2]string{top, base}
	}
	return out
}

func newScripted(state golibvirt.DomainState, chains map[string][2]string) *scriptedLibvirt {
	tops := map[string]string{}
	for dev, c := range chains {
		tops[dev] = c[0]
	}
	x := domainXMLWith(tops)
	return &scriptedLibvirt{state: state, live: x, inac: x, snaps: map[string]string{"s1": "<domainsnapshot><name>s1</name></domainsnapshot>"}}
}

func basesOf(chains map[string][2]string) map[string]string {
	b := map[string]string{}
	for dev, c := range chains {
		b[dev] = c[1]
	}
	return b
}

func fileSum(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func indexOfCall(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// Review M-4: a snapshot whose XML cannot be read froze layers no one can
// name. That is an error, so the caller merges nothing — never "this
// snapshot froze nothing".
func TestSnapshotBaseFiles_UnreadableSnapshotXMLFailsClosed(t *testing.T) {
	v := &scriptedLibvirt{snaps: map[string]string{
		"good": "<domainsnapshot><name>good</name><domain><devices><disk><source file='/d/vm-root.qcow2'/><target dev='vda'/></disk></devices></domain></domainsnapshot>",
		"bad":  "<domainsnapshot><name>bad</name><domain><devices><disk><source file='/d/x",
	}}
	if got, err := snapshotBaseFiles(v, "vm"); err == nil {
		t.Fatalf("an unparsable snapshot XML was read as %v, want an error", got)
	}
}

// A frozen block device (source dev=) is a frozen layer too.
func TestSnapshotBaseFiles_ABlockDeviceIsAFrozenLayer(t *testing.T) {
	v := &scriptedLibvirt{snaps: map[string]string{
		"s": "<domainsnapshot><name>s</name><domain><devices><disk type='block'><source dev='/dev/vg/vm-root'/><target dev='vda'/></disk></devices></domain></domainsnapshot>",
	}}
	got, err := snapshotBaseFiles(v, "vm")
	if err != nil {
		t.Fatal(err)
	}
	if len(got["s"]) != 1 || got["s"][0] != "/dev/vg/vm-root" {
		t.Fatalf("frozen layers = %v, want the block device", got)
	}
}

// Review M-3: the snapshot's libvirt metadata goes BEFORE any byte of its
// frozen layer changes. Deleted after, a crash between leaves a revertable
// snapshot whose frozen layer holds later data: a revert to it restores the
// wrong state, silently.
func TestFlattenSnapshot_DropsTheMetadataBeforeWritingTheBase(t *testing.T) {
	for _, st := range []golibvirt.DomainState{golibvirt.DomainRunning, golibvirt.DomainShutoff} {
		t.Run(fmt.Sprint(st), func(t *testing.T) {
			needQemuTools(t)
			chains := chainFixture(t, t.TempDir(), "vda")
			v := newScripted(st, chains)
			before := fileSum(t, chains["vda"][1])
			deletedClean := false
			v.onDelete = func() { deletedClean = fileSum(t, chains["vda"][1]) == before }
			if _, err := flattenSnapshot(v, "vm", "s1", basesOf(chains)); err != nil {
				t.Fatal(err)
			}
			d, c := indexOfCall(v.calls, "snapshot-delete"), indexOfCall(v.calls, "block-commit")
			if d < 0 || (c >= 0 && c < d) || !deletedClean {
				t.Fatalf("the metadata was deleted after the base was written (calls %v, base untouched at delete: %v)", v.calls, deletedClean)
			}
		})
	}
}

// Review M-2 / re-review 2 I-B: after a running pivot that left the
// persistent definition on the top, the merge repoints it; when it cannot
// (the define fails), every layer is kept and marked as merged into the
// base, so a start that would boot one refuses instead of running the guest
// on stale data.
func TestFlattenSnapshot_RunningKeepsAndMarksTheLayersWhenTheDefinitionCannotBeRepointed(t *testing.T) {
	needQemuTools(t)
	chains := chainFixture(t, t.TempDir(), "vda")
	v := newScripted(golibvirt.DomainRunning, chains)
	v.pivotKeepsConfig = true
	v.defineErr = errors.New("define refused")
	removable, err := flattenSnapshot(v, "vm", "s1", basesOf(chains))
	if err != nil {
		t.Fatal(err)
	}
	if l := flattenLayers(removable); len(l) != 0 {
		t.Fatalf("layers %v given up while the persistent definition still names %s", l, chains["vda"][0])
	}
	if !exists(chains["vda"][0]) {
		t.Fatal("the top the persistent definition names was removed")
	}
	if into, ok := MergedInto(chains["vda"][0]); !ok || into != chains["vda"][1] {
		t.Fatalf("the kept top is not marked as merged into %s (marker %q, %v)", chains["vda"][1], into, ok)
	}
}

// The running path: block-commit and pivot each disk, then give up the
// layers above each base once both definitions name it.
func TestFlattenSnapshot_RunningGivesUpTheLayersOnceBothDefinitionsNameTheBase(t *testing.T) {
	needQemuTools(t)
	chains := chainFixture(t, t.TempDir(), "vda")
	v := newScripted(golibvirt.DomainRunning, chains)
	removable, err := flattenSnapshot(v, "vm", "s1", basesOf(chains))
	if err != nil {
		t.Fatal(err)
	}
	if l := flattenLayers(removable); len(l) != 1 || l[0] != resolvedPath(chains["vda"][0]) {
		t.Fatalf("removable = %v, want [%s]", l, chains["vda"][0])
	}
	if got := parseDomainDiskSources(v.inac)["vda"]; got != chains["vda"][1] {
		t.Fatalf("persistent definition names %s, want the base", got)
	}
}

// The offline path: commit, repoint the persistent definition, define it —
// in that order — and only then are the layers above given up. The data is
// in the base.
func TestFlattenSnapshot_OfflineCommitsRepointsAndDefines(t *testing.T) {
	needQemuTools(t)
	chains := chainFixture(t, t.TempDir(), "vda", "vdb")
	v := newScripted(golibvirt.DomainShutoff, chains)
	removable, err := flattenSnapshot(v, "vm", "s1", basesOf(chains))
	if err != nil {
		t.Fatal(err)
	}
	if indexOfCall(v.calls, "define") < 0 {
		t.Fatalf("no define: %v", v.calls)
	}
	got := parseDomainDiskSources(v.inac)
	for i, dev := range []string{"vda", "vdb"} {
		if got[dev] != chains[dev][1] {
			t.Errorf("%s: definition names %s, want %s", dev, got[dev], chains[dev][1])
		}
		run(t, "qemu-io", "-f", "qcow2", "-c", fmt.Sprintf("read -P %d 0 4k", i+7), chains[dev][1])
	}
	if l := flattenLayers(removable); len(l) != 2 {
		t.Fatalf("removable = %v, want both tops", l)
	}
}

// A define that fails after the commits leaves every disk on its top, which
// still reads the same over its base: nothing is given up, and the error is
// returned.
func TestFlattenSnapshot_OfflineDefineFailureGivesUpNothing(t *testing.T) {
	needQemuTools(t)
	chains := chainFixture(t, t.TempDir(), "vda", "vdb")
	v := newScripted(golibvirt.DomainShutoff, chains)
	v.defineErr = errors.New("define refused")
	removable, err := flattenSnapshot(v, "vm", "s1", basesOf(chains))
	if err == nil || len(flattenLayers(removable)) != 0 {
		t.Fatalf("flatten = %v, %v; want an error and nothing given up", removable, err)
	}
	for i, dev := range []string{"vda", "vdb"} {
		if !exists(chains[dev][0]) {
			t.Fatalf("%s: top removed", dev)
		}
		run(t, "qemu-io", "-f", "qcow2", "-c", fmt.Sprintf("read -P %d 0 4k", i+7), chains[dev][0])
	}
}

// Running, two disks: the first merges and pivots, the second's commit
// fails. The error is returned and no layer of either disk is given up.
func TestFlattenSnapshot_RunningMultiDiskPartialFailureGivesUpNothing(t *testing.T) {
	needQemuTools(t)
	chains := chainFixture(t, t.TempDir(), "vda", "vdb")
	v := newScripted(golibvirt.DomainRunning, chains)
	v.commitErr = map[string]error{"vdb": errors.New("commit refused")}
	v.commitErr["vda"] = nil
	removable, err := flattenSnapshot(v, "vm", "s1", basesOf(chains))
	if err == nil || len(flattenLayers(removable)) != 0 {
		t.Fatalf("flatten = %v, %v; want an error and nothing given up", removable, err)
	}
	for _, dev := range []string{"vda", "vdb"} {
		if !exists(chains[dev][0]) || !exists(chains[dev][1]) {
			t.Fatalf("%s: a layer was removed", dev)
		}
	}
}
