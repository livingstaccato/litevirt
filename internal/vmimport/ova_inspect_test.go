package vmimport

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarMember struct {
	name string
	typ  byte
	body []byte
}

func buildTar(t *testing.T, members ...tarMember) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, m := range members {
		typ := m.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.body)), Typeflag: typ}
		if typ == tar.TypeSymlink {
			hdr.Size, hdr.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(m.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// The descriptor of an OVA laid out as the OVF specification has it (the .ovf
// first) is read without reading the disk behind it.
func TestInspectOVA_ReadsOnlyUpToTheDescriptor(t *testing.T) {
	disk := make([]byte, 4<<20)
	ova := buildTar(t,
		tarMember{name: "win2022.ovf", body: []byte(ovfWindowsSCSI)},
		tarMember{name: "disk-0.vmdk", body: disk},
	)
	cr := &countingReader{r: bytes.NewReader(ova)}
	data, err := InspectOVA(cr)
	if err != nil {
		t.Fatalf("InspectOVA: %v", err)
	}
	if string(data) != ovfWindowsSCSI {
		t.Fatalf("descriptor = %d bytes, want the .ovf member's %d", len(data), len(ovfWindowsSCSI))
	}
	if cr.n >= len(disk) {
		t.Fatalf("InspectOVA read %d bytes of a %d-byte archive: it read the disk", cr.n, len(ova))
	}
	fv, err := ParseOVFBytes(data)
	if err != nil {
		t.Fatalf("ParseOVFBytes: %v", err)
	}
	if fv.CPUs != 4 || fv.Firmware != "uefi" || len(fv.NICs) != 1 {
		t.Fatalf("parsed %+v", fv)
	}
}

// A descriptor behind the disk is still found (the disk is skipped, not kept).
func TestInspectOVA_DescriptorAfterTheDisk(t *testing.T) {
	ova := buildTar(t,
		tarMember{name: "disk-0.vmdk", body: make([]byte, 1<<20)},
		tarMember{name: "sub/win2022.OVF", body: []byte(ovfWindowsSCSI)},
	)
	data, err := InspectOVA(bytes.NewReader(ova))
	if err != nil || string(data) != ovfWindowsSCSI {
		t.Fatalf("InspectOVA = %d bytes, %v; want the descriptor", len(data), err)
	}
}

// What UnpackOVA refuses at the head of an archive the preview refuses too.
func TestInspectOVA_RefusesWhatTheImportRefuses(t *testing.T) {
	many := make([]tarMember, 0, maxArchiveMembers+2)
	for i := 0; i <= maxArchiveMembers; i++ {
		many = append(many, tarMember{name: fmt.Sprintf("pad-%d", i)})
	}
	many = append(many, tarMember{name: "a.ovf", body: []byte(ovfWindowsSCSI)})
	for _, tc := range []struct {
		name string
		ova  []tarMember
		want string
	}{
		{"symlink", []tarMember{{name: "evil.vmdk", typ: tar.TypeSymlink}, {name: "a.ovf", body: []byte(ovfWindowsSCSI)}}, "disallowed type"},
		{"member cap", many, "member cap"},
		{"no descriptor", []tarMember{{name: "disk.vmdk", body: []byte("x")}}, "no .ovf descriptor"},
		{"empty name", []tarMember{{name: "", body: []byte("x")}, {name: "a.ovf", body: []byte(ovfWindowsSCSI)}}, "empty archive member name"},
		{"root name", []tarMember{{name: "/.", body: []byte("x")}, {name: "a.ovf", body: []byte(ovfWindowsSCSI)}}, "empty archive member name"},
		{"dot name", []tarMember{{name: ".", body: []byte("x")}, {name: "a.ovf", body: []byte(ovfWindowsSCSI)}}, "empty archive member name"},
		{"empty name after the descriptor", []tarMember{{name: "a.ovf", body: []byte(ovfWindowsSCSI)}, {name: "x/..", body: []byte("x")}}, "empty archive member name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ova := buildTar(t, tc.ova...)
			if _, err := InspectOVA(bytes.NewReader(ova)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("InspectOVA err = %v, want %q", err, tc.want)
			}
			if _, err := UnpackOVA(bytes.NewReader(ova), t.TempDir(), Budget(1<<30)); err == nil {
				t.Fatalf("UnpackOVA accepted what the preview refuses")
			}
		})
	}
}

const ovfOther = `<?xml version="1.0"?><Envelope/>`

// The import refuses an archive with two descriptors, naming both, before it
// writes the second: the preview describes the first, so importing either
// could import a VM nobody previewed.
func TestUnpackOVA_RefusesASecondDescriptor(t *testing.T) {
	for _, tc := range []struct {
		name string
		ova  []tarMember
	}{
		{"behind the disk", []tarMember{
			{name: "a.ovf", body: []byte(ovfWindowsSCSI)},
			{name: "disk-0.vmdk", body: make([]byte, 4096)},
			{name: "b.OVF", body: []byte(ovfOther)},
		}},
		{"adjacent", []tarMember{
			{name: "a.ovf", body: []byte(ovfWindowsSCSI)},
			{name: "b.OVF", body: []byte(ovfOther)},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			_, err := UnpackOVA(bytes.NewReader(buildTar(t, tc.ova...)), dest, Budget(1<<30))
			if err == nil || !strings.Contains(err.Error(), `"a.ovf"`) || !strings.Contains(err.Error(), `"b.OVF"`) {
				t.Fatalf("UnpackOVA err = %v, want a refusal naming a.ovf and b.OVF", err)
			}
			if _, err := os.Stat(filepath.Join(dest, "b.OVF")); !os.IsNotExist(err) {
				t.Fatalf("second descriptor written before the refusal (stat err %v)", err)
			}
		})
	}
}

// A second descriptor among the small members the preview reads after the
// first (a manifest, a certificate) is refused, naming both.
func TestInspectOVA_RefusesASecondDescriptorItReads(t *testing.T) {
	ova := buildTar(t,
		tarMember{name: "a.ovf", body: []byte(ovfWindowsSCSI)},
		tarMember{name: "a.mf", body: []byte("SHA256(a.ovf)= 00\n")},
		tarMember{name: "b.ovf", body: []byte(ovfOther)},
		tarMember{name: "disk-0.vmdk", body: make([]byte, 4096)},
	)
	_, err := InspectOVA(bytes.NewReader(ova))
	if err == nil || !strings.Contains(err.Error(), `"a.ovf"`) || !strings.Contains(err.Error(), `"b.ovf"`) {
		t.Fatalf("InspectOVA err = %v, want a refusal naming a.ovf and b.ovf", err)
	}
}

// A second descriptor behind a disk is out of the preview's sight: reading
// to it would read the disk. The preview describes the first descriptor
// without reading the disk, and the import refuses the archive.
func TestInspectOVA_SecondDescriptorBehindADiskIsLeftToTheImport(t *testing.T) {
	disk := make([]byte, 4<<20)
	ova := buildTar(t,
		tarMember{name: "a.ovf", body: []byte(ovfWindowsSCSI)},
		tarMember{name: "disk-0.vmdk", body: disk},
		tarMember{name: "b.ovf", body: []byte(ovfOther)},
	)
	cr := &countingReader{r: bytes.NewReader(ova)}
	data, err := InspectOVA(cr)
	if err != nil || string(data) != ovfWindowsSCSI {
		t.Fatalf("InspectOVA = %d bytes, %v; want the first descriptor", len(data), err)
	}
	if cr.n >= len(disk) {
		t.Fatalf("InspectOVA read %d bytes: it read the disk", cr.n)
	}
	if _, err := UnpackOVA(bytes.NewReader(ova), t.TempDir(), Budget(1<<30)); err == nil || !strings.Contains(err.Error(), "more than one .ovf") {
		t.Fatalf("UnpackOVA err = %v, want the second-descriptor refusal", err)
	}
}

// A second descriptor whose name is not canonical ("a.ovf/.", "a.ovf/x/..",
// "a.ovf\.") is still a descriptor: the import writes it, flattened, over
// the first. Both the preview and the import judge a member by the name the
// import writes it under, so both refuse the archive; otherwise the preview
// would describe one VM and the import create another.
func TestOVA_ANonCanonicalSecondDescriptorIsRefusedByPreviewAndImport(t *testing.T) {
	for _, second := range []string{"a.ovf/.", "a.ovf/x/..", `a.ovf\.`, "sub/./a.ovf"} {
		t.Run(second, func(t *testing.T) {
			ova := buildTar(t,
				tarMember{name: "a.ovf", body: []byte(ovfWindowsSCSI)},
				tarMember{name: second, body: []byte(ovfOther)},
				tarMember{name: "disk-0.vmdk", body: make([]byte, 4096)},
			)
			if _, err := InspectOVA(bytes.NewReader(ova)); err == nil || !strings.Contains(err.Error(), "more than one .ovf") {
				t.Fatalf("InspectOVA err = %v, want the second-descriptor refusal", err)
			}
			dest := t.TempDir()
			_, err := UnpackOVA(bytes.NewReader(ova), dest, Budget(1<<30))
			if err == nil || !strings.Contains(err.Error(), "more than one .ovf") {
				t.Fatalf("UnpackOVA err = %v, want the second-descriptor refusal", err)
			}
			if got, _ := os.ReadFile(filepath.Join(dest, "a.ovf")); string(got) != ovfWindowsSCSI {
				t.Fatalf("the first descriptor was overwritten before the refusal: %q", got)
			}
		})
	}
}

// Two members that flatten to one name would have the second overwrite the
// first. The import refuses the second before writing it, and so does the
// preview for the members it reads.
func TestOVA_AMemberRepeatingAnEarlierFlattenedNameIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		ova  []tarMember
	}{
		{"disk before the descriptor", []tarMember{
			{name: "disk-0.vmdk", body: []byte("first")},
			{name: "x/disk-0.vmdk", body: []byte("second")},
			{name: "a.ovf", body: []byte(ovfWindowsSCSI)},
		}},
		{"manifest after the descriptor", []tarMember{
			{name: "a.ovf", body: []byte(ovfWindowsSCSI)},
			{name: "a.mf", body: []byte("first")},
			{name: "y/a.mf", body: []byte("second")},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ova := buildTar(t, tc.ova...)
			if _, err := InspectOVA(bytes.NewReader(ova)); err == nil || !strings.Contains(err.Error(), "repeats") {
				t.Fatalf("InspectOVA err = %v, want the repeated-name refusal", err)
			}
			dest := t.TempDir()
			if _, err := UnpackOVA(bytes.NewReader(ova), dest, Budget(1<<30)); err == nil || !strings.Contains(err.Error(), "repeats") {
				t.Fatalf("UnpackOVA err = %v, want the repeated-name refusal", err)
			}
			first := filepath.Base(tc.ova[0].name)
			if tc.name == "manifest after the descriptor" {
				first = "a.mf"
			}
			if got, _ := os.ReadFile(filepath.Join(dest, first)); string(got) != "first" {
				t.Fatalf("%s was overwritten before the refusal: %q", first, got)
			}
		})
	}
}

// The preview's trailer budget is cumulative: after one 600 KiB member, a
// second does not fit what is left of maxInspectTrailer, so the walk stops
// at its header without reading its body, and a descriptor behind it is
// out of sight (the import refuses that archive). A per-member budget would
// read both and so let a preview skip thousands of near-1 MiB members.
func TestInspectOVA_TrailerBudgetIsCumulative(t *testing.T) {
	const member = 600 << 10
	head := buildTar(t,
		tarMember{name: "a.ovf", body: []byte(ovfWindowsSCSI)},
		tarMember{name: "a.cert", body: make([]byte, member)},
	)
	ova := buildTar(t,
		tarMember{name: "a.ovf", body: []byte(ovfWindowsSCSI)},
		tarMember{name: "a.cert", body: make([]byte, member)},
		tarMember{name: "a.mf", body: make([]byte, member)},
		tarMember{name: "b.ovf", body: []byte(ovfOther)},
	)
	cr := &countingReader{r: bytes.NewReader(ova)}
	data, err := InspectOVA(cr)
	if err != nil || string(data) != ovfWindowsSCSI {
		t.Fatalf("InspectOVA = %d bytes, %v; want the first descriptor", len(data), err)
	}
	// head ends in the two zero blocks that close an archive; the second
	// member's header takes the place of the first of them.
	if limit := len(head) - 512; cr.n > limit {
		t.Fatalf("InspectOVA read %d bytes, past the second member's header (%d): it read that member", cr.n, limit)
	}
	if _, err := UnpackOVA(bytes.NewReader(ova), t.TempDir(), Budget(1<<30)); err == nil || !strings.Contains(err.Error(), "more than one .ovf") {
		t.Fatalf("UnpackOVA err = %v, want the second-descriptor refusal", err)
	}
}

// sparseTar is an io.ReadSeeker over a tar whose member bodies are zeros
// unless given, so a test can declare members of terabytes: archive/tar
// seeks past a body it skips, and nothing of it is held in memory.
type sparseTar struct {
	parts []sparsePart
	size  int64
	off   int64
}

type sparsePart struct {
	at int64
	b  []byte
}

func newSparseTar(t *testing.T, members ...sparseMember) *sparseTar {
	t.Helper()
	st := &sparseTar{}
	for _, m := range members {
		var hb bytes.Buffer
		tw := tar.NewWriter(&hb)
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: m.size, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
		st.parts = append(st.parts, sparsePart{at: st.size, b: hb.Bytes()})
		st.size += int64(hb.Len())
		if m.body != nil {
			st.parts = append(st.parts, sparsePart{at: st.size, b: m.body})
		}
		st.size += (m.size + 511) &^ 511
	}
	st.size += 1024 // the two zero blocks that end an archive
	return st
}

type sparseMember struct {
	name string
	size int64
	body []byte // nil: zeros
}

func (s *sparseTar) Read(p []byte) (int, error) {
	if s.off >= s.size {
		return 0, io.EOF
	}
	if rem := s.size - s.off; int64(len(p)) > rem {
		p = p[:rem]
	}
	clear(p)
	for _, pt := range s.parts {
		lo, hi := max(pt.at, s.off), min(pt.at+int64(len(pt.b)), s.off+int64(len(p)))
		if lo < hi {
			copy(p[lo-s.off:hi-s.off], pt.b[lo-pt.at:hi-pt.at])
		}
	}
	s.off += int64(len(p))
	return len(p), nil
}

func (s *sparseTar) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		s.off = off
	case io.SeekCurrent:
		s.off += off
	case io.SeekEnd:
		s.off = s.size + off
	}
	return s.off, nil
}

// The preview applies the import's member and archive size caps to the
// sizes the headers it reads declare, ahead of the descriptor and after it.
func TestInspectOVA_RefusesTheImportsSizeCaps(t *testing.T) {
	ovf := []byte(ovfWindowsSCSI)
	for _, tc := range []struct {
		name    string
		members []sparseMember
		want    string
	}{
		{"member over the cap ahead of the descriptor", []sparseMember{
			{name: "disk-0.vmdk", size: maxMemberSize + 1},
			{name: "a.ovf", size: int64(len(ovf)), body: ovf},
		}, "exceeds size cap"},
		{"member over the cap after the descriptor", []sparseMember{
			{name: "a.ovf", size: int64(len(ovf)), body: ovf},
			{name: "disk-0.vmdk", size: maxMemberSize + 1},
		}, "exceeds size cap"},
		{"archive over the cap ahead of the descriptor", []sparseMember{
			{name: "disk-0.vmdk", size: maxMemberSize},
			{name: "disk-1.vmdk", size: maxMemberSize},
			{name: "a.ovf", size: int64(len(ovf)), body: ovf},
		}, "total size cap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := InspectOVA(newSparseTar(t, tc.members...)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("InspectOVA err = %v, want %q", err, tc.want)
			}
		})
	}
	// The import refuses an oversized member at its header, as the preview
	// does (its archive cap is the same admit; reaching it would write 8 TiB).
	_, err := UnpackOVA(newSparseTar(t, sparseMember{name: "disk-0.vmdk", size: maxMemberSize + 1}), t.TempDir(), Budget(1<<30))
	if err == nil || !strings.Contains(err.Error(), "exceeds size cap") {
		t.Fatalf("UnpackOVA err = %v, want the member size cap", err)
	}
	// The sparse archive itself is well formed: within the caps it previews.
	data, err := InspectOVA(newSparseTar(t,
		sparseMember{name: "disk-0.vmdk", size: maxMemberSize},
		sparseMember{name: "a.ovf", size: int64(len(ovf)), body: ovf},
	))
	if err != nil || string(data) != ovfWindowsSCSI {
		t.Fatalf("InspectOVA of a capped sparse archive = %d bytes, %v", len(data), err)
	}
}
