package filerestore

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type tEnt struct {
	name     string
	typ      byte
	body     string
	link     string
	mode     int64
	pax      map[string]string
	declared int64 // size to declare when != len(body)
}

func mkTar(t *testing.T, ents ...tEnt) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link,
			ModTime: time.Unix(1700000000, 0), PAXRecords: e.pax, Uid: 1234, Gid: 1234, Uname: "evil", Format: tar.FormatPAX}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
			if e.declared != 0 {
				h.Size = e.declared
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("header %q: %v", e.name, err)
		}
		if e.typ == tar.TypeReg && e.declared == 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type outEnt struct {
	h    *tar.Header
	body string
}

func readTar(t *testing.T, b []byte) map[string]outEnt {
	t.Helper()
	out := map[string]outEnt{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("sanitized archive is not valid: %v", err)
		}
		body, _ := io.ReadAll(tr)
		out[h.Name] = outEnt{h, string(body)}
	}
}

// Names a careless extractor would write outside its directory, or that are
// not names at all, never reach the caller.
func TestSanitizeTar_RefusesUnsafeNames(t *testing.T) {
	in := mkTar(t,
		tEnt{name: "vda1/ok.txt", typ: tar.TypeReg, body: "fine"},
		tEnt{name: "/etc/passwd", typ: tar.TypeReg, body: "abs"},
		tEnt{name: "vda1/../../etc/shadow", typ: tar.TypeReg, body: "dotdot"},
		tEnt{name: "vda1/a/../b", typ: tar.TypeReg, body: "unclean"},
		tEnt{name: "vda1/./c", typ: tar.TypeReg, body: "dot"},
		tEnt{name: "vda1/" + strings.Repeat("x", 300), typ: tar.TypeReg, body: "long component"},
		tEnt{name: "vda2/elsewhere", typ: tar.TypeReg, body: "not selected"},
		tEnt{name: "vda1x/prefix-trick", typ: tar.TypeReg, body: "not selected"},
	)
	var out bytes.Buffer
	st, err := SanitizeTar(&out, bytes.NewReader(in), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatalf("SanitizeTar: %v", err)
	}
	got := readTar(t, out.Bytes())
	if len(got) != 1 || got["vda1/ok.txt"].body != "fine" {
		t.Fatalf("got %v, want only vda1/ok.txt", keys(got))
	}
	if st.Skipped != 7 {
		t.Fatalf("skipped %d, want 7", st.Skipped)
	}
}

func TestSanitizeTar_RefusesNonUTF8AndNUL(t *testing.T) {
	// archive/tar will not write these names itself; build the header bytes.
	in := mkTar(t, tEnt{name: "vda1/good", typ: tar.TypeReg, body: "g"})
	bad := rawTarHeader(t, "vda1/bad\xff", "x")
	in = append(bad, in...)
	var out bytes.Buffer
	if _, err := SanitizeTar(&out, bytes.NewReader(in), []string{"vda1"}, TarLimits{}); err != nil {
		t.Fatalf("SanitizeTar: %v", err)
	}
	got := readTar(t, out.Bytes())
	if _, ok := got["vda1/good"]; !ok || len(got) != 1 {
		t.Fatalf("got %v", keys(got))
	}
}

// rawTarHeader writes one ustar regular-file entry with an arbitrary name.
func rawTarHeader(t *testing.T, name, body string) []byte {
	t.Helper()
	h := make([]byte, 512)
	copy(h[0:100], name)
	copy(h[100:108], "0000644\x00")
	copy(h[108:116], "0000000\x00")
	copy(h[116:124], "0000000\x00")
	copy(h[124:136], []byte(octal(int64(len(body)), 11)+"\x00"))
	copy(h[136:148], "00000000000\x00")
	h[156] = '0'
	copy(h[257:263], "ustar\x00")
	copy(h[263:265], "00")
	for i := 148; i < 156; i++ {
		h[i] = ' '
	}
	var sum int64
	for _, c := range h {
		sum += int64(c)
	}
	copy(h[148:156], octal(sum, 6)+"\x00 ")
	data := make([]byte, (len(body)+511)/512*512)
	copy(data, body)
	return append(h, data...)
}

func octal(n int64, width int) string {
	s := strings.Repeat("0", width) + strconvOct(n)
	return s[len(s)-width:]
}

func strconvOct(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%8)}, b...)
		n /= 8
	}
	return string(b)
}

// Only directories, regular files and symlinks pass; a hard link, device or
// fifo does not.
func TestSanitizeTar_OnlySafeTypes(t *testing.T) {
	in := mkTar(t,
		tEnt{name: "vda1/dir", typ: tar.TypeDir, mode: 0o755},
		tEnt{name: "vda1/dir/f", typ: tar.TypeReg, body: "data"},
		tEnt{name: "vda1/lnk", typ: tar.TypeSymlink, link: "/etc/shadow"},
		tEnt{name: "vda1/hard", typ: tar.TypeLink, link: "vda1/dir/f"},
		tEnt{name: "vda1/dev", typ: tar.TypeChar},
		tEnt{name: "vda1/blk", typ: tar.TypeBlock},
		tEnt{name: "vda1/fifo", typ: tar.TypeFifo},
	)
	var out bytes.Buffer
	st, err := SanitizeTar(&out, bytes.NewReader(in), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	got := readTar(t, out.Bytes())
	for _, want := range []string{"vda1/dir/", "vda1/dir/f", "vda1/lnk"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s (got %v)", want, keys(got))
		}
	}
	for _, refused := range []string{"vda1/hard", "vda1/dev", "vda1/blk", "vda1/fifo"} {
		if _, ok := got[refused]; ok {
			t.Errorf("%s passed", refused)
		}
	}
	if got["vda1/lnk"].h.Typeflag != tar.TypeSymlink || got["vda1/lnk"].h.Linkname != "/etc/shadow" {
		t.Errorf("symlink not kept as a symlink: %+v", got["vda1/lnk"].h)
	}
	if st.Skipped != 4 {
		t.Errorf("skipped %d, want 4", st.Skipped)
	}
}

// Extracting the archive must never write through a link: nothing under a
// symlink the archive holds, and no name twice (a symlink replacing a
// directory already written).
func TestSanitizeTar_NothingThroughASymlink(t *testing.T) {
	in := mkTar(t,
		tEnt{name: "vda1/esc", typ: tar.TypeSymlink, link: "/root/.ssh"},
		tEnt{name: "vda1/esc/authorized_keys", typ: tar.TypeReg, body: "ssh-ed25519 attacker"},
		tEnt{name: "vda1/d", typ: tar.TypeDir},
		tEnt{name: "vda1/d", typ: tar.TypeSymlink, link: "/etc"},
		tEnt{name: "vda1/d/cron.d", typ: tar.TypeReg, body: "x"},
	)
	var out bytes.Buffer
	if _, err := SanitizeTar(&out, bytes.NewReader(in), []string{"vda1"}, TarLimits{}); err != nil {
		t.Fatal(err)
	}
	got := readTar(t, out.Bytes())
	if _, ok := got["vda1/esc/authorized_keys"]; ok {
		t.Fatal("an entry under a symlink passed")
	}
	if e, ok := got["vda1/d/"]; !ok || e.h.Typeflag != tar.TypeDir {
		t.Fatalf("the first vda1/d (a directory) should stand: %v", keys(got))
	}
	for name, e := range got {
		if strings.TrimSuffix(name, "/") == "vda1/d" && e.h.Typeflag == tar.TypeSymlink {
			t.Fatal("a symlink replaced a directory already in the archive")
		}
	}
}

// Headers are rebuilt: permission bits only, no owner, no guest PAX records.
func TestSanitizeTar_RebuildsHeaders(t *testing.T) {
	in := mkTar(t, tEnt{name: "vda1/suid", typ: tar.TypeReg, body: "x", mode: 0o4755,
		pax: map[string]string{"SCHILY.xattr.security.capability": "cap", "LIBARCHIVE.xattr.user.x": "y"}})
	var out bytes.Buffer
	if _, err := SanitizeTar(&out, bytes.NewReader(in), []string{"vda1"}, TarLimits{}); err != nil {
		t.Fatal(err)
	}
	h := readTar(t, out.Bytes())["vda1/suid"].h
	if h == nil {
		t.Fatal("entry missing")
	}
	if h.Mode != 0o755 {
		t.Errorf("mode %o, want 755 (setuid stripped)", h.Mode)
	}
	if h.Uid != 0 || h.Gid != 0 || h.Uname != "" {
		t.Errorf("owner carried over: uid=%d gid=%d uname=%q", h.Uid, h.Gid, h.Uname)
	}
	for k := range h.PAXRecords {
		if strings.Contains(k, "xattr") {
			t.Errorf("guest PAX record %q carried over", k)
		}
	}
}

func TestSanitizeTar_Limits(t *testing.T) {
	in := mkTar(t,
		tEnt{name: "vda1/a", typ: tar.TypeReg, body: strings.Repeat("a", 100)},
		tEnt{name: "vda1/b", typ: tar.TypeReg, body: strings.Repeat("b", 100)},
		tEnt{name: "vda1/c", typ: tar.TypeReg, body: strings.Repeat("c", 100)},
	)
	var out bytes.Buffer
	st, err := SanitizeTar(&out, bytes.NewReader(in), []string{"vda1"}, TarLimits{MaxBytes: 250})
	if !errors.Is(err, ErrLimit) || !st.Truncated {
		t.Fatalf("want ErrLimit and Truncated at 250 bytes, got %v %+v", err, st)
	}
	got := readTar(t, out.Bytes()) // still a valid, closed archive
	if len(got) != 2 || st.Bytes != 200 {
		t.Fatalf("got %v (%d bytes), want a and b only", keys(got), st.Bytes)
	}
	out.Reset()
	st, err = SanitizeTar(&out, bytes.NewReader(in), []string{"vda1"}, TarLimits{MaxEntries: 1})
	if !errors.Is(err, ErrLimit) || len(readTar(t, out.Bytes())) != 1 {
		t.Fatalf("MaxEntries 1: err=%v %+v", err, st)
	}
}

// An archive that ends inside a file is an error, not a short file passed on
// as whole.
func TestSanitizeTar_TruncatedStream(t *testing.T) {
	in := mkTar(t, tEnt{name: "vda1/big", typ: tar.TypeReg, body: strings.Repeat("z", 5000)})
	var out bytes.Buffer
	if _, err := SanitizeTar(&out, bytes.NewReader(in[:512+1000]), []string{"vda1"}, TarLimits{}); err == nil {
		t.Fatal("a truncated archive was accepted")
	}
}

// A stream of refused headers is bounded too.
func TestSanitizeTar_HeaderFloodBounded(t *testing.T) {
	old := maxTarHeaders
	maxTarHeaders = 50
	defer func() { maxTarHeaders = old }()
	var ents []tEnt
	for i := 0; i < 60; i++ {
		ents = append(ents, tEnt{name: "other/x" + itoa(i), typ: tar.TypeReg, body: "."})
	}
	var out bytes.Buffer
	if _, err := SanitizeTar(&out, bytes.NewReader(mkTar(t, ents...)), []string{"vda1"}, TarLimits{}); err == nil {
		t.Fatal("60 refused headers past a bound of 50 were read without error")
	}
}

func TestSanitizeEntries(t *testing.T) {
	in := []Entry{
		{Name: "ok", Type: TypeFile, Size: 10, Mode: 0o4755},
		{Name: "ok", Type: TypeFile},        // duplicate
		{Name: "a/b", Type: TypeFile},       // slash
		{Name: "..", Type: TypeDir},         // dot-dot
		{Name: "bad\xff", Type: TypeFile},   // not UTF-8
		{Name: "weird", Type: "blockdev"},   // unknown type
		{Name: "d", Type: TypeDir, Size: 9}, // dir size
		{Name: "f", Type: TypeFile, Target: "/x"},
		{Name: "l", Type: TypeSymlink, Target: "/etc/passwd"},
		{Name: "neg", Type: TypeFile, Size: -5},
	}
	out, skipped := SanitizeEntries(in)
	if skipped != 4 {
		t.Fatalf("skipped %d, want 4", skipped)
	}
	byName := map[string]Entry{}
	for _, e := range out {
		byName[e.Name] = e
	}
	if byName["ok"].Mode != 0o755 {
		t.Errorf("mode %o", byName["ok"].Mode)
	}
	if byName["weird"].Type != TypeOther {
		t.Errorf("unknown type kept: %q", byName["weird"].Type)
	}
	if byName["d"].Size != 0 || byName["neg"].Size != 0 {
		t.Errorf("sizes: d=%d neg=%d", byName["d"].Size, byName["neg"].Size)
	}
	if byName["f"].Target != "" || byName["l"].Target != "/etc/passwd" {
		t.Errorf("targets: f=%q l=%q", byName["f"].Target, byName["l"].Target)
	}
	many := make([]Entry, MaxListEntries+10)
	for i := range many {
		many[i] = Entry{Name: "n" + strings.Repeat("x", i%7) + string(rune('A'+i%26)) + itoa(i), Type: TypeFile}
	}
	if out, _ := SanitizeEntries(many); len(out) != MaxListEntries {
		t.Errorf("kept %d entries, cap is %d", len(out), MaxListEntries)
	}
}

func itoa(i int) string {
	return strconvOct(int64(i))
}

func TestSelectionNamesAndPaths(t *testing.T) {
	if _, err := SelectionNames([]string{"/"}); err == nil {
		t.Error("selecting / was accepted")
	}
	if _, err := SelectionNames([]string{"/vda1/../x"}); err == nil {
		t.Error(".. was accepted")
	}
	if _, err := SelectionNames([]string{"vda1/etc"}); err == nil {
		t.Error("a relative path was accepted")
	}
	got, err := SelectionNames([]string{"/vda1/etc//hosts/"})
	if err != nil || got[0] != "vda1/etc/hosts" {
		t.Errorf("got %v %v", got, err)
	}
	if v, r := SplitVolume("/rootfs/etc/x"); v != "rootfs" || r != "etc/x" {
		t.Errorf("SplitVolume: %q %q", v, r)
	}
}

func keys(m map[string]outEnt) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
