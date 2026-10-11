package filerestore

import (
	"archive/tar"
	"bufio"
	"bytes"
	"errors"
	"io"
	"math"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/filerestore/wire"
)

// rec is one record of a hostile agent's stream, with its data.
type rec struct {
	wire.Record
	data string
}

func file(name, data string) rec {
	return rec{wire.Record{Name: name, Type: TypeFile, Size: int64(len(data)), Mode: 0o644, MTime: 1700000000}, data}
}

func dir(name string) rec { return rec{wire.Record{Name: name, Type: TypeDir, Mode: 0o755}, ""} }

func link(name, target string) rec {
	return rec{wire.Record{Name: name, Type: TypeSymlink, Link: target}, ""}
}

// stream encodes records the way the agent does, ending the stream unless
// noEnd.
func stream(t *testing.T, noEnd bool, recs ...rec) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, r := range recs {
		if err := wire.WriteRecord(&b, r.Record); err != nil {
			t.Fatal(err)
		}
		b.WriteString(r.data)
	}
	if !noEnd {
		_ = wire.WriteRecord(&b, wire.Record{End: true})
	}
	return b.Bytes()
}

func sanitize(t *testing.T, in []byte, sels []string, lim TarLimits) (map[string]outEnt, TarStats, error) {
	t.Helper()
	var out bytes.Buffer
	st, err := SanitizeStream(&out, bufio.NewReader(bytes.NewReader(in)), sels, lim)
	if err != nil && !errors.Is(err, ErrLimit) {
		return nil, st, err
	}
	return readTar(t, out.Bytes()), st, err
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

func keys(m map[string]outEnt) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Names a careless extractor would write outside its directory, or that are
// not names at all, never reach the caller.
func TestSanitize_RefusesUnsafeNames(t *testing.T) {
	got, st, err := sanitize(t, stream(t, false,
		file("vda1/ok.txt", "fine"),
		file("/etc/passwd", "abs"),
		file("vda1/../../etc/shadow", "dotdot"),
		file("vda1/a/../b", "unclean"),
		file("vda1/./c", "dot"),
		file("vda1/"+strings.Repeat("x", 300), "long component"),
		file("vda2/elsewhere", "not selected"),
		file("vda1x/prefix-trick", "not selected"),
		file("vda1/nul\x00byte", "nul"),
	), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatalf("SanitizeStream: %v", err)
	}
	if len(got) != 1 || got["vda1/ok.txt"].body != "fine" {
		t.Fatalf("got %v, want only vda1/ok.txt", keys(got))
	}
	if st.Skipped != 8 {
		t.Fatalf("skipped %d, want 8", st.Skipped)
	}
}

// Only directories, regular files and symlinks pass.
func TestSanitize_OnlySafeTypes(t *testing.T) {
	got, st, err := sanitize(t, stream(t, false,
		dir("vda1/dir"),
		file("vda1/dir/f", "data"),
		link("vda1/lnk", "dir/f"),
		rec{wire.Record{Name: "vda1/hard", Type: "hardlink", Link: "vda1/dir/f"}, ""},
		rec{wire.Record{Name: "vda1/dev", Type: TypeOther}, ""},
		rec{wire.Record{Name: "vda1/blk", Type: "blockdev"}, ""},
	), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vda1/dir/", "vda1/dir/f", "vda1/lnk"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s (got %v)", want, keys(got))
		}
	}
	for _, refused := range []string{"vda1/hard", "vda1/dev", "vda1/blk"} {
		if _, ok := got[refused]; ok {
			t.Errorf("%s passed", refused)
		}
	}
	if got["vda1/lnk"].h == nil || got["vda1/lnk"].h.Typeflag != tar.TypeSymlink || got["vda1/lnk"].h.Linkname != "dir/f" {
		t.Errorf("symlink not kept as a symlink: %+v", got["vda1/lnk"].h)
	}
	if st.Skipped != 3 {
		t.Errorf("skipped %d, want 3", st.Skipped)
	}
}

// Extracting the archive must never write through a link: nothing under a
// symlink the archive holds, and no name twice.
func TestSanitize_NothingThroughASymlink(t *testing.T) {
	got, _, err := sanitize(t, stream(t, false,
		// Targets inside the archive, so the links themselves are kept.
		link("vda1/esc", "other"),
		file("vda1/esc/authorized_keys", "ssh-ed25519 attacker"),
		dir("vda1/d"),
		link("vda1/d", "other"),
		file("vda1/d/cron.d", "x"),
	), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
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

// On a case-insensitive or normalizing filesystem (macOS, Windows), "A" and
// "a", or NFC and NFD spellings, are one path: the symlink and duplicate
// checks compare them as one.
func TestSanitize_CaseAndNormalizationCollisions(t *testing.T) {
	nfc, nfd := "vda1/café", "vda1/café"
	got, st, err := sanitize(t, stream(t, false,
		link("vda1/A", "x"),
		file("vda1/a/authorized_keys", "attacker"),
		link(nfc, "x"),
		file(nfd+"/cron", "x"),
		file("vda1/Readme", "1"),
		file("vda1/README", "2"),
	), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, refused := range []string{"vda1/a/authorized_keys", nfd + "/cron", "vda1/README"} {
		if _, ok := got[refused]; ok {
			t.Errorf("%q passed", refused)
		}
	}
	if st.Skipped != 3 {
		t.Errorf("skipped %d, want 3 (%v)", st.Skipped, keys(got))
	}
}

// Headers are built from scratch: permission bits only, no owner.
func TestSanitize_RebuildsHeaders(t *testing.T) {
	r := file("vda1/suid", "x")
	r.Mode = 0o4755
	got, _, err := sanitize(t, stream(t, false, r), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	h := got["vda1/suid"].h
	if h == nil || h.Mode != 0o755 || h.Uid != 0 || h.Gid != 0 || h.Uname != "" {
		t.Fatalf("header %+v: want mode 755, no owner", h)
	}
}

func TestSanitize_Limits(t *testing.T) {
	in := stream(t, false,
		file("vda1/a", strings.Repeat("a", 100)),
		file("vda1/b", strings.Repeat("b", 100)),
		file("vda1/c", strings.Repeat("c", 100)),
	)
	// The cap is the whole archive's: each entry here costs its 512-byte
	// header and padded data, plus the header allowance it is checked with.
	got, st, err := sanitize(t, in, []string{"vda1"}, TarLimits{MaxBytes: 3000})
	if !errors.Is(err, ErrLimit) || !st.Truncated {
		t.Fatalf("want ErrLimit and Truncated at 3000 bytes, got %v %+v", err, st)
	}
	if len(got) != 2 || st.Bytes != 200 {
		t.Fatalf("got %v (%d bytes), want a and b only", keys(got), st.Bytes)
	}
	got, _, err = sanitize(t, in, []string{"vda1"}, TarLimits{MaxEntries: 1})
	if !errors.Is(err, ErrLimit) || len(got) != 1 {
		t.Fatalf("MaxEntries 1: err=%v %v", err, keys(got))
	}
}

// I-1: a size near MaxInt64 after a small file must not wrap the byte cap
// into a pass.
func TestSanitize_SizeCannotOverflowTheCap(t *testing.T) {
	huge := rec{wire.Record{Name: "vda1/huge", Type: TypeFile, Size: math.MaxInt64}, ""}
	in := stream(t, true, file("vda1/one", "x"), huge)
	got, st, err := sanitize(t, in, []string{"vda1"}, TarLimits{MaxBytes: 1 << 20})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("a MaxInt64-byte file after a 1-byte one: err=%v, want ErrLimit", err)
	}
	if _, ok := got["vda1/huge"]; ok || st.Bytes != 1 {
		t.Fatalf("got %v, %d bytes", keys(got), st.Bytes)
	}
}

// I-1: the bytes counted are the bytes written, and refused entries' bytes
// are bounded by the same cap (they are read to stay in step).
func TestSanitize_RefusedBytesAreBounded(t *testing.T) {
	refused := rec{wire.Record{Name: "elsewhere/big", Type: TypeFile, Size: 1 << 40}, ""}
	in := stream(t, true, refused)
	_, _, err := sanitize(t, in, []string{"vda1"}, TarLimits{MaxBytes: 1 << 20})
	if err == nil || !strings.Contains(err.Error(), "refused data") {
		t.Fatalf("a refused 1 TiB entry under a 1 MiB cap: %v", err)
	}
}

// I-1: the host reads records, not tar — a GNU sparse archive (whose holes a
// tar reader would synthesize as endless zeros) is not parsed at all.
func TestSanitize_SparseTarIsNotParsed(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	_ = tw.WriteHeader(&tar.Header{Name: "vda1/sparse", Typeflag: tar.TypeReg, Size: 0, Format: tar.FormatPAX,
		PAXRecords: map[string]string{"GNU.sparse.major": "1", "GNU.sparse.minor": "0", "GNU.sparse.name": "vda1/sparse",
			"GNU.sparse.realsize": strconv.FormatInt(math.MaxInt64, 10)}})
	_ = tw.Close()
	var out bytes.Buffer
	start := time.Now()
	_, err := SanitizeStream(&out, bufio.NewReader(bytes.NewReader(b.Bytes())), []string{"vda1"}, TarLimits{})
	if err == nil {
		t.Fatal("a sparse tar was accepted as a record stream")
	}
	if out.Len() > 1024 || time.Since(start) > time.Second {
		t.Fatalf("a sparse tar produced %d bytes in %v", out.Len(), time.Since(start))
	}
}

// I-2: the names one extraction remembers are bounded, whatever their
// length; past the bound the extraction stops.
func TestSanitize_TrackingIsBounded(t *testing.T) {
	old := maxTracked
	maxTracked = 10
	defer func() { maxTracked = old }()
	var recs []rec
	for i := 0; i < 20; i++ {
		recs = append(recs, file("vda1/"+strings.Repeat("n", 200)+strconv.Itoa(i), ""))
	}
	got, st, err := sanitize(t, stream(t, false, recs...), []string{"vda1"}, TarLimits{})
	if !errors.Is(err, ErrLimit) || len(got) != 10 || !st.Truncated {
		t.Fatalf("20 entries past a tracking bound of 10: err=%v kept=%d", err, len(got))
	}
}

// A record line over its bound, and a stream that ends inside a file, are
// errors.
func TestSanitize_MalformedStreams(t *testing.T) {
	long := []byte(`{"n":"` + strings.Repeat("x", wire.MaxRecordLine) + `","t":"file"}` + "\n")
	if _, _, err := sanitize(t, long, []string{"vda1"}, TarLimits{}); err == nil {
		t.Error("an oversized record line was accepted")
	}
	short := stream(t, true, file("vda1/big", strings.Repeat("z", 5000)))
	short = short[:len(short)-4000]
	if _, _, err := sanitize(t, short, []string{"vda1"}, TarLimits{}); err == nil {
		t.Error("a stream that ends inside a file was accepted")
	}
	neg := stream(t, false, rec{wire.Record{Name: "vda1/n", Type: TypeFile, Size: -1}, ""})
	if _, _, err := sanitize(t, neg, []string{"vda1"}, TarLimits{}); err == nil {
		t.Error("a negative size was accepted")
	}
	if _, _, err := sanitize(t, []byte("not json\n"), []string{"vda1"}, TarLimits{}); err == nil {
		t.Error("garbage was accepted")
	}
}

// A stream of refused records is bounded too.
func TestSanitize_RecordFloodBounded(t *testing.T) {
	old := maxRecords
	maxRecords = 50
	defer func() { maxRecords = old }()
	var recs []rec
	for i := 0; i < 60; i++ {
		recs = append(recs, file("other/x"+strconv.Itoa(i), "."))
	}
	if _, _, err := sanitize(t, stream(t, false, recs...), []string{"vda1"}, TarLimits{}); err == nil {
		t.Fatal("60 refused records past a bound of 50 were read without error")
	}
}

func TestSanitizeEntries(t *testing.T) {
	in := []Entry{
		{Name: "ok", Type: TypeFile, Size: 10, Mode: 0o4755},
		{Name: "ok", Type: TypeFile},
		{Name: "a/b", Type: TypeFile},
		{Name: "..", Type: TypeDir},
		{Name: "bad\xff", Type: TypeFile},
		{Name: "weird", Type: "blockdev"},
		{Name: "d", Type: TypeDir, Size: 9},
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
	if byName["ok"].Mode != 0o755 || byName["weird"].Type != TypeOther || byName["d"].Size != 0 || byName["neg"].Size != 0 {
		t.Errorf("entries %+v", byName)
	}
	if byName["f"].Target != "" || byName["l"].Target != "/etc/passwd" {
		t.Errorf("targets: f=%q l=%q", byName["f"].Target, byName["l"].Target)
	}
	many := make([]Entry, MaxListEntries+10)
	for i := range many {
		many[i] = Entry{Name: "n" + strconv.Itoa(i), Type: TypeFile}
	}
	if out, _ := SanitizeEntries(many); len(out) != MaxListEntries {
		t.Errorf("kept %d entries, cap is %d", len(out), MaxListEntries)
	}
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
}

// N-6: Unicode case folding, as APFS and NTFS apply it — "ſ" is "s", "ς"
// is "σ" — not just ToLower.
func TestSanitize_UnicodeCaseFolding(t *testing.T) {
	got, st, err := sanitize(t, stream(t, false,
		link("vda1/s", "x"),
		file("vda1/ſ/authorized_keys", "attacker"), // ſ
		file("vda1/σ", "1"),                        // σ
		file("vda1/ς", "2"),                        // ς
	), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["vda1/ſ/authorized_keys"]; ok {
		t.Error("an entry under a symlink, spelled with ſ for s, passed")
	}
	if _, ok := got["vda1/ς"]; ok {
		t.Error("ς passed beside σ")
	}
	if st.Skipped != 2 {
		t.Errorf("skipped %d, want 2", st.Skipped)
	}
}

// N-3: names have at most MaxDepth components, and a deep name costs a
// hash per depth where a symlink was written, not one per component.
func TestSanitize_DepthBoundedAndCheap(t *testing.T) {
	deep := "vda1" + strings.Repeat("/d", MaxDepth)
	got, _, err := sanitize(t, stream(t, false, file(deep, "x")), []string{"vda1"}, TarLimits{})
	if err != nil || len(got) != 0 {
		t.Fatalf("a %d-deep name: %v %v", MaxDepth+1, keys(got), err)
	}
	// One symlink at depth 2, then many deep records under other names.
	recs := []rec{link("vda1/l", "x")}
	for i := 0; i < 200; i++ {
		recs = append(recs, file("vda1/q"+strconv.Itoa(i)+strings.Repeat("/d", 200), ""))
	}
	before := keyCalls
	if _, _, err := sanitize(t, stream(t, false, recs...), []string{"vda1"}, TarLimits{}); err != nil {
		t.Fatal(err)
	}
	// Per record: its own key, and one ancestor at the symlink's depth.
	if calls := keyCalls - before; calls > int64(3*len(recs)) {
		t.Fatalf("%d hashes for %d records of depth 200: the check grows with depth", calls, len(recs))
	}
}

// Names with control, bidi or invisible characters never reach a tar.
func TestSanitize_RefusesControlCharactersInNames(t *testing.T) {
	got, st, err := sanitize(t, stream(t, false,
		file("vda1/ok", "1"),
		file("vda1/esc\x1b[2J", "2"),
		file("vda1/nl\nname", "3"),
		file("vda1/bidi‮gnp.exe", "4"),
	), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || st.Skipped != 3 {
		t.Fatalf("got %v skipped %d", keys(got), st.Skipped)
	}
}

// N-8: a symlink is kept only with a relative target that stays inside the
// archive; absolute and escaping targets are left out and counted.
func TestSanitize_SymlinkTargetsConfined(t *testing.T) {
	got, st, err := sanitize(t, stream(t, false,
		link("vda1/etc/rel", "hosts"),
		link("vda1/etc/up", "../usr/share/x"),
		link("vda1/top", "../vda2/other"),
		link("vda1/abs", "/etc/shadow"),
		link("vda1/esc", "../../.ssh"),
		link("vda1/a/b/esc2", "../../../../home/u/.ssh"),
		link("vda1/self", "."),
	), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kept := range []string{"vda1/etc/rel", "vda1/etc/up", "vda1/top"} {
		if _, ok := got[kept]; !ok {
			t.Errorf("%s (a target inside the archive) was dropped", kept)
		}
	}
	for _, dropped := range []string{"vda1/abs", "vda1/esc", "vda1/a/b/esc2"} {
		if _, ok := got[dropped]; ok {
			t.Errorf("%s (an absolute or escaping target) was kept", dropped)
		}
	}
	if st.LinksDropped != 4 {
		t.Errorf("links dropped %d, want 4 (abs, esc, esc2, self)", st.LinksDropped)
	}
}

// Nit: the byte cap covers the whole archive, headers included — empty
// files with long names cannot stream past it.
func TestSanitize_HeaderBytesCount(t *testing.T) {
	var recs []rec
	for i := 0; i < 1000; i++ {
		recs = append(recs, file("vda1/"+strings.Repeat("n", 200)+strconv.Itoa(i), ""))
	}
	var out bytes.Buffer
	st, err := SanitizeStream(&out, bufio.NewReader(bytes.NewReader(stream(t, false, recs...))), []string{"vda1"}, TarLimits{MaxBytes: 64 << 10})
	if !errors.Is(err, ErrLimit) || int64(out.Len()) > 64<<10+2048 {
		t.Fatalf("1000 empty files with 200-byte names under a 64 KiB cap: err=%v, archive %d bytes (%d entries)", err, out.Len(), st.Entries)
	}
}

// R2-M1: a chain of two links, each lexically inside the archive, must not
// escape physically: the kernel resolves "up" before the ".." after it.
func TestSanitize_LinkChainCannotEscape(t *testing.T) {
	got, st, err := sanitize(t, stream(t, false,
		link("vda1/a/b/c/up", "../../.."),        // -> vda1: fine on its own
		link("vda1/esc", "a/b/c/up/../../../.."), // lexically vda1, physically 3 levels above the root
		link("vda1/mid", "x/../y"),               // ".." after a name
		link("vda1/ok", "../vda1/a"),             // leading ".." only: fine
	), []string{"vda1"}, TarLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["vda1/a/b/c/up"]; !ok {
		t.Error("a link with only leading .. inside the archive was dropped")
	}
	if _, ok := got["vda1/ok"]; !ok {
		t.Error("vda1/ok was dropped")
	}
	for _, bad := range []string{"vda1/esc", "vda1/mid"} {
		if _, ok := got[bad]; ok {
			t.Errorf("%s (a .. after a name) was kept", bad)
		}
	}
	if st.LinksDropped != 2 {
		t.Errorf("links dropped %d, want 2", st.LinksDropped)
	}
}

// R2-M3: links at every depth cannot make a record cost one hash per
// component: each record is folded once and walks the link trie.
func TestSanitize_LinksAtEveryDepthStayCheap(t *testing.T) {
	var recs []rec
	branch := "vda1"
	for d := 1; d < MaxDepth-2; d++ {
		branch += "/b"
		recs = append(recs, link(branch+"l", "x")) // a link at depth d+1, in its own branch
	}
	long := strings.Repeat("c", 200)
	deep := "vda1"
	for i := 0; i < 18; i++ {
		deep += "/" + long
	}
	for i := 0; i < 2000; i++ {
		recs = append(recs, file(deep+strconv.Itoa(i), ""))
	}
	before := keyCalls
	start := time.Now()
	if _, _, err := sanitize(t, stream(t, false, recs...), []string{"vda1"}, TarLimits{}); err != nil {
		t.Fatal(err)
	}
	if calls := keyCalls - before; calls > int64(len(recs)) {
		t.Fatalf("%d hashes for %d records: more than one per record", calls, len(recs))
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("%d records took %v", len(recs), el)
	}
}

// R3-M2: a stream of symlinks that each open their own deep branch cannot
// make the host hold a large trie: the trie and the number of links are
// capped, and an extraction past the cap stops (ErrLimit) instead of
// growing. 4096 links, each 254 one-character components deep in its own
// top branch, cost about 250 MB of daemon heap with a node per map.
func TestSanitize_LinkTrieMemoryBounded(t *testing.T) {
	var recs []rec
	for i := 0; i < 4096; i++ {
		recs = append(recs, link("vda1/"+strconv.Itoa(i)+strings.Repeat("/a", 253)+"/l", "x"))
	}
	in := stream(t, false, recs...)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, st, err := sanitize(t, in, []string{"vda1"}, TarLimits{})
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Errorf("one extraction allocated %d MB for %d symlinks", alloc>>20, len(recs))
	}
	if !errors.Is(err, ErrLimit) || !st.Truncated {
		t.Errorf("past the trie's cap the extraction must stop: err %v, stats %+v", err, st)
	}
}

// R3-M2: the number of symlinks one extraction tracks is capped too.
func TestLinkTrie_CapsLinks(t *testing.T) {
	old := maxLinks
	defer func() { maxLinks = old }()
	maxLinks = 3
	var tr linkTrie
	for i := 0; i < 3; i++ {
		if !tr.add("v/l" + strconv.Itoa(i)) {
			t.Fatalf("link %d refused under the cap", i)
		}
	}
	if tr.add("v/l3") {
		t.Fatal("a fourth link was tracked past a cap of three")
	}
	if !tr.underLink("v/l1/x") || tr.underLink("v/l9/x") || tr.underLink("v/l1") {
		t.Fatal("the capped trie answers wrongly")
	}
}
