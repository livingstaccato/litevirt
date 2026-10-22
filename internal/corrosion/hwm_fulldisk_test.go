package corrosion

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestNowTS_FullDiskKeepsAdvancingAndPersisting: on a filesystem with no free
// blocks, the clock high-water still persists and the clock still advances,
// with no fatal exit. Saving it must not need new space: the lab-2 disk-full
// incident exited the daemon 214 ms after the first save failed, because each
// save wrote a fresh temp file and renamed it over nowts.hwm.
func TestNowTS_FullDiskKeepsAdvancingAndPersisting(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	wall := t0

	c, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	c.SetWallClockForTests(func() time.Time { return wall })
	var fatal []error
	c.onPersistFatal = func(err error) { fatal = append(fatal, err) }
	last := parseTS(t, c.NowTS())
	lastHLC := c.clock.Now()

	c.hwm.fs = fullDiskHWMFS{} // the disk fills

	for i := 0; i < 60; i++ { // 30 s: fifteen times the persist-ahead headroom
		wall = wall.Add(500 * time.Millisecond)
		got := parseTS(t, c.NowTS())
		if len(fatal) != 0 {
			t.Fatalf("step %d: a full disk made clock persistence fatal (the daemon exits here): %v", i, fatal[0])
		}
		if !got.After(last) {
			t.Fatalf("step %d: NowTS did not advance: %s after %s", i, got, last)
		}
		if got.After(c.durableTS) {
			t.Fatalf("step %d: emitted %s beyond the durable ceiling %s", i, got, c.durableTS)
		}
		last = got
		h := c.clock.Now()
		if !h.After(lastHLC) {
			t.Fatalf("step %d: HLC did not advance: %s after %s", i, h, lastHLC)
		}
		lastHLC = h
	}
	if len(fatal) != 0 {
		t.Fatalf("a full disk made clock persistence fatal %d times; first: %v", len(fatal), fatal[0])
	}
	if !c.durableTS.After(t0.Add(25 * time.Second)) {
		t.Fatalf("durable ceiling %s did not advance with the clock on a full disk", c.durableTS)
	}
	onDisk, hlcMS, found, err := newHWMStore(dir).load()
	if err != nil || !found {
		t.Fatalf("load after full-disk saves: found=%v err=%v", found, err)
	}
	if onDisk.Before(last) || hlcMS < lastHLC.PhysicalMS {
		t.Fatalf("on-disk ceilings (%s, %d) are below what was emitted (%s, %d)", onDisk, hlcMS, last, lastHLC.PhysicalMS)
	}
	c.Close()

	// A restart with the wall clock an hour behind emits after everything above.
	c2, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.SetWallClockForTests(func() time.Time { return t0.Add(-time.Hour) })
	if got := parseTS(t, c2.NowTS()); !got.After(last) {
		t.Fatalf("restart regressed the LWW key: %s, already emitted %s", got, last)
	}
	if h := c2.clock.Now(); h.PhysicalMS < lastHLC.PhysicalMS {
		t.Fatalf("restart regressed the HLC: %s, already emitted %s", h, lastHLC)
	}
}

// TestNowTS_FullDiskStillFatalOnRealIOError: the deliberate exit stays for an
// error the store cannot write around. A disk that refuses even an overwrite
// still exhausts the headroom and calls onPersistFatal.
func TestNowTS_FullDiskStillFatalOnRealIOError(t *testing.T) {
	dir := t.TempDir()
	wall := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	c, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetWallClockForTests(func() time.Time { return wall })
	var fatal int
	c.onPersistFatal = func(error) { fatal++ }
	c.NowTS()
	c.hwm.fs = eioHWMFS{}
	for i := 0; i < 20 && fatal == 0; i++ {
		wall = wall.Add(500 * time.Millisecond)
		c.NowTS()
	}
	if fatal == 0 {
		t.Fatal("an I/O error on every write must still end in onPersistFatal")
	}
}

type eioHWMFS struct{ osHWMFS }

func (eioHWMFS) OpenFile(name string, flag int, perm os.FileMode) (hwmFile, error) {
	if flag&(os.O_WRONLY|os.O_RDWR) != 0 && !strings.HasSuffix(name, ".lock") {
		return nil, fmt.Errorf("open %s: input/output error", name)
	}
	return osHWMFS{}.OpenFile(name, flag, perm)
}

// parseHWMBeforeSlots is the nowts.hwm reader of every build before the
// two-slot layout, frozen verbatim: what a node rolled back to such a build
// runs on the file this build wrote.
func parseHWMBeforeSlots(s string) (lww time.Time, hlcMS int64, err error) {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) < 3 || strings.TrimSpace(lines[0]) != "v1" {
		return time.Time{}, 0, fmt.Errorf("bad header/too few lines")
	}
	var haveLWW, haveHLC bool
	for _, ln := range lines[1:] {
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			return time.Time{}, 0, fmt.Errorf("bad line %q", ln)
		}
		switch k {
		case "lww":
			t, e := time.Parse(nowTSLayout, v)
			if e != nil {
				return time.Time{}, 0, fmt.Errorf("bad lww %q: %w", v, e)
			}
			lww, haveLWW = t.UTC(), true
		case "hlc_ms":
			n, e := strconv.ParseInt(v, 10, 64)
			if e != nil || n < 0 {
				return time.Time{}, 0, fmt.Errorf("bad hlc_ms %q", v)
			}
			hlcMS, haveHLC = n, true
		}
	}
	if !haveLWW || !haveHLC {
		return time.Time{}, 0, fmt.Errorf("missing lww/hlc_ms")
	}
	return lww, hlcMS, nil
}

// legacyHWM is the exact file every build before the two-slot layout wrote.
func legacyHWM(lww time.Time, hlcMS int64) string {
	return fmt.Sprintf("v1\nlww=%s\nhlc_ms=%d\n", lww.UTC().Format(nowTSLayout), hlcMS)
}

// TestHWM_UpgradeReadsLegacyFile: a node upgraded onto this build starts from
// the ceilings the previous build persisted, and converts the file once, at
// start, to the layout it can then overwrite in place.
func TestHWM_UpgradeReadsLegacyFile(t *testing.T) {
	dir := t.TempDir()
	lww := time.Date(2026, 10, 21, 12, 0, 2, 123456789, time.UTC)
	const hlcMS = 1792584002500
	if err := os.WriteFile(filepath.Join(dir, "nowts.hwm"), []byte(legacyHWM(lww, hlcMS)), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatalf("an upgraded node must start on the previous build's nowts.hwm: %v", err)
	}
	defer c.Close()
	if !c.durableTS.Equal(lww) || c.durableHLCMS != hlcMS {
		t.Fatalf("loaded (%s, %d), want (%s, %d)", c.durableTS, c.durableHLCMS, lww, hlcMS)
	}
	b, err := os.ReadFile(filepath.Join(dir, "nowts.hwm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != hwmFileSize {
		t.Fatalf("start did not convert nowts.hwm to the in-place layout: %d bytes", len(b))
	}

	// Converted, it persists on a full disk.
	c.SetWallClockForTests(func() time.Time { return lww.Add(time.Minute) })
	var fatal int
	c.onPersistFatal = func(error) { fatal++ }
	c.hwm.fs = fullDiskHWMFS{}
	got := parseTS(t, c.NowTS())
	if fatal != 0 || !got.After(lww) {
		t.Fatalf("after conversion: fatal=%d ts=%s", fatal, got)
	}
}

// TestHWM_RollbackReaderReadsSlottedFile: a node rolled back to a build before
// the two-slot layout reads the file this build wrote, and gets the latest
// ceilings, so the rollback keeps the clock monotonic. That reader takes the
// last value of each key, and slot B is written last and holds the latest.
func TestHWM_RollbackReaderReadsSlottedFile(t *testing.T) {
	dir := t.TempDir()
	s := newHWMStore(dir)
	base := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		lww := base.Add(time.Duration(i) * 2 * time.Second)
		hlc := int64(1792584000000 + i*2000)
		if i == 3 {
			s.fs = fullDiskHWMFS{} // in place on a full disk as well
		}
		if err := s.store(lww, hlc); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
		b, err := os.ReadFile(s.path)
		if err != nil {
			t.Fatal(err)
		}
		oldLWW, oldHLC, err := parseHWMBeforeSlots(string(b))
		if err != nil {
			t.Fatalf("store %d: the previous build cannot read this build's nowts.hwm: %v\n%s", i, err, b)
		}
		if !oldLWW.Equal(lww) || oldHLC != hlc {
			t.Fatalf("store %d: previous build reads (%s, %d), want the latest (%s, %d)", i, oldLWW, oldHLC, lww, hlc)
		}
	}
}

// TestHWM_RollbackRewriteThenUpgradeAgain: a rolled-back build replaces the
// file with its own layout; upgrading again reads that and converts again.
func TestHWM_RollbackRewriteThenUpgradeAgain(t *testing.T) {
	dir := t.TempDir()
	s := newHWMStore(dir)
	lww := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if err := s.store(lww, 100); err != nil {
		t.Fatal(err)
	}
	newer := lww.Add(time.Hour)
	if err := os.WriteFile(s.path, []byte(legacyHWM(newer, 200)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, hlc, found, err := s.load()
	if err != nil || !found || !got.Equal(newer) || hlc != 200 {
		t.Fatalf("load of the rolled-back build's file: (%s, %d) found=%v err=%v", got, hlc, found, err)
	}
	if err := s.store(newer, 200); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(s.path); len(b) != hwmFileSize {
		t.Fatalf("not converted: %d bytes", len(b))
	}
}

// TestHWM_TornSlotFallsBackToTheOther: a crash mid-overwrite leaves at most
// one slot torn. The checksum rejects it and the other slot is read: slot A
// torn means slot B still holds the previous ceiling, which bounds every key
// emitted before the save returned; slot B torn means slot A already holds
// the new one. Both torn is corrupt and fails closed.
func TestHWM_TornSlotFallsBackToTheOther(t *testing.T) {
	dir := t.TempDir()
	s := newHWMStore(dir)
	prev := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if err := s.store(prev, 1000); err != nil {
		t.Fatal(err)
	}
	clean, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	tear := func(b []byte, slot int) []byte {
		out := append([]byte(nil), b...)
		off := hwmSlotOffset(slot) + 10 // inside the lww value
		out[off] ^= 0x01
		return out
	}
	for _, slot := range []int{0, 1} {
		if err := os.WriteFile(s.path, tear(clean, slot), 0o600); err != nil {
			t.Fatal(err)
		}
		got, hlc, found, err := s.load()
		if err != nil || !found || !got.Equal(prev) || hlc != 1000 {
			t.Fatalf("slot %d torn: (%s, %d) found=%v err=%v; want the other slot", slot, got, hlc, found, err)
		}
	}
	if err := os.WriteFile(s.path, tear(tear(clean, 0), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.load(); err == nil {
		t.Fatal("both slots torn must fail closed")
	}
}

// TestHWM_DamagedHeaderHealsOnNextSave: a file of the right size whose header is
// damaged is replaced by the next save, as every earlier build replaced a corrupt
// file. Overwriting only the slots would report a save that the next start
// cannot read.
func TestHWM_DamagedHeaderHealsOnNextSave(t *testing.T) {
	dir := t.TempDir()
	s := newHWMStore(dir)
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if err := s.store(at, 1000); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	b[0] = 'x'
	if err := os.WriteFile(s.path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	next := at.Add(2 * time.Second)
	if err := s.store(next, 3000); err != nil {
		t.Fatalf("save over a damaged header: %v", err)
	}
	got, hlc, found, err := s.load()
	if err != nil || !found || !got.Equal(next) || hlc != 3000 {
		t.Fatalf("after a save over a damaged header: (%s, %d) found=%v err=%v; want (%s, 3000)", got, hlc, found, err, next)
	}
}

// tornHWMFS crashes the store at its failAt-th in-place write (counting from 1):
// that write lands only n bytes, its first n (a prefix tear) or its last n (a
// suffix tear, as when a device writes the later part of a sector range first),
// and returns an error.
type tornHWMFS struct {
	osHWMFS
	failAt, n int
	suffix    bool
	writes    *int
}

func (fs tornHWMFS) OpenFile(name string, flag int, perm os.FileMode) (hwmFile, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &tornHWMFile{File: f, fs: fs}, nil
}

type tornHWMFile struct {
	*os.File
	fs tornHWMFS
}

func (f *tornHWMFile) WriteAt(b []byte, off int64) (int, error) {
	*f.fs.writes++
	if *f.fs.writes != f.fs.failAt {
		return f.File.WriteAt(b, off)
	}
	n := f.fs.n
	if f.fs.suffix {
		_, _ = f.File.WriteAt(b[len(b)-n:], off+int64(len(b)-n))
	} else {
		_, _ = f.File.WriteAt(b[:n], off)
	}
	return 0, fmt.Errorf("crash during write %d", f.fs.failAt)
}

// TestHWM_TornSaveNeverRegressesEitherReader crashes an in-place save at every
// write, torn at every length from either end. Afterwards this build's reader
// reads at least the previous ceiling, and the previous build's reader (the one
// a rolled-back node runs) either fails, which is fail-closed, or also reads at
// least the previous ceiling. A plain overwrite of slot B can tear into a mix
// that parses as an earlier time; the save blanks B's values first so it cannot.
func TestHWM_TornSaveNeverRegressesEitherReader(t *testing.T) {
	dir := t.TempDir()
	s := newHWMStore(dir)
	prev := time.Date(2026, 10, 21, 17, 59, 59, 900000000, time.UTC)
	const prevHLC = 1792529999999
	next := time.Date(2026, 10, 21, 18, 0, 2, 100000000, time.UTC)
	const nextHLC = 1792530002100
	if err := s.store(prev, prevHLC); err != nil {
		t.Fatal(err)
	}
	clean, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	for failAt := 1; failAt <= 3; failAt++ {
		for n := 0; n <= hwmSlotSize; n++ {
			for _, suffix := range []bool{false, true} {
				if err := os.WriteFile(s.path, clean, 0o600); err != nil {
					t.Fatal(err)
				}
				var writes int
				s.fs = tornHWMFS{failAt: failAt, n: n, suffix: suffix, writes: &writes}
				_ = s.store(next, nextHLC)
				s.fs = nil
				b, err := os.ReadFile(s.path)
				if err != nil {
					t.Fatal(err)
				}
				lww, hlc, err := parseHWMFile(b)
				if err != nil || lww.Before(prev) || hlc < prevHLC {
					t.Fatalf("write %d torn at %d (suffix=%v): this build reads (%s, %d, %v), below (%s, %d)",
						failAt, n, suffix, lww, hlc, err, prev, prevHLC)
				}
				if lww, hlc, err := parseHWMBeforeSlots(string(b)); err == nil && (lww.Before(prev) || hlc < prevHLC) {
					t.Fatalf("write %d torn at %d (suffix=%v): the previous build reads (%s, %d), below (%s, %d)",
						failAt, n, suffix, lww, hlc, prev, prevHLC)
				}
			}
		}
	}
}

// TestHWM_PrepareLeavesAConvertedFileAlone: opening a client on a data dir whose
// file already has the layout writes nothing (lv's read-only listing opens one).
func TestHWM_PrepareLeavesAConvertedFileAlone(t *testing.T) {
	dir := t.TempDir()
	s := newHWMStore(dir)
	if err := s.store(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), 1000); err != nil {
		t.Fatal(err)
	}
	s.fs = eioHWMFS{}
	if err := s.prepare(); err != nil {
		t.Fatalf("prepare wrote to an already-converted nowts.hwm: %v", err)
	}
}

// TestHWM_ReplaceSetsNoCOWBeforeWriting: the file a conversion creates is marked
// no-copy-on-write before its first byte is written (btrfs applies the flag
// only to an empty file), so later in-place saves need no new space there.
func TestHWM_ReplaceSetsNoCOWBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	var events []string
	old := hwmSetNoCOW
	hwmSetNoCOW = func(f hwmFile) { events = append(events, "nocow "+filepath.Base(f.Name())) }
	t.Cleanup(func() { hwmSetNoCOW = old })
	s := newHWMStore(dir)
	s.fs = recordingHWMFS{events: &events}
	if err := s.store(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), 1000); err != nil {
		t.Fatal(err)
	}
	want := []string{"nocow nowts.hwm.tmp", "write nowts.hwm.tmp"}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("events %v, want %v", events, want)
	}
}

type recordingHWMFS struct {
	osHWMFS
	events *[]string
}

func (fs recordingHWMFS) OpenFile(name string, flag int, perm os.FileMode) (hwmFile, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &recordingHWMFile{File: f, events: fs.events}, nil
}

type recordingHWMFile struct {
	*os.File
	events *[]string
}

func (f *recordingHWMFile) Write(b []byte) (int, error) {
	*f.events = append(*f.events, "write "+filepath.Base(f.Name()))
	return f.File.Write(b)
}
