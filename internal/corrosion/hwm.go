package corrosion

import (
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// hwmStore durably persists this node's monotonic clock high-waters — the LWW-key
// wall ceiling (behind NowTS) and the HLC physical-ms ceiling — to a single
// versioned file <dataDir>/nowts.hwm. It exists to close the backward-clock
// lost-update: without it, NowTS's in-memory monotonic high-water resets to zero on
// restart, so a daemon that restarts after a wall-clock step-back emits OLDER
// updated_at keys and its fresh writes silently lose LWW cluster-wide.
//
// A routine save needs no new disk space. The file has a fixed size and two slots,
// each carrying both ceilings and a checksum, and a save overwrites them in place:
// slot A, fsync, slot B's values blanked, fsync, then slot B, fsync (overwrite). A full
// ext4 or xfs filesystem therefore cannot fail it (btrfs only with the no-copy-on-write
// flag replace sets; ZFS always allocates), which
// matters because NowTS exits the daemon once a save keeps failing (client.go,
// onPersistFatal), and a save falls due every couple of seconds. Only creating the
// file, or converting one written by an earlier build, writes a temp file and renames
// it (fsync temp, rename, fsync dir); start does that once (prepare).
//
// The reader takes the larger of each ceiling across the slots whose checksum holds.
// A crash mid-save tears at most the slot being written: if A, slot B still holds
// the previous ceiling, and nothing past it was emitted before the save returned; if
// B, slot A already holds the new one. Both slots failing is corrupt.
//
// The layout is also the earlier builds' format (see parseHWM), which reads the last
// value of each key and ignores keys it does not know. Slot B is written last and,
// once a save returns, holds the latest ceilings, so a node rolled back to such a
// build reads them; the checksum lines are unknown keys to it. That reader does not
// check the checksum, so slot B is blanked before it is rewritten: a torn B then
// fails to parse instead of reading as an earlier time.
//
// Writes are increase-only (max-merged under the lock), a separate stable .lock file
// serializes writers, and a corrupt file is reported as an error (the caller fails
// closed + loud rather than silently resetting to wall clock, which would re-open the
// bug); a genuinely-absent file is "fresh node", not corrupt.
type hwmStore struct {
	dir  string
	path string
	lock string

	// storeHook, when non-nil, replaces the real durable write. Test seam for
	// injected persistence failures; production leaves it nil.
	storeHook func(lww time.Time, hlcMS int64) error
	// fs is the filesystem the store reads and writes through. nil is the real
	// one; a test substitutes one that refuses writes needing new space.
	fs hwmFS
}

// hwmFS is the part of the filesystem hwmStore uses.
type hwmFS interface {
	OpenFile(name string, flag int, perm os.FileMode) (hwmFile, error)
	ReadFile(name string) ([]byte, error)
	Rename(oldpath, newpath string) error
}

// hwmFile is the part of *os.File hwmStore uses.
type hwmFile interface {
	Write(b []byte) (int, error)
	WriteAt(b []byte, off int64) (int, error)
	Sync() error
	Close() error
	Fd() uintptr
	Name() string
}

type osHWMFS struct{}

func (osHWMFS) OpenFile(name string, flag int, perm os.FileMode) (hwmFile, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}
func (osHWMFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }
func (osHWMFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (s *hwmStore) fsys() hwmFS {
	if s.fs == nil {
		return osHWMFS{}
	}
	return s.fs
}

func newHWMStore(dir string) *hwmStore {
	return &hwmStore{
		dir:  dir,
		path: filepath.Join(dir, "nowts.hwm"),
		lock: filepath.Join(dir, "nowts.hwm.lock"),
	}
}

// load reads the persisted ceilings. found=false,err=nil ⇒ no file yet (fresh node).
// err!=nil ⇒ the file exists but is unreadable/corrupt — the caller MUST fail closed
// (refuse to start / refuse to advance), never silently fall back to wall clock.
func (s *hwmStore) load() (lww time.Time, hlcMS int64, found bool, err error) {
	b, e := s.fsys().ReadFile(s.path)
	if os.IsNotExist(e) {
		return time.Time{}, 0, false, nil
	}
	if e != nil {
		return time.Time{}, 0, false, fmt.Errorf("read %s: %w", s.path, e)
	}
	lww, hlcMS, e = parseHWMFile(b)
	if e != nil {
		return time.Time{}, 0, false, fmt.Errorf("corrupt %s: %w", s.path, e)
	}
	return lww, hlcMS, true, nil
}

// parseHWM decodes the strict versioned format every earlier build wrote, and the
// body of one slot of the two-slot layout:
//
//	v1
//	lww=<RFC3339Nano>
//	hlc_ms=<int64>
//
// Any deviation is an error (corrupt) so a torn/garbled file is never read as a
// valid-but-lower ceiling.
func parseHWM(s string) (lww time.Time, hlcMS int64, err error) {
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

// store persists both ceilings, INCREASE-ONLY. flock alone only serializes writers,
// it doesn't stop two processes (the daemon + a NewLocalClient tool sharing one
// dataDir) from each writing their own lower in-memory value — so under the lock we
// RE-READ the current file and max-merge, guaranteeing the on-disk ceilings never
// regress regardless of who writes. A file already in the two-slot layout is
// overwritten in place; anything else is replaced. Any step failing returns an error
// and the caller must NOT treat the new ceiling as durable.
func (s *hwmStore) store(lww time.Time, hlcMS int64) error {
	if s.storeHook != nil {
		return s.storeHook(lww, hlcMS)
	}
	fsys := s.fsys()
	lf, err := fsys.OpenFile(s.lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock: %w", err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)

	// Increase-only max-merge against the current on-disk value (a concurrent writer
	// may have advanced it past our in-memory view). A parseable current file wins
	// where it's higher; an unreadable/absent one is replaced by our valid value.
	cur, readErr := fsys.ReadFile(s.path)
	if readErr == nil {
		if curLWW, curHLC, pe := parseHWMFile(cur); pe == nil {
			if curLWW.After(lww) {
				lww = curLWW
			}
			if curHLC > hlcMS {
				hlcMS = curHLC
			}
		}
	}
	slot, err := encodeHWMSlot(lww, hlcMS)
	if err != nil {
		return err
	}
	if readErr == nil && hwmSlotted(cur) {
		return s.overwrite(fsys, slot)
	}
	return s.replace(fsys, slot)
}

// prepare puts the file in the two-slot layout, keeping the ceilings it holds, so
// later saves overwrite it in place. Called at start, when the disk is least likely
// to be full; a failure leaves the file as it was and store retries the conversion.
// A file already in the layout with both slots intact is left alone, so opening a
// client to read writes nothing.
func (s *hwmStore) prepare() error {
	if b, err := s.fsys().ReadFile(s.path); err == nil && hwmSlotted(b) {
		_, _, errA := decodeHWMSlot(b[hwmSlotOffset(0) : hwmSlotOffset(0)+hwmSlotSize])
		_, _, errB := decodeHWMSlot(b[hwmSlotOffset(1) : hwmSlotOffset(1)+hwmSlotSize])
		if errA == nil && errB == nil {
			return nil
		}
	}
	return s.store(time.Time{}, 0)
}

// hwmSlotted reports whether b has the two-slot layout's size and header, which is
// what an in-place save needs: it rewrites the slots and leaves the header alone.
func hwmSlotted(b []byte) bool {
	return len(b) == hwmFileSize && string(b[:len(hwmHeader)]) == hwmHeader
}

// overwrite rewrites both slots of an existing two-slot file in place: A, fsync;
// B's values blanked, fsync; B, fsync. Nothing is allocated, so a full filesystem
// does not fail it.
//
// The blanking is for a node rolled back to an earlier build, whose reader takes
// slot B without a checksum. A write torn between B's old and new digits can read
// as a valid earlier time (17:59:59.9 → 18:00:02.1 tearing to 17:00:02.1); torn
// between blanks and new digits it cannot parse at all, which fails closed.
func (s *hwmStore) overwrite(fsys hwmFS, slot []byte) error {
	f, err := fsys.OpenFile(s.path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	for _, w := range []struct {
		what string
		b    []byte
		slot int
	}{{"slot A", slot, 0}, {"blank slot B", hwmBlankSlot(slot), 1}, {"slot B", slot, 1}} {
		if _, err := f.WriteAt(w.b, int64(hwmSlotOffset(w.slot))); err != nil {
			return fmt.Errorf("write %s: %w", w.what, err)
		}
		if err := f.Sync(); err != nil {
			return fmt.Errorf("fsync %s: %w", w.what, err)
		}
	}
	return nil
}

// hwmBlankSlot is slot with every value byte replaced by 'x': the keys and line
// breaks stay, so the file keeps its shape, but no reader parses a value from it.
func hwmBlankSlot(slot []byte) []byte {
	out := append([]byte(nil), slot...)
	inValue := false
	for i, c := range out {
		switch {
		case c == '\n':
			inValue = false
		case inValue:
			out[i] = 'x'
		case c == '=':
			inValue = true
		}
	}
	return out
}

// replace writes a whole two-slot file beside the old one and renames it over:
// flock → write temp → fsync(temp) → rename → fsync(dir). It needs new space.
func (s *hwmStore) replace(fsys hwmFS, slot []byte) error {
	content := make([]byte, 0, hwmFileSize)
	content = append(content, hwmHeader...)
	content = append(content, slot...)
	content = append(content, slot...)
	tmp := s.path + ".tmp"
	f, err := fsys.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp: %w", err)
	}
	// Before the first byte: btrfs applies no-copy-on-write only to an empty file.
	hwmSetNoCOW(f)
	if _, err := f.Write(content); err != nil {
		f.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := fsys.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	// fsync the directory so the rename itself is durable across power loss.
	d, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}

// The two-slot layout, fixed width so a save never changes the file's size:
//
//	v1
//	lww=<RFC3339, nowTSLayout, 30 bytes>      ┐
//	hlc_ms=<19 digits, zero-padded>           │ slot A
//	crc=<crc32 of the two lines above, %08x>  ┘
//	lww=…                                     ┐
//	hlc_ms=…                                  │ slot B
//	crc=…                                     ┘
const (
	hwmHeader     = "v1\n"
	hwmLWWWidth   = len(nowTSLayout) - len("Z07:00") + len("Z")
	hwmSlotBody   = len("lww=") + hwmLWWWidth + 1 + len("hlc_ms=") + 19 + 1
	hwmSlotSize   = hwmSlotBody + len("crc=") + 8 + 1
	hwmFileSize   = len(hwmHeader) + 2*hwmSlotSize
	hwmSlotLWWPfx = "lww="
	hwmSlotHLCPfx = "hlc_ms="
	hwmSlotCRCPfx = "crc="
)

func hwmSlotOffset(i int) int { return len(hwmHeader) + i*hwmSlotSize }

func encodeHWMSlot(lww time.Time, hlcMS int64) ([]byte, error) {
	ts := lww.UTC().Format(nowTSLayout)
	if len(ts) != hwmLWWWidth || hlcMS < 0 {
		return nil, fmt.Errorf("ceiling (%s, %d) does not fit the nowts.hwm layout", ts, hlcMS)
	}
	body := fmt.Sprintf("%s%s\n%s%019d\n", hwmSlotLWWPfx, ts, hwmSlotHLCPfx, hlcMS)
	slot := fmt.Sprintf("%s%s%08x\n", body, hwmSlotCRCPfx, crc32.ChecksumIEEE([]byte(body)))
	if len(slot) != hwmSlotSize {
		return nil, fmt.Errorf("nowts.hwm slot is %d bytes, want %d", len(slot), hwmSlotSize)
	}
	return []byte(slot), nil
}

// decodeHWMSlot parses one slot, rejecting it unless its checksum holds.
func decodeHWMSlot(b []byte) (time.Time, int64, error) {
	body, sum := b[:hwmSlotBody], string(b[hwmSlotBody:])
	if want := fmt.Sprintf("%s%08x\n", hwmSlotCRCPfx, crc32.ChecksumIEEE(body)); sum != want {
		return time.Time{}, 0, fmt.Errorf("checksum mismatch")
	}
	return parseHWM(hwmHeader + string(body))
}

// parseHWMFile reads either layout: the two-slot one this build writes, or the
// single-record one earlier builds wrote (still present after an upgrade, or after a
// rolled-back build rewrote it).
func parseHWMFile(b []byte) (lww time.Time, hlcMS int64, err error) {
	if len(b) != hwmFileSize || string(b[:len(hwmHeader)]) != hwmHeader {
		return parseHWM(string(b))
	}
	var valid int
	var errs []string
	for i := 0; i < 2; i++ {
		off := hwmSlotOffset(i)
		l, h, e := decodeHWMSlot(b[off : off+hwmSlotSize])
		if e != nil {
			errs = append(errs, fmt.Sprintf("slot %d: %v", i, e))
			continue
		}
		valid++
		if l.After(lww) {
			lww = l
		}
		if h > hlcMS {
			hlcMS = h
		}
	}
	if valid == 0 {
		return time.Time{}, 0, fmt.Errorf("no valid slot (%s)", strings.Join(errs, "; "))
	}
	return lww, hlcMS, nil
}

// hwmSetNoCOW marks a newly created hwm file no-copy-on-write. A variable so a
// test can see when it runs.
var hwmSetNoCOW = setNoCOW
