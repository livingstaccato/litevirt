package health

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// What the pauser does when it cannot write a pause record
// (enforcement.partition_pause_record_failure; docs/design/partition-pause.md
// §3.4). A full or failing data_dir must not, by default, turn a pause the
// host CAN perform into a self-fence that kills every VM on it.
//
// What the majority relies on is that the minority's workloads stop executing
// (§4), never the record: the record is a host-local file nothing reads across
// the network. It decides only what THIS host later resumes, so a record that
// cannot be written is a question of what the host may resume after a heal,
// not of whether the copy runs during the partition.
const (
	// PauseRecordFailurePause (the default): pause anyway. The record is kept
	// in the reserve when one exists, otherwise in this process's memory, and
	// is written to the record directory as soon as a write succeeds. A
	// daemon that dies while holding a record only in memory comes back to a
	// paused domain with no record, which it treats as paused by someone else
	// and never resumes: held, not free to run.
	PauseRecordFailurePause = "pause"
	// PauseRecordFailureReserve: the record must be durable before the pause,
	// in the record directory or in the reserve, a file allocated in advance
	// that only pause records use. With neither writable the pause fails and
	// the host self-fences, as in self_fence.
	PauseRecordFailureReserve = "reserve"
	// PauseRecordFailureSelfFence: the record directory only, and a write that
	// fails is a failed pause: partition_pause_failed, and a self-fence. The
	// behaviour before this setting existed.
	//
	// reserve and self_fence trade the pause for a self-fence, and that needs
	// a verified watchdog. Without one armed, a failed pause would leave the
	// copy running beside the majority's replacement (partition_pause_failed
	// cannot reach the majority across the partition), so both fall back to
	// pause: the record is held in memory and the workload is paused
	// (fallback=no_verified_watchdog in the log).
	PauseRecordFailureSelfFence = "self_fence"
)

// ValidPauseRecordFailure reports whether mode is a known
// enforcement.partition_pause_record_failure value ("" is the default).
func ValidPauseRecordFailure(mode string) bool {
	switch mode {
	case "", PauseRecordFailurePause, PauseRecordFailureReserve, PauseRecordFailureSelfFence:
		return true
	}
	return false
}

// Where a record landed, and the layers a test fault can fail.
const (
	PauseRecordLayerDisk    = "disk"
	PauseRecordLayerReserve = "reserve"
	PauseRecordLayerMemory  = "memory"
)

// pauseRecordWriteBound caps how long a pause waits for its record to reach
// the record directory or the reserve. A dying disk (I/O stuck in D state, an
// fsync that never returns) must not hold the pause past the majority's wait;
// the write goes on in the background and lands, or is undone, once it
// returns (pauseDirState.gen). pauseRecordWriteFloor is the least it gets when
// the pass has no read budget left: a write on a healthy disk takes
// milliseconds.
const (
	pauseRecordWriteBound = partitionPauseCallTimeout
	pauseRecordWriteFloor = 100 * time.Millisecond
)

// The reserve: <data_dir>/partition-pause/reserve, reserveSlots fixed slots of
// reserveSlotSize bytes, written in full with zeros when it is made, so that a
// record later overwrites blocks the file already owns and needs no new space.
// That holds on an overwrite-in-place filesystem (ext4, xfs), and on btrfs
// once FS_NOCOW_FL is set on the file (ensureReserve sets it, best effort,
// and a snapshot of the subvolume undoes it). zfs allocates on every write
// whatever the file says, so there the reserve is best effort.
//
// A slot is [len uint32][crc32 uint32][seq uint64][len bytes of JSON],
// zero-padded; the checksum covers seq and the JSON; a zero length is free. A
// live slot is never overwritten in place: a newer record of the same key
// goes to a free slot, which is synced before the older one is zeroed, so a
// torn write can only ever damage a slot that is not the one copy of a
// record. A slot that does not check is therefore skipped (and zeroed before
// it is reused), and of two slots holding one key the higher seq wins.
const (
	pauseReserveFile = "reserve"
	reserveSlots     = 1024
	reserveSlotSize  = 1024
	reserveSlotHdr   = 16
)

// errRecordSuperseded is a durable write abandoned because a newer record or
// a remove of the same key came after it began.
var errRecordSuperseded = errors.New("a newer record or a remove of this workload superseded the write")

// pauseDirState is what every store over one record directory in this
// process shares: the records held only in memory, the reserve's index and a
// test fault. Package-level, so the readers outside the pauser
// (ReadPauseRecord: the snapshot, NIC guard and settle paths) see a record
// the pauser holds in memory exactly as they see one on disk.
//
// mu guards the maps and is never held across a disk write or fsync, so a
// hung disk cannot stall a reader or the fallback to memory. A durable write
// of one key holds that key's lock (keyLock) instead, so writes of one key
// apply in order, and checks gen under mu before it starts and when it
// lands.
type pauseDirState struct {
	mu sync.Mutex
	// gen counts every record and every remove of a key. A durable write
	// carries the gen it was made for; one that lands after gen moved on
	// undoes itself, so a late write never brings back a record a resume
	// removed.
	gen      map[string]uint64
	keyLocks map[string]*sync.Mutex
	mem      map[string]PauseRecord
	// reserve: loaded is set once the file was read; slots maps a key to its
	// slot and recs to its record; free lists the unused slots, dirty the
	// ones holding a superseded, stale or corrupt copy, zeroed before reuse;
	// seq is the highest slot sequence number read or written.
	loaded bool
	slots  map[string]int
	recs   map[string]PauseRecord
	free   []int
	dirty  []int
	seq    uint64
	// fullWarned is set once the reserve ran out of free slots.
	fullWarned bool
	fault      func(layer string, rec PauseRecord) error
}

var pauseDirs = struct {
	mu sync.Mutex
	m  map[string]*pauseDirState
}{m: map[string]*pauseDirState{}}

func pauseStateFor(dir string) *pauseDirState {
	pauseDirs.mu.Lock()
	defer pauseDirs.mu.Unlock()
	st := pauseDirs.m[dir]
	if st == nil {
		st = &pauseDirState{gen: map[string]uint64{}, keyLocks: map[string]*sync.Mutex{}, mem: map[string]PauseRecord{}}
		pauseDirs.m[dir] = st
	}
	return st
}

// forgetPauseProcessStateForTests drops what this process holds for dataDir,
// as a daemon that dies loses it.
func forgetPauseProcessStateForTests(dataDir string) {
	pauseDirs.mu.Lock()
	delete(pauseDirs.m, filepath.Join(dataDir, partitionPauseDir))
	pauseDirs.mu.Unlock()
}

// injected runs the test fault for a write to layer, outside st.mu, so a
// fault that blocks stands for a hung disk and blocks only that write.
func (st *pauseDirState) injected(layer string, rec PauseRecord) error {
	if st == nil {
		return nil
	}
	st.mu.Lock()
	f := st.fault
	st.mu.Unlock()
	if f == nil {
		return nil
	}
	return f(layer, rec)
}

func (st *pauseDirState) keyLock(key string) *sync.Mutex {
	st.mu.Lock()
	defer st.mu.Unlock()
	l := st.keyLocks[key]
	if l == nil {
		l = &sync.Mutex{}
		st.keyLocks[key] = l
	}
	return l
}

func (st *pauseDirState) current(key string, g uint64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.gen[key] == g
}

func (s pauseStore) reservePath() string { return filepath.Join(s.dir, pauseReserveFile) }

// ensureReserve makes the reserve if it does not exist yet: a temp file
// marked no-copy-on-write while empty, written in full with zeros, fsync,
// rename, directory fsync. It needs the space it reserves, so it is made
// while the disk has room, at the pauser's first pass, and retried on every
// later one until it exists.
func (s pauseStore) ensureReserve() error {
	if s.dir == "" {
		return errors.New("no data directory")
	}
	if fi, err := os.Stat(s.reservePath()); err == nil {
		if fi.Size() != reserveSlots*reserveSlotSize {
			return fmt.Errorf("%s is %d bytes, want %d", s.reservePath(), fi.Size(), reserveSlots*reserveSlotSize)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, pauseReserveFile+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// btrfs: overwrite the zeros in place later. Only an empty file takes
	// the flag; elsewhere it is refused and nothing changes.
	_ = setNoCOW(tmp)
	if _, err := tmp.Write(make([]byte, reserveSlots*reserveSlotSize)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.reservePath()); err != nil {
		return err
	}
	return syncDir(s.dir)
}

// loadReserve reads the reserve into st once; the file is read outside
// st.mu. Absent is empty. A reserve that cannot be read, or is the wrong
// size, is an error on every call until it reads (an operator who removes a
// broken reserve clears it); a slot that does not check is skipped with a
// warning.
func (s pauseStore) loadReserve() error {
	st := s.st
	st.mu.Lock()
	loaded := st.loaded
	st.mu.Unlock()
	if loaded {
		return nil
	}
	b, err := os.ReadFile(s.reservePath())
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.loaded {
		return nil
	}
	if os.IsNotExist(err) {
		// Not cached as loaded: the reserve may be made later this process.
		st.slots, st.recs, st.free, st.dirty = map[string]int{}, map[string]PauseRecord{}, nil, nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the partition-pause reserve: %w", err)
	}
	if len(b) != reserveSlots*reserveSlotSize {
		return fmt.Errorf("corrupt partition-pause reserve %s: %d bytes, want %d", s.reservePath(), len(b), reserveSlots*reserveSlotSize)
	}
	slots, recs, seqs := map[string]int{}, map[string]PauseRecord{}, map[string]uint64{}
	var free, dirty []int
	var top uint64
	for i := 0; i < reserveSlots; i++ {
		slot := b[i*reserveSlotSize : (i+1)*reserveSlotSize]
		rec, seq, used, why := decodeSlot(slot)
		if !used {
			free = append(free, i)
			continue
		}
		if why != "" {
			// A torn first write (its pause never happened: the record
			// precedes it) or a torn clear (no longer the record's copy).
			slog.Warn("partition-pause: skipping a reserve slot that does not check; it is zeroed before reuse",
				"reserve", s.reservePath(), "slot", i, "why", why)
			dirty = append(dirty, i)
			continue
		}
		top = max(top, seq)
		if old, dup := slots[rec.Key()]; dup {
			// A crash between writing a newer copy and zeroing the older.
			if seqs[rec.Key()] > seq {
				dirty = append(dirty, i)
				continue
			}
			dirty = append(dirty, old)
		}
		slots[rec.Key()], recs[rec.Key()], seqs[rec.Key()] = i, rec, seq
	}
	st.slots, st.recs, st.free, st.dirty, st.loaded = slots, recs, free, dirty, true
	st.seq = max(st.seq, top)
	return nil
}

// decodeSlot reads one slot: used=false for a free one; why != "" for one
// that does not check.
func decodeSlot(slot []byte) (rec PauseRecord, seq uint64, used bool, why string) {
	n := binary.LittleEndian.Uint32(slot[0:4])
	if n == 0 {
		return PauseRecord{}, 0, false, ""
	}
	if n > reserveSlotSize-reserveSlotHdr {
		return PauseRecord{}, 0, true, fmt.Sprintf("claims %d bytes", n)
	}
	body := slot[8 : reserveSlotHdr+n]
	if crc32.ChecksumIEEE(body) != binary.LittleEndian.Uint32(slot[4:8]) {
		return PauseRecord{}, 0, true, "fails its checksum"
	}
	if err := json.Unmarshal(body[8:], &rec); err != nil || rec.Kind == "" || rec.Name == "" {
		return PauseRecord{}, 0, true, "does not parse"
	}
	return rec, binary.LittleEndian.Uint64(slot[8:16]), true, ""
}

// writeSlot writes one slot and fsyncs it, outside st.mu; the caller owns
// slot i (it is in no list and no key's slot). payload nil zeroes it. The
// file is opened without O_CREATE: the reserve is used only when it was made
// in advance.
func (s pauseStore) writeSlot(i int, payload []byte, seq uint64) error {
	buf := make([]byte, reserveSlotSize)
	if payload != nil {
		if len(payload) > reserveSlotSize-reserveSlotHdr {
			return fmt.Errorf("record is %d bytes, a reserve slot holds %d", len(payload), reserveSlotSize-reserveSlotHdr)
		}
		binary.LittleEndian.PutUint32(buf[0:4], uint32(len(payload)))
		binary.LittleEndian.PutUint64(buf[8:16], seq)
		copy(buf[reserveSlotHdr:], payload)
		binary.LittleEndian.PutUint32(buf[4:8], crc32.ChecksumIEEE(buf[8:reserveSlotHdr+len(payload)]))
	}
	f, err := os.OpenFile(s.reservePath(), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(buf, int64(i)*reserveSlotSize); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// releaseSlot zeroes slot i, which the caller detached, and frees it; a slot
// that cannot be zeroed is dirty until a later flush zeroes it.
func (s pauseStore) releaseSlot(i int) {
	err := s.writeSlot(i, nil, 0)
	st := s.st
	st.mu.Lock()
	defer st.mu.Unlock()
	if err != nil {
		slog.Warn("partition-pause: could not zero a reserve slot; retried on the next pass", "slot", i, "error", err)
		st.dirty = append(st.dirty, i)
		return
	}
	st.free = append(st.free, i)
	sort.Ints(st.free)
}

// zeroDirty zeroes every dirty slot and frees it.
func (s pauseStore) zeroDirty() {
	st := s.st
	st.mu.Lock()
	dirty := st.dirty
	st.dirty = nil
	st.mu.Unlock()
	for _, i := range dirty {
		s.releaseSlot(i)
	}
}

// putReserve writes rec for gen g into a free slot, never over its live one,
// then zeroes the slot that held its older copy.
func (s pauseStore) putReserve(rec PauseRecord, g uint64) error {
	if err := s.loadReserve(); err != nil {
		return err
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if len(payload) > reserveSlotSize-reserveSlotHdr {
		return fmt.Errorf("record is %d bytes, a reserve slot holds %d", len(payload), reserveSlotSize-reserveSlotHdr)
	}
	key := rec.Key()
	st := s.st
	st.mu.Lock()
	if !st.loaded {
		st.mu.Unlock()
		return fmt.Errorf("no reserve at %s", s.reservePath())
	}
	if st.gen[key] != g {
		st.mu.Unlock()
		return errRecordSuperseded
	}
	if len(st.free) == 0 {
		warn := !st.fullWarned
		st.fullWarned = true
		st.mu.Unlock()
		if warn {
			slog.Warn("partition-pause: every reserve slot is in use; a pause record that cannot reach the record directory is held in memory, or fails the pause, as enforcement.partition_pause_record_failure says",
				"reserve", s.reservePath(), "slots", reserveSlots)
		}
		return fmt.Errorf("the reserve's %d slots are all in use", reserveSlots)
	}
	i := st.free[0]
	st.free = st.free[1:]
	st.seq++
	seq := st.seq
	st.mu.Unlock()
	if err := s.writeSlot(i, payload, seq); err != nil {
		st.mu.Lock()
		st.dirty = append(st.dirty, i) // it may hold part of the record
		st.mu.Unlock()
		return err
	}
	st.mu.Lock()
	if st.gen[key] != g {
		st.mu.Unlock()
		s.releaseSlot(i)
		return errRecordSuperseded
	}
	old, had := st.slots[key]
	st.slots[key], st.recs[key] = i, rec
	delete(st.mem, key)
	st.mu.Unlock()
	if had {
		s.releaseSlot(old)
	}
	return nil
}

// detachSlotLocked takes key's slot out of the index, for the caller to
// release. Call with st.mu held.
func (st *pauseDirState) detachSlotLocked(key string) (int, bool) {
	i, ok := st.slots[key]
	if ok {
		delete(st.slots, key)
		delete(st.recs, key)
	}
	return i, ok
}

// persist makes rec, recorded at gen g, durable: the record directory, then,
// with reserve set, the reserve. It runs under the key's lock and may block
// as long as the disk does; record bounds the wait, not the write.
func (s pauseStore) persist(rec PauseRecord, g uint64, reserve bool) (string, error) {
	st := s.st
	key := rec.Key()
	kl := st.keyLock(key)
	kl.Lock()
	defer kl.Unlock()
	if !st.current(key, g) {
		return "", errRecordSuperseded
	}
	diskErr := s.put(rec)
	if diskErr == nil {
		if !s.landed(rec, g) {
			return "", errRecordSuperseded
		}
		return PauseRecordLayerDisk, nil
	}
	if !reserve {
		return "", diskErr
	}
	// An older file of this key would win over the reserve in list;
	// removing one frees space rather than taking it.
	fn, _ := pauseFileName(rec.Kind, rec.Name)
	if err := os.Remove(filepath.Join(s.dir, fn)); err != nil && !os.IsNotExist(err) {
		slog.Warn("partition-pause: could not remove an older record file", "key", key, "error", err)
	}
	rerr := st.injected(PauseRecordLayerReserve, rec)
	if rerr == nil {
		rerr = s.putReserve(rec, g)
	}
	if rerr == nil {
		return PauseRecordLayerReserve, nil
	}
	return "", fmt.Errorf("%v; and the reserve: %v", diskErr, rerr)
}

// landed is the check a durable write of rec at gen g makes once its file is
// in the record directory. Still current: the file is the record now, and an
// older copy in memory or the reserve is dropped. Superseded (a remove came,
// or a newer record whose own write is queued behind this one): the file is
// removed again, so it cannot bring back a record a resume removed. A reader
// may see the file between its rename and this check; the pauser drops a
// record that describes no paused workload (stillPausedByUs).
func (s pauseStore) landed(rec PauseRecord, g uint64) bool {
	st := s.st
	key := rec.Key()
	st.mu.Lock()
	if st.gen[key] != g {
		st.mu.Unlock()
		if err := s.removeDisk(rec.Kind, rec.Name); err != nil {
			slog.Warn("partition-pause: could not remove a record file a later remove superseded", "key", key, "error", err)
		}
		return false
	}
	delete(st.mem, key)
	i, had := st.detachSlotLocked(key)
	st.mu.Unlock()
	if had {
		s.releaseSlot(i)
	}
	return true
}

// record writes rec before its pause: the record directory first; then,
// unless mode is self_fence, the reserve. The wait is bounded; the write goes
// on in the background. When neither layer took the record in time, memOK
// decides: hold it in this process's memory (the default mode, or any mode
// without a verified watchdog to self-fence), or fail. It reports where the
// record landed. An error is a pause that must not happen.
func (s pauseStore) record(rec PauseRecord, mode string, memOK bool, bound time.Duration) (string, error) {
	if _, err := pauseFileName(rec.Kind, rec.Name); err != nil {
		return "", err
	}
	if s.st == nil {
		return PauseRecordLayerDisk, s.put(rec)
	}
	st := s.st
	key := rec.Key()
	st.mu.Lock()
	st.gen[key]++
	g := st.gen[key]
	st.mu.Unlock()
	type result struct {
		where string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		where, err := s.persist(rec, g, mode != PauseRecordFailureSelfFence)
		ch <- result{where, err}
	}()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	var err error
	select {
	case r := <-ch:
		if r.err == nil {
			return r.where, nil
		}
		err = r.err
	case <-timer.C:
		err = fmt.Errorf("the record write did not return within %v", bound)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !memOK {
		// No pause: a write still in flight must not land a record for it.
		st.gen[key]++
		return "", err
	}
	// The write still in flight, if any, keeps gen g: when it lands it
	// replaces this copy.
	st.mem[key] = rec
	return PauseRecordLayerMemory, nil
}

// flush writes every record held in memory or in the reserve to the record
// directory, and drops the slot or memory copy once it is there; it zeroes
// dirty reserve slots first. An unreadable reserve still lets the memory
// records through. Each write is a durable write of the record's current gen,
// so a remove that comes while it runs wins (landed).
func (s pauseStore) flush() {
	if s.st == nil {
		return
	}
	st := s.st
	if err := s.loadReserve(); err != nil {
		slog.Warn("partition-pause: cannot read the reserve; flushing only the records held in memory", "error", err)
	}
	s.zeroDirty()
	st.mu.Lock()
	todo := map[string]PauseRecord{}
	for k, r := range st.recs {
		todo[k] = r
	}
	for k, r := range st.mem {
		todo[k] = r // memory is newer than the reserve
	}
	gens := map[string]uint64{}
	keys := make([]string, 0, len(todo))
	for k := range todo {
		keys = append(keys, k)
		gens[k] = st.gen[k]
	}
	st.mu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		rec := todo[k]
		if _, err := s.persist(rec, gens[k], false); err != nil {
			if errors.Is(err, errRecordSuperseded) {
				continue
			}
			return // still full: retried next pass
		}
		slog.Info("partition-pause: a pause record is in the record directory now", "kind", rec.Kind, "name", rec.Name)
	}
}

// remove drops kind/name's record from every layer. Absent is success. It
// does not wait for a durable write of the key in flight: bumping gen makes
// that write undo itself when it lands (landed). Each layer is tried; the
// first error is returned, and a reserve slot that could not be zeroed is
// put back, so the workload stays held.
func (s pauseStore) remove(kind, name string) error {
	if s.st == nil {
		return s.removeDisk(kind, name)
	}
	key := kind + "/" + name
	st := s.st
	rerr := s.loadReserve()
	st.mu.Lock()
	st.gen[key]++
	g := st.gen[key]
	delete(st.mem, key)
	rec := st.recs[key]
	i, had := st.detachSlotLocked(key)
	st.mu.Unlock()
	err := s.removeDisk(kind, name)
	if had {
		if zerr := s.writeSlot(i, nil, 0); zerr != nil {
			st.mu.Lock()
			if _, newer := st.slots[key]; st.gen[key] == g && !newer {
				st.slots[key], st.recs[key] = i, rec
			} else {
				st.dirty = append(st.dirty, i)
			}
			st.mu.Unlock()
			if err == nil {
				err = zerr
			}
		} else {
			st.mu.Lock()
			st.free = append(st.free, i)
			sort.Ints(st.free)
			st.mu.Unlock()
		}
	}
	if err == nil {
		err = rerr
	}
	return err
}

// get reads kind/name's record: memory and the reserve, then the record
// directory. A record moves only from memory or the reserve to the
// directory, written there before it is dropped from where it was, so
// reading in this order never misses one in flight. An unreadable layer is
// an error, which every reader treats as held.
func (s pauseStore) get(kind, name string) (PauseRecord, bool, error) {
	if s.dir == "" {
		return PauseRecord{}, false, nil
	}
	key := kind + "/" + name
	var rerr error
	if s.st != nil {
		rerr = s.loadReserve()
		s.st.mu.Lock()
		rec, ok := s.st.mem[key]
		if !ok && rerr == nil {
			rec, ok = s.st.recs[key]
		}
		s.st.mu.Unlock()
		if ok {
			return rec, true, nil
		}
	}
	rec, ok, err := s.getDisk(kind, name)
	if err != nil || ok {
		return rec, ok, err
	}
	return PauseRecord{}, false, rerr
}

// list returns every record in every layer, sorted by key; for a key in more
// than one, memory wins over the record directory, and that over the reserve.
// Memory and the reserve are read first, for get's reason.
func (s pauseStore) list() ([]PauseRecord, error) {
	byKey := map[string]PauseRecord{}
	mem := map[string]PauseRecord{}
	if s.st != nil {
		if err := s.loadReserve(); err != nil {
			return nil, err
		}
		st := s.st
		st.mu.Lock()
		for k, r := range st.recs {
			byKey[k] = r
		}
		for k, r := range st.mem {
			mem[k] = r
		}
		st.mu.Unlock()
	}
	disk, err := s.listDisk()
	if err != nil {
		return nil, err
	}
	for _, r := range disk {
		byKey[r.Key()] = r
	}
	for k, r := range mem {
		byKey[k] = r
	}
	out := make([]PauseRecord, 0, len(byKey))
	for _, r := range byKey {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}
