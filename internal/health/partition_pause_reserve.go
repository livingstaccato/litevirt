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
	// that only pause records use. With neither writable the pause fails, as
	// in self_fence.
	PauseRecordFailureReserve = "reserve"
	// PauseRecordFailureSelfFence: the record directory only, and a write that
	// fails is a failed pause: partition_pause_failed, and a self-fence when a
	// verified watchdog is armed. The behaviour before this setting existed.
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

// The reserve: <data_dir>/partition-pause/reserve, reserveSlots fixed slots of
// reserveSlotSize bytes, written in full with zeros when it is made, so that a
// record later overwrites blocks the file already owns and needs no new space.
// That holds on an overwrite-in-place filesystem (ext4, xfs); a copy-on-write
// one (btrfs, zfs) allocates on every write and gains little from it.
//
// A slot is [len uint32][crc32 uint32][len bytes of JSON], zero-padded; a
// zero length is free. A slot that does not check is an error, never a skip:
// a skipped record is a paused workload nothing will ever resume.
const (
	pauseReserveFile = "reserve"
	reserveSlots     = 1024
	reserveSlotSize  = 1024
	reserveSlotHdr   = 8
)

// pauseDirState is what every store over one record directory in this
// process shares: the records held only in memory, the reserve's index and a
// test fault. Package-level, so the readers outside the pauser
// (ReadPauseRecord: the snapshot, NIC guard and settle paths) see a record
// the pauser holds in memory exactly as they see one on disk.
type pauseDirState struct {
	mu  sync.Mutex
	mem map[string]PauseRecord
	// reserve: loaded is set once the file was read; slots maps a key to its
	// slot and recs to its record; free lists the unused slots.
	loaded bool
	slots  map[string]int
	recs   map[string]PauseRecord
	free   []int
	fault  func(layer string, rec PauseRecord) error
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
		st = &pauseDirState{mem: map[string]PauseRecord{}}
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

func (s pauseStore) reservePath() string { return filepath.Join(s.dir, pauseReserveFile) }

// ensureReserve makes the reserve if it does not exist yet: a temp file
// written in full with zeros, fsync, rename, directory fsync. It needs the
// space it reserves, so it is made while the disk has room, at the pauser's
// first pass, and retried on every later one until it exists.
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

// loadReserveLocked reads the reserve into st once. Absent is empty. Call
// with st.mu held. An unreadable or corrupt reserve is an error on every call
// until it reads (an operator who removes a corrupt reserve clears it).
func (s pauseStore) loadReserveLocked() error {
	st := s.st
	if st.loaded {
		return nil
	}
	b, err := os.ReadFile(s.reservePath())
	if os.IsNotExist(err) {
		// Not cached as loaded: the reserve may be made later this process.
		st.slots, st.recs, st.free = map[string]int{}, map[string]PauseRecord{}, nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the partition-pause reserve: %w", err)
	}
	if len(b) != reserveSlots*reserveSlotSize {
		return fmt.Errorf("corrupt partition-pause reserve %s: %d bytes, want %d", s.reservePath(), len(b), reserveSlots*reserveSlotSize)
	}
	slots, recs := map[string]int{}, map[string]PauseRecord{}
	var free []int
	for i := 0; i < reserveSlots; i++ {
		slot := b[i*reserveSlotSize : (i+1)*reserveSlotSize]
		n := binary.LittleEndian.Uint32(slot[0:4])
		if n == 0 {
			free = append(free, i)
			continue
		}
		if n > reserveSlotSize-reserveSlotHdr {
			return fmt.Errorf("corrupt partition-pause reserve %s: slot %d claims %d bytes", s.reservePath(), i, n)
		}
		payload := slot[reserveSlotHdr : reserveSlotHdr+n]
		if crc32.ChecksumIEEE(payload) != binary.LittleEndian.Uint32(slot[4:8]) {
			return fmt.Errorf("corrupt partition-pause reserve %s: slot %d fails its checksum", s.reservePath(), i)
		}
		var rec PauseRecord
		if err := json.Unmarshal(payload, &rec); err != nil || rec.Kind == "" || rec.Name == "" {
			return fmt.Errorf("corrupt partition-pause reserve %s: slot %d does not parse", s.reservePath(), i)
		}
		if old, dup := slots[rec.Key()]; dup {
			return fmt.Errorf("corrupt partition-pause reserve %s: slots %d and %d both hold %s", s.reservePath(), old, i, rec.Key())
		}
		slots[rec.Key()], recs[rec.Key()] = i, rec
	}
	st.slots, st.recs, st.free, st.loaded = slots, recs, free, true
	return nil
}

// writeSlotLocked overwrites one slot in place and fsyncs it. payload nil
// frees the slot. The file is opened without O_CREATE: the reserve is used
// only when it was made in advance.
func (s pauseStore) writeSlotLocked(i int, payload []byte) error {
	buf := make([]byte, reserveSlotSize)
	if payload != nil {
		if len(payload) > reserveSlotSize-reserveSlotHdr {
			return fmt.Errorf("record is %d bytes, a reserve slot holds %d", len(payload), reserveSlotSize-reserveSlotHdr)
		}
		binary.LittleEndian.PutUint32(buf[0:4], uint32(len(payload)))
		binary.LittleEndian.PutUint32(buf[4:8], crc32.ChecksumIEEE(payload))
		copy(buf[reserveSlotHdr:], payload)
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

// putReserveLocked writes rec into its slot, or a free one.
func (s pauseStore) putReserveLocked(rec PauseRecord) error {
	if err := s.loadReserveLocked(); err != nil {
		return err
	}
	if _, err := os.Stat(s.reservePath()); err != nil {
		return fmt.Errorf("no reserve: %w", err)
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	st := s.st
	i, ok := st.slots[rec.Key()]
	if !ok {
		if len(st.free) == 0 {
			return fmt.Errorf("the reserve's %d slots are all in use", reserveSlots)
		}
		i = st.free[0]
	}
	if err := s.writeSlotLocked(i, payload); err != nil {
		return err
	}
	if !ok {
		st.free = st.free[1:]
	}
	st.slots[rec.Key()], st.recs[rec.Key()] = i, rec
	return nil
}

// clearReserveLocked frees key's slot, if it has one.
func (s pauseStore) clearReserveLocked(key string) error {
	if err := s.loadReserveLocked(); err != nil {
		return err
	}
	st := s.st
	i, ok := st.slots[key]
	if !ok {
		return nil
	}
	if err := s.writeSlotLocked(i, nil); err != nil {
		return err
	}
	delete(st.slots, key)
	delete(st.recs, key)
	st.free = append(st.free, i)
	sort.Ints(st.free)
	return nil
}

// record writes rec before its pause, as mode allows: the record directory
// first; then, unless mode is self_fence, the reserve; then, in the default
// mode only, this process's memory. It reports where the record landed. An
// error is a pause that must not happen.
func (s pauseStore) record(rec PauseRecord, mode string) (string, error) {
	if _, err := pauseFileName(rec.Kind, rec.Name); err != nil {
		return "", err
	}
	diskErr := s.put(rec)
	if s.st == nil {
		return PauseRecordLayerDisk, diskErr
	}
	st := s.st
	st.mu.Lock()
	defer st.mu.Unlock()
	if diskErr == nil {
		// The newest record is the file now: an older copy held elsewhere
		// must not outlive it.
		delete(st.mem, rec.Key())
		if err := s.clearReserveLocked(rec.Key()); err != nil {
			slog.Warn("partition-pause: could not clear a reserve slot the record directory now holds", "key", rec.Key(), "error", err)
		}
		return PauseRecordLayerDisk, nil
	}
	if mode == PauseRecordFailureSelfFence {
		return "", diskErr
	}
	// An older file of this key would win over the reserve and memory in
	// list; removing one frees space rather than taking it.
	fn, _ := pauseFileName(rec.Kind, rec.Name)
	if err := os.Remove(filepath.Join(s.dir, fn)); err != nil && !os.IsNotExist(err) {
		slog.Warn("partition-pause: could not remove an older record file", "key", rec.Key(), "error", err)
	}
	rerr := st.injected2(PauseRecordLayerReserve, rec)
	if rerr == nil {
		rerr = s.putReserveLocked(rec)
	}
	if rerr == nil {
		delete(st.mem, rec.Key())
		return PauseRecordLayerReserve, nil
	}
	if mode == PauseRecordFailureReserve {
		return "", fmt.Errorf("%v; and the reserve: %v", diskErr, rerr)
	}
	st.mem[rec.Key()] = rec
	return PauseRecordLayerMemory, nil
}

// injected2 is injected for a caller that already holds st.mu.
func (st *pauseDirState) injected2(layer string, rec PauseRecord) error {
	if st.fault == nil {
		return nil
	}
	return st.fault(layer, rec)
}

// flush writes every record held in memory or in the reserve to the record
// directory, and releases the slot or memory once it is there. It holds
// st.mu throughout, so a remove of the same record cannot interleave and be
// undone by a late write.
func (s pauseStore) flush() {
	if s.st == nil {
		return
	}
	st := s.st
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := s.loadReserveLocked(); err != nil {
		return
	}
	if len(st.mem) == 0 && len(st.recs) == 0 {
		return
	}
	todo := map[string]PauseRecord{}
	for k, r := range st.recs {
		todo[k] = r
	}
	for k, r := range st.mem {
		todo[k] = r // memory is newer than the reserve
	}
	keys := make([]string, 0, len(todo))
	for k := range todo {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rec := todo[k]
		if err := st.injected2(PauseRecordLayerDisk, rec); err != nil {
			return
		}
		if err := s.putDiskLocked(rec); err != nil {
			return // still full: retried next pass
		}
		delete(st.mem, k)
		if err := s.clearReserveLocked(k); err != nil {
			slog.Warn("partition-pause: could not clear a reserve slot the record directory now holds", "key", k, "error", err)
		}
		slog.Info("partition-pause: a pause record is in the record directory now", "kind", rec.Kind, "name", rec.Name)
	}
}

// putDiskLocked is put without the fault hook (flush checks it itself, under
// the lock it already holds).
func (s pauseStore) putDiskLocked(rec PauseRecord) error {
	st := s.st
	s.st = nil
	err := s.put(rec)
	s.st = st
	return err
}

// remove drops kind/name's record from every layer. Absent is success. Each
// layer is tried; the first error is returned, and a layer that kept its copy
// keeps the workload held.
func (s pauseStore) remove(kind, name string) error {
	err := s.removeDisk(kind, name)
	if s.st == nil {
		return err
	}
	key := kind + "/" + name
	st := s.st
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.mem, key)
	if rerr := s.clearReserveLocked(key); rerr != nil && err == nil {
		err = rerr
	}
	return err
}

// get reads kind/name's record: memory, then the record directory, then the
// reserve. An unreadable layer is an error, which every reader treats as
// held.
func (s pauseStore) get(kind, name string) (PauseRecord, bool, error) {
	if s.dir == "" {
		return PauseRecord{}, false, nil
	}
	key := kind + "/" + name
	if s.st != nil {
		s.st.mu.Lock()
		rec, ok := s.st.mem[key]
		s.st.mu.Unlock()
		if ok {
			return rec, true, nil
		}
	}
	rec, ok, err := s.getDisk(kind, name)
	if err != nil || ok || s.st == nil {
		return rec, ok, err
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if err := s.loadReserveLocked(); err != nil {
		return PauseRecord{}, false, err
	}
	rec, ok = s.st.recs[key]
	return rec, ok, nil
}

// list returns every record in every layer, sorted by key; for a key in more
// than one, memory wins over the record directory, and that over the reserve.
func (s pauseStore) list() ([]PauseRecord, error) {
	disk, err := s.listDisk()
	if err != nil || s.st == nil {
		return disk, err
	}
	st := s.st
	st.mu.Lock()
	if err := s.loadReserveLocked(); err != nil {
		st.mu.Unlock()
		return nil, err
	}
	byKey := map[string]PauseRecord{}
	for k, r := range st.recs {
		byKey[k] = r
	}
	for _, r := range disk {
		byKey[r.Key()] = r
	}
	for k, r := range st.mem {
		byKey[k] = r
	}
	st.mu.Unlock()
	out := make([]PauseRecord, 0, len(byKey))
	for _, r := range byKey {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}
