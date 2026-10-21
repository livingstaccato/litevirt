package corrosion

import (
	"os"
	"sync"
	"syscall"
	"time"
)

// fullDiskHWMFS is an hwmFS on a filesystem with no free blocks: it refuses,
// with ENOSPC, every operation that needs new space, and lets through every
// one that does not. Creating a file, and writing past a file's current end
// (which includes every write after O_TRUNC), need new space; overwriting
// bytes a file already has, renaming and fsync do not. Test seam.
type fullDiskHWMFS struct{}

func (fullDiskHWMFS) OpenFile(name string, flag int, perm os.FileMode) (hwmFile, error) {
	fi, statErr := os.Stat(name)
	if flag&os.O_CREATE != 0 && os.IsNotExist(statErr) {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOSPC}
	}
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	var size int64
	if statErr == nil && flag&os.O_TRUNC == 0 {
		size = fi.Size()
	}
	return &fullDiskHWMFile{File: f, size: size}, nil
}

func (fullDiskHWMFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }
func (fullDiskHWMFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

// fullDiskHWMFile refuses a write that reaches past the bytes the file had
// when it was opened.
type fullDiskHWMFile struct {
	*os.File
	size int64
	pos  int64
}

func (f *fullDiskHWMFile) Write(b []byte) (int, error) {
	if f.pos+int64(len(b)) > f.size {
		return 0, &os.PathError{Op: "write", Path: f.Name(), Err: syscall.ENOSPC}
	}
	n, err := f.File.Write(b)
	f.pos += int64(n)
	return n, err
}

func (f *fullDiskHWMFile) WriteAt(b []byte, off int64) (int, error) {
	if off+int64(len(b)) > f.size {
		return 0, &os.PathError{Op: "write", Path: f.Name(), Err: syscall.ENOSPC}
	}
	return f.File.WriteAt(b, off)
}

// ClockPersistenceForTests gives a test client, which has none, the durable
// clock high-water a daemon keeps in its data directory: dir holds nowts.hwm,
// and onFatal stands in for the daemon's exit when the clock can neither
// persist nor advance. It returns fillDisk, which from then on makes every
// write the store attempts behave as on a full filesystem. Test-only.
func (c *Client) ClockPersistenceForTests(t TestingT, dir string, onFatal func(error)) (fillDisk func()) {
	t.Helper()
	c.onPersistFatal = onFatal
	c.dataDir = dir
	if err := c.initClockPersistence(); err != nil {
		t.Fatalf("clock persistence: %v", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			c.tsMu.Lock()
			defer c.tsMu.Unlock()
			c.hwm.fs = fullDiskHWMFS{}
		})
	}
}

// ClockDurableCeilingForTests is the LWW ceiling this client last persisted.
// Test-only.
func (c *Client) ClockDurableCeilingForTests() time.Time {
	c.tsMu.Lock()
	defer c.tsMu.Unlock()
	return c.durableTS
}
