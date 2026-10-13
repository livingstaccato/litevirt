package health

import (
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/storage"
)

// The filesystem calls on set-aside disk copies, each under the storage bound.
//
// The hourly sweep and `lv host superseded-disks` glob and lstat every
// host-local disk directory, and a `dir` pool can be a hard NFS mount. A call
// there whose server does not answer blocks in the kernel for as long as the
// server is gone, and nothing in Go interrupts it: the sweep goroutine or the
// RPC sat there for the whole outage. The renames that set a disk aside (a
// failover start, a returning host's stranded-disk tend, a --restore) come
// right after a look that answered, but a server can die between the two.
//
// Each call now runs under storage.Bounded and returns an
// *storage.FSNoAnswerError when it does not answer in time
// (storage.IsFSNoAnswer). A no-answer is never "not there": nothing is
// removed or renamed on it, and the listing fails rather than leave out what
// it could not see. A call given up on may still finish in the kernel later;
// a rename that does land then leaves its copy under the set-aside name,
// which the listing finds by that name and the retention keeps while its VM
// exists.

// The calls themselves; tests stand in a storage that does not answer. Each
// is read outside the bounded call, which may outlive a test's restore.
var (
	supersededGlob   = filepath.Glob
	supersededLstat  = os.Lstat
	supersededRemove = os.Remove
	supersededRename = os.Rename
)

// globSetAside lists the names in dir that look like set-aside copies.
func globSetAside(dir string) ([]string, error) {
	glob := supersededGlob
	pattern := filepath.Join(dir, "*"+supersededInfix+"*")
	return storage.Bounded("list the set-aside copies in", dir, func() ([]string, error) { return glob(pattern) })
}

// lstatSetAside is os.Lstat of a set-aside copy or a disk path.
func lstatSetAside(p string) (os.FileInfo, error) {
	lstat := supersededLstat
	return storage.Bounded("lstat", p, func() (os.FileInfo, error) { return lstat(p) })
}

// removeSetAside is os.Remove of a set-aside copy.
func removeSetAside(p string) error {
	remove := supersededRemove
	_, err := storage.Bounded("remove", p, func() (struct{}, error) { return struct{}{}, remove(p) })
	return err
}

// renameSetAside is os.Rename of a disk to or from its set-aside name.
func renameSetAside(from, to string) error {
	rename := supersededRename
	_, err := storage.Bounded("rename to "+to, from, func() (struct{}, error) { return struct{}{}, rename(from, to) })
	return err
}

// linkSetAside is linkFile of a copy back to its disk's path.
func linkSetAside(from, to string) error {
	link := linkFile
	_, err := storage.Bounded("link to "+from, to, func() (struct{}, error) { return struct{}{}, link(from, to) })
	return err
}
