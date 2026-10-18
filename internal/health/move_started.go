package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/secretfile"
)

// A start of a VM's domain on this host leaves a host-local record of the
// ownership generation it ran at. A pivoted move's condition that reaches
// this host after such a start (replication from the holder was cut) finds
// the disk row still on the source, which the guest may have written here:
// the heal then does not point the row at the copy by itself, even once the
// domain is gone (resolveRemoteMove).

// StartedHereDirName is the data-dir child the records live in.
const StartedHereDirName = "move-started"

type startedHere struct {
	VM         string `json:"vm"`
	OwnerEpoch int64  `json:"owner_epoch"`
	At         string `json:"at"`
}

func startedHereFile(dataDir, vm string) string {
	sum := sha256.Sum256([]byte(vm))
	return filepath.Join(dataDir, StartedHereDirName, hex.EncodeToString(sum[:]))
}

// NoteStartingHere records that vm's domain is about to start on this host at
// its current ownership generation; a later generation than one recorded
// replaces it. Called after a start's move heal and before the domain starts,
// so a start that then fails leaves the record too: it may only hold a later
// heal back, never let one through.
func NoteStartingHere(ctx context.Context, db *corrosion.Client, dataDir, vm string) error {
	if db == nil || dataDir == "" {
		return nil
	}
	rec, err := corrosion.GetVM(ctx, db, vm)
	if err != nil || rec == nil {
		return err
	}
	if prev, ok, err := startedHereAt(dataDir, vm); err == nil && ok && prev >= rec.OwnerEpoch {
		return nil
	}
	b, err := json.Marshal(startedHere{VM: vm, OwnerEpoch: rec.OwnerEpoch, At: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	dir := filepath.Join(dataDir, StartedHereDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := secretfile.Write(startedHereFile(dataDir, vm), b, 0o600); err != nil {
		return err
	}
	return syncDir(dir)
}

// noteStartingHere is NoteStartingHere for a start that goes on when the
// record cannot be written: the heal's other evidence still holds.
func noteStartingHere(ctx context.Context, db *corrosion.Client, dataDir, vm string) {
	if err := NoteStartingHere(ctx, db, dataDir, vm); err != nil {
		slog.Warn("recording this host's start of the VM failed", "vm", vm, "error", err)
	}
}

// startedHereAt reads the latest generation vm was started at on this host
// (ok false when there is no record).
func startedHereAt(dataDir, vm string) (epoch int64, ok bool, err error) {
	b, err := os.ReadFile(startedHereFile(dataDir, vm))
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var r startedHere
	if err := json.Unmarshal(b, &r); err != nil || r.VM != vm {
		return 0, false, fmt.Errorf("unreadable record of this host's starts of %s: %v", vm, err)
	}
	return r.OwnerEpoch, true, nil
}

// forgetStartedHere drops vm's record: the name now belongs to another VM, or
// to none.
func forgetStartedHere(dataDir, vm string) {
	if err := os.Remove(startedHereFile(dataDir, vm)); err == nil {
		_ = syncDir(filepath.Join(dataDir, StartedHereDirName))
	}
}

// MoveFileFacts describes path's size and modification time as read here,
// for an operator judging which of a move's files holds the writes to keep.
func MoveFileFacts(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Sprintf("%s cannot be read here (%v)", path, err)
	}
	return fmt.Sprintf("%s is %d bytes, modified %s", path, fi.Size(), fi.ModTime().UTC().Format(time.RFC3339Nano))
}

// ModifiedLater reports whether a was provably modified after b: both read
// here, and a's modification time strictly later.
func ModifiedLater(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && fa.ModTime().After(fb.ModTime())
}
