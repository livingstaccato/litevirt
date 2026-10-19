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
	"strings"
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

// StartingEventType is the vm_events type of each start NoteStartingHere
// records: replicated, so `lv events <vm>` on any host lists the starts of a
// VM, an HA failover's included.
const StartingEventType = "vm.starting"

// NoteStartingHere records that vm's domain is about to start on this host at
// its current ownership generation; a later generation than one recorded
// replaces it. Called after a start's move heal and before the domain starts,
// so a start that then fails leaves the record too: it may only hold a later
// heal back, never let one through. Each call also appends a replicated
// StartingEventType event naming this host and the generation.
func NoteStartingHere(ctx context.Context, db *corrosion.Client, dataDir, vm string) error {
	if db == nil || dataDir == "" {
		return nil
	}
	rec, err := corrosion.GetVM(ctx, db, vm)
	if err != nil || rec == nil {
		return err
	}
	evErr := NoteStartEvent(ctx, db, rec.HostName, vm)
	if prev, ok, err := startedHereAt(dataDir, vm); err == nil && ok && prev >= rec.OwnerEpoch {
		return evErr
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
	if err := syncDir(dir); err != nil {
		return err
	}
	return evErr
}

// NoteStartEvent appends the replicated StartingEventType event of a start of
// vm on host, naming the VM's ownership generation when it has a row.
func NoteStartEvent(ctx context.Context, db *corrosion.Client, host, vm string) error {
	if db == nil {
		return nil
	}
	detail := fmt.Sprintf("starting on %s", host)
	if rec, err := corrosion.GetVM(ctx, db, vm); err == nil && rec != nil {
		detail += fmt.Sprintf(" at ownership generation %d", rec.OwnerEpoch)
	}
	if err := corrosion.InsertVMEvent(ctx, db, corrosion.VMEventRecord{VMName: vm, HostName: host,
		Type: StartingEventType, Detail: detail}); err != nil {
		return fmt.Errorf("record the start event: %w", err)
	}
	return nil
}

// MoveStartsText lists the starts of m's VM recorded since m began (the
// replicated StartingEventType events), for an operator choosing between a
// move's two files. An empty list proves nothing, and says so.
func MoveStartsText(ctx context.Context, db *corrosion.Client, m UnresolvedMove) string {
	more := fmt.Sprintf("the list may be incomplete: an event stamped by a host whose clock runs behind the move's, "+
		"one pruned with the VM's old events or beyond the newest 1000, one that has not reached this host, and a "+
		"start by a build that records none are not listed; `lv events %s` lists the events, and `lv audit ls "+
		"--target %s` its failover reschedules", m.VM, m.VM)
	evs, err := corrosion.ListVMEvents(ctx, db, m.VM, 1000, m.At)
	if err != nil {
		return fmt.Sprintf("the starts of the VM cannot be read here (%v); %s", err, more)
	}
	var out []string
	for _, e := range evs {
		if e.Type == StartingEventType {
			out = append(out, e.Detail+" ("+e.TS+")")
		}
	}
	if len(out) == 0 {
		return fmt.Sprintf("no start of the VM is recorded since the move began, but the absence proves nothing: %s", more)
	}
	return fmt.Sprintf("the starts of the VM recorded since the move began: %s; %s", strings.Join(out, "; "), more)
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
