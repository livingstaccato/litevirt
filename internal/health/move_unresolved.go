package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/secretfile"
)

// An unresolved volume move (lv move-volume): a move records one before the
// first step that can leave the VM's persistent domain config and its disk
// row naming different files, and removes it once the two agree again. One a
// move leaves behind (a double fault, or a daemon that died mid-cutover) is
// honoured by every start of the VM's domain on this host, and by the cold
// migration and the backup that read the disk row: the row is pointed at the
// file the config names (ResolveUnresolvedMoves), or the operation is refused
// when that cannot be done without losing writes.

// UnresolvedMoveDirName is the data-dir child the records live in.
const UnresolvedMoveDirName = "move-unresolved"

// UnresolvedMove is one recorded move of one disk.
type UnresolvedMove struct {
	VM        string `json:"vm"`
	Disk      string `json:"disk"`
	TargetDev string `json:"target_dev,omitempty"`
	Src       string `json:"src"`
	SrcType   string `json:"src_type,omitempty"`
	SrcPool   string `json:"src_pool,omitempty"`
	Dst       string `json:"dst"`
	DstType   string `json:"dst_type,omitempty"`
	DstPool   string `json:"dst_pool,omitempty"`
	// Live: a block-copy mirror ran, so the guest wrote Src until a pivot.
	Live bool `json:"live,omitempty"`
	// Pivoted: the guest was moved onto Dst, so Src lacks its later writes.
	Pivoted bool   `json:"pivoted,omitempty"`
	Error   string `json:"error,omitempty"`
	At      string `json:"at"`
}

func unresolvedMoveVMDir(dataDir, vm string) string {
	sum := sha256.Sum256([]byte(vm))
	return filepath.Join(dataDir, UnresolvedMoveDirName, hex.EncodeToString(sum[:]))
}

// UnresolvedMoveFile is where the record of vm's disk is kept.
func UnresolvedMoveFile(dataDir, vm, disk string) string {
	sum := sha256.Sum256([]byte(disk))
	return filepath.Join(unresolvedMoveVMDir(dataDir, vm), hex.EncodeToString(sum[:]))
}

// movesInFlight holds the moves this process is running, keyed vm\x00disk.
// A record of one of them describes a move still under way, not one left
// behind, so no start acts on it.
var movesInFlight sync.Map

// MarkMoveInFlight marks vm's disk as being moved by this process until end
// is called.
func MarkMoveInFlight(vm, disk string) (end func()) {
	k := vm + "\x00" + disk
	movesInFlight.Store(k, struct{}{})
	return func() { movesInFlight.Delete(k) }
}

func moveInFlight(vm, disk string) bool {
	_, ok := movesInFlight.Load(vm + "\x00" + disk)
	return ok
}

// RecordUnresolvedMove durably records m, replacing an earlier record of the
// same disk.
func RecordUnresolvedMove(dataDir string, m UnresolvedMove) error {
	if m.VM == "" || m.Disk == "" || m.Src == "" || m.Dst == "" {
		return fmt.Errorf("an unresolved move names its vm, disk and both files")
	}
	if m.At == "" {
		m.At = time.Now().UTC().Format(time.RFC3339)
	}
	dir := unresolvedMoveVMDir(dataDir, m.VM)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := secretfile.Write(UnresolvedMoveFile(dataDir, m.VM, m.Disk), b, 0o600); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dir))
}

// ClearUnresolvedMove removes the record of vm's disk. An absent one is not
// an error.
func ClearUnresolvedMove(dataDir, vm, disk string) error {
	if err := os.Remove(UnresolvedMoveFile(dataDir, vm, disk)); err != nil && !os.IsNotExist(err) {
		return err
	}
	dir := unresolvedMoveVMDir(dataDir, vm)
	_ = syncDir(dir)
	_ = os.Remove(dir) // only once it is empty
	return nil
}

// ClearUnresolvedMovesOf removes every record of vm: its domain is gone.
func ClearUnresolvedMovesOf(dataDir, vm string) error {
	if err := os.RemoveAll(unresolvedMoveVMDir(dataDir, vm)); err != nil {
		return err
	}
	_ = syncDir(filepath.Join(dataDir, UnresolvedMoveDirName))
	return nil
}

// UnresolvedMovesOf lists vm's records. An unreadable one fails the read: it
// may be one.
func UnresolvedMovesOf(dataDir, vm string) ([]UnresolvedMove, error) {
	dir := unresolvedMoveVMDir(dataDir, vm)
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []UnresolvedMove
	for _, e := range ents {
		if e.Name() != "" && e.Name()[0] == '.' {
			continue // a temp file of a write that did not finish
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var m UnresolvedMove
		if err := json.Unmarshal(b, &m); err != nil || m.VM != vm || m.Disk == "" || m.Src == "" || m.Dst == "" {
			return nil, fmt.Errorf("unreadable unresolved-move record %s: %v", p, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// movedDiskNames reports which of m's two files the domain definition names
// for the disk, by the rule the move's own cutover uses.
func movedDiskNames(domXML string, m UnresolvedMove) (string, error) {
	_, changed, err := lv.RewriteDiskSource(domXML, m.TargetDev, m.Src, m.Dst)
	if err != nil {
		return "", err
	}
	if changed {
		return m.Src, nil
	}
	return m.Dst, nil
}

// ResolveUnresolvedMoves settles vm's recorded moves on this host before its
// domain is started or its disk rows are read for a copy. inactiveXML reads
// the domain's persistent config; it is called only when a record exists.
//
// For each record, the disk row is pointed at the file the config names and
// the record is removed. A record whose VM, disk row or files no longer match
// is removed as stale. The operation is refused, naming both files and what
// the operator does, when the config cannot be read or names neither file;
// when the guest was writing the source under a mirror and stopped before a
// pivot, but the config names the copy (the copy may lack the guest's last
// writes); and when the guest was pivoted onto the copy but the config names
// the source (which lacks the writes made since).
func ResolveUnresolvedMoves(ctx context.Context, db *corrosion.Client, dataDir, host, vm string, inactiveXML func() (string, error)) error {
	moves, err := UnresolvedMovesOf(dataDir, vm)
	if err != nil {
		return fmt.Errorf("%s: read this host's unresolved volume moves: %w", vm, err)
	}
	for _, m := range moves {
		if err := resolveUnresolvedMove(ctx, db, dataDir, host, m, inactiveXML); err != nil {
			return err
		}
	}
	return nil
}

func resolveUnresolvedMove(ctx context.Context, db *corrosion.Client, dataDir, host string, m UnresolvedMove, inactiveXML func() (string, error)) error {
	rec := UnresolvedMoveFile(dataDir, m.VM, m.Disk)
	if moveInFlight(m.VM, m.Disk) {
		return fmt.Errorf("%s: a volume move of its disk %s is in progress on %s", m.VM, m.Disk, host)
	}
	vmRec, err := corrosion.GetVM(ctx, db, m.VM)
	if err != nil {
		return fmt.Errorf("%s: read the VM to settle the volume move of its disk %s: %w", m.VM, m.Disk, err)
	}
	stale := func(why string) error {
		slog.Info("move-volume record no longer describes the disk; removing it", "vm", m.VM, "disk", m.Disk, "why", why, "record", rec)
		return ClearUnresolvedMove(dataDir, m.VM, m.Disk)
	}
	if vmRec == nil {
		return stale("the VM is gone")
	}
	disks, err := corrosion.GetVMDisks(ctx, db, m.VM)
	if err != nil {
		return fmt.Errorf("%s: read the disk rows to settle the volume move of disk %s: %w", m.VM, m.Disk, err)
	}
	var row *corrosion.DiskRecord
	for i := range disks {
		if disks[i].DiskName == m.Disk {
			row = &disks[i]
		}
	}
	switch {
	case row == nil:
		return stale("the disk row is gone")
	case row.HostName != host:
		return stale("the disk row names host " + row.HostName)
	case row.Path != m.Src && row.Path != m.Dst:
		return stale("the disk row names " + row.Path)
	}

	x, xerr := "", errors.New("no libvirt backend")
	if inactiveXML != nil {
		x, xerr = inactiveXML()
	}
	names := ""
	if xerr == nil {
		names, xerr = movedDiskNames(x, m)
	}
	if xerr != nil {
		return fmt.Errorf("%s: a volume move of its disk %s did not finish, and its persistent config could not be read or "+
			"names neither %s nor %s (%v); the disk row names %s and both files are kept. Operator: make the config "+
			"readable (virsh dumpxml --inactive %s) and name one of the two files in it, then retry; the disk row is "+
			"then pointed at that file (the record is %s)", m.VM, m.Disk, m.Src, m.Dst, xerr, row.Path, m.VM, rec)
	}
	path, typ, pool := m.Src, m.SrcType, m.SrcPool
	if names == m.Dst {
		if m.Live && !m.Pivoted {
			return fmt.Errorf("%s: a live volume move of its disk %s did not finish: the guest was writing %s while a "+
				"block-copy mirror kept %s current, and it stopped before a pivot, so %s may lack its last writes; the "+
				"persistent config names %s and the disk row %s; both files are kept. Operator: if the guest was pivoted "+
				"onto %s (virsh blockjob %s <disk> --pivot) before it stopped, retry `lv move-volume %s %s %s`; otherwise "+
				"point the disk's source in the persistent config back at %s (virsh edit %s) and retry (the record is %s)",
				m.VM, m.Disk, m.Src, m.Dst, m.Dst, m.Dst, row.Path, m.Dst, m.VM, m.VM, m.Disk, m.DstPool, m.Src, m.VM, rec)
		}
		path, typ, pool = m.Dst, m.DstType, m.DstPool
	} else if m.Pivoted {
		return fmt.Errorf("%s: a live volume move of its disk %s did not finish: the guest was pivoted onto %s, but the "+
			"persistent config names %s, which lacks the writes made since; the disk row names %s and both files are "+
			"kept. Operator: point the disk's source in the persistent config at %s (virsh edit %s) and retry (the "+
			"record is %s)", m.VM, m.Disk, m.Dst, m.Src, row.Path, m.Dst, m.VM, rec)
	}
	if row.Path != path {
		if err := corrosion.UpdateDiskPlacement(ctx, db, m.VM, m.Disk, host, path, typ, pool); err != nil {
			return fmt.Errorf("%s: point the disk row of %s at %s, which the persistent config names: %w", m.VM, m.Disk, path, err)
		}
		if path == m.Dst {
			if info, ierr := qcow2.Info(path); ierr == nil && info.BackingFile == "" {
				if cerr := corrosion.ClearDiskBacking(ctx, db, m.VM, m.Disk, path); cerr != nil {
					slog.Warn("move-volume record: clearing the moved disk's backing record failed", "vm", m.VM, "disk", m.Disk, "error", cerr)
				}
			}
		}
		slog.Warn("move-volume record: the disk row named a file the persistent config does not; pointed it at the config's",
			"vm", m.VM, "disk", m.Disk, "row_was", row.Path, "row_now", path)
	}
	return ClearUnresolvedMove(dataDir, m.VM, m.Disk)
}

// domainRunningNow reports whether libvirt reads name as running.
func domainRunningNow(v interface {
	DomainState(string) (string, error)
}, name string) bool {
	st, err := v.DomainState(name)
	return err == nil && st == "running"
}
