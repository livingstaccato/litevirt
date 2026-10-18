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
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/secretfile"
)

// An unresolved volume move (lv move-volume): a move records one before the
// first step that can leave the VM's persistent domain config and its disk
// row naming different files, and removes it once the two agree again. One a
// move leaves behind (a double fault, or a daemon that died mid-cutover) is
// honoured by every start of the VM's domain, every migration, and every copy
// that reads the disk row: the row is pointed at the file the config names
// (ResolveUnresolvedMoves), or the operation is refused when that cannot be
// done without losing writes. Its replicated twin (vm.move_unresolved) carries
// it to the other hosts.

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
	root := filepath.Join(dataDir, UnresolvedMoveDirName)
	_, rerr := os.Stat(root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if os.IsNotExist(rerr) {
		// The tree is new: make its entry in the data directory durable too.
		if err := syncDir(dataDir); err != nil {
			return err
		}
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

// MoveUnresolvedError is the refusal of a start, a copy or a retried move
// because of an unresolved volume move. Retryable marks a transient one (a
// move still in flight, a read that failed); the rest need the operator.
type MoveUnresolvedError struct {
	VM, Disk  string
	Retryable bool
	Detail    string
}

// moveUnresolvedPrefix starts every MoveUnresolvedError's text, so a caller
// that received one over gRPC can recognise it (IsMoveUnresolved).
const moveUnresolvedPrefix = "move-unresolved: "

func (e *MoveUnresolvedError) Error() string { return moveUnresolvedPrefix + e.Detail }

// GRPCStatus maps the refusal to FailedPrecondition, or Unavailable when it
// is transient.
func (e *MoveUnresolvedError) GRPCStatus() *status.Status {
	if e.Retryable {
		return status.New(codes.Unavailable, e.Error())
	}
	return status.New(codes.FailedPrecondition, e.Error())
}

// IsMoveUnresolved reports whether err is a MoveUnresolvedError, in process or
// received over gRPC.
func IsMoveUnresolved(err error) bool {
	var e *MoveUnresolvedError
	if errors.As(err, &e) {
		return true
	}
	st, ok := status.FromError(err)
	return ok && strings.HasPrefix(st.Message(), moveUnresolvedPrefix)
}

// MoveUnresolvedRetryable reports whether err is a transient refusal.
func MoveUnresolvedRetryable(err error) bool {
	var e *MoveUnresolvedError
	if errors.As(err, &e) {
		return e.Retryable
	}
	return status.Code(err) == codes.Unavailable && IsMoveUnresolved(err)
}

func refuse(m UnresolvedMove, retryable bool, format string, args ...any) error {
	return &MoveUnresolvedError{VM: m.VM, Disk: m.Disk, Retryable: retryable, Detail: fmt.Sprintf(format, args...)}
}

// The replicated twin of the host-local records: one health condition per VM
// whose evidence lists the host that holds the records and the records, so a
// host that does not hold them (a failover onto shared storage) honours them
// too. Raised and resolved only by the host holding the records
// (PublishUnresolvedMoves); cleared for every host when the VM is deleted or a
// new VM takes its name.
const (
	MoveUnresolvedEvaluator = "move_volume"
	MoveUnresolvedCode      = "vm.move_unresolved"
	moveUnresolvedKind      = "vm"
)

type moveUnresolvedEvidence struct {
	Host  string           `json:"host"`
	Moves []UnresolvedMove `json:"moves"`
}

func openMoveCondition(ctx context.Context, db *corrosion.Client, vm string) (corrosion.HealthCondition, moveUnresolvedEvidence, bool, error) {
	var ev moveUnresolvedEvidence
	if db == nil {
		return corrosion.HealthCondition{}, ev, false, nil
	}
	row, found, err := corrosion.GetHealthCondition(ctx, db, MoveUnresolvedEvaluator, MoveUnresolvedCode, moveUnresolvedKind, vm)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return row, ev, false, err
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		return row, ev, true, fmt.Errorf("unreadable %s evidence: %w", MoveUnresolvedCode, err)
	}
	return row, ev, true, nil
}

// PublishUnresolvedMoves brings vm's condition in line with this host's
// records of it: raised (or updated) while one exists, resolved when none is
// left. A condition another host raised is left alone.
func PublishUnresolvedMoves(ctx context.Context, db *corrosion.Client, dataDir, host, vm string) error {
	if db == nil {
		return nil
	}
	moves, err := UnresolvedMovesOf(dataDir, vm)
	if err != nil {
		return err
	}
	row, ev, open, err := openMoveCondition(ctx, db, vm)
	if err != nil && !open {
		return err
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	if len(moves) == 0 {
		if !open || (ev.Host != "" && ev.Host != host) {
			return nil
		}
		return resolveMoveCondition(ctx, db, row, host)
	}
	b, _ := json.Marshal(moveUnresolvedEvidence{Host: host, Moves: moves})
	if open && row.Evidence == string(b) {
		return nil
	}
	if !open {
		row = corrosion.HealthCondition{Evaluator: MoveUnresolvedEvaluator, Code: MoveUnresolvedCode,
			SubjectKind: moveUnresolvedKind, SubjectID: vm, Lifecycle: corrosion.ConditionConfirmed,
			FirstSeen: ts, ConfirmedAt: ts}
	}
	row.Evidence, row.Severity, row.Hosts = string(b), corrosion.SeverityWarning, []string{host}
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen, row.ResolvedAt, row.Reporter = ts, "", host
	return corrosion.UpsertHealthCondition(ctx, db, row)
}

func resolveMoveCondition(ctx context.Context, db *corrosion.Client, row corrosion.HealthCondition, host string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, host
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	return corrosion.UpsertHealthCondition(ctx, db, row)
}

// ForgetUnresolvedMoves drops vm's records on this host and resolves its
// condition whichever host raised it: the VM is deleted, or a new VM takes
// its name.
func ForgetUnresolvedMoves(ctx context.Context, db *corrosion.Client, dataDir, vm string) error {
	if err := ClearUnresolvedMovesOf(dataDir, vm); err != nil {
		return err
	}
	row, _, open, err := openMoveCondition(ctx, db, vm)
	if !open {
		return err
	}
	return resolveMoveCondition(ctx, db, row, row.Reporter)
}

// MoveDomain is what the settle reads of the VM's domain on this host.
type MoveDomain struct {
	// InactiveXML reads the persistent config.
	InactiveXML func() (string, error)
	// State reads the domain's state ("running", "shutoff", …); an error
	// when it is not defined here.
	State func() (string, error)
}

func (d MoveDomain) running() bool {
	if d.State == nil {
		return false
	}
	st, err := d.State()
	return err == nil && st == "running"
}

// missing reports whether the domain is known not to be defined here (a
// state read that failed for another reason is not taken for that).
func (d MoveDomain) missing() bool {
	if d.State == nil {
		return false
	}
	st, err := d.State()
	if err != nil {
		msg := strings.ToLower(err.Error())
		return strings.Contains(msg, "not found") || strings.Contains(msg, "no domain")
	}
	return st == "no-domain"
}

// ResolveUnresolvedMoves settles vm's recorded moves before its domain is
// started on this host, or its disk rows are read for a copy.
//
// For each record this host holds, the disk row is pointed at the file the
// persistent config names and the record is removed. A record whose VM, disk
// row or files no longer match is removed as stale. The operation is refused,
// naming both files and what the operator does, when the config cannot be read
// or names neither file; when the guest wrote the source under a mirror and
// was not pivoted, but the config names the copy (the copy may lack the guest's
// last writes); and when the guest was pivoted onto the copy but the config
// names the source (which lacks the writes made since).
//
// Records another host holds are seen through the VM's condition. That host's
// config cannot be read here, so the file holding every acknowledged write
// decides: the source before a pivot, the copy after one, either after an
// offline move. A row naming the other file is refused, or, when the VM's row
// names this host (it was failed over here) and the file is reachable, pointed
// at it.
func ResolveUnresolvedMoves(ctx context.Context, db *corrosion.Client, dataDir, host, vm string, dom MoveDomain) error {
	moves, err := UnresolvedMovesOf(dataDir, vm)
	if err != nil {
		return &MoveUnresolvedError{VM: vm, Detail: fmt.Sprintf("%s: read this host's unresolved volume moves: %v", vm, err)}
	}
	local := map[string]bool{}
	for _, m := range moves {
		local[m.Disk] = true
		if err := resolveUnresolvedMove(ctx, db, dataDir, host, m, dom); err != nil {
			_ = PublishUnresolvedMoves(ctx, db, dataDir, host, vm)
			return err
		}
	}
	_, ev, open, cerr := openMoveCondition(ctx, db, vm)
	if cerr != nil {
		return &MoveUnresolvedError{VM: vm, Retryable: true, Detail: fmt.Sprintf("%s: read the %s condition: %v", vm, MoveUnresolvedCode, cerr)}
	}
	if open && ev.Host == host {
		// This host's own condition: its records above are the truth.
		if err := PublishUnresolvedMoves(ctx, db, dataDir, host, vm); err != nil {
			slog.Warn("move-volume record: publishing the settled state failed", "vm", vm, "error", err)
		}
		return nil
	}
	if !open {
		return nil
	}
	for _, m := range ev.Moves {
		if local[m.Disk] {
			continue
		}
		if err := resolveRemoteMove(ctx, db, host, ev.Host, m); err != nil {
			return err
		}
	}
	return nil
}

func resolveUnresolvedMove(ctx context.Context, db *corrosion.Client, dataDir, host string, m UnresolvedMove, dom MoveDomain) error {
	rec := UnresolvedMoveFile(dataDir, m.VM, m.Disk)
	if moveInFlight(m.VM, m.Disk) {
		return refuse(m, true, "%s: a volume move of its disk %s is in progress on %s", m.VM, m.Disk, host)
	}
	vmRec, err := corrosion.GetVM(ctx, db, m.VM)
	if err != nil {
		return refuse(m, true, "%s: read the VM to settle the volume move of its disk %s: %v", m.VM, m.Disk, err)
	}
	stale := func(why string) error {
		slog.Info("move-volume record no longer describes the disk; removing it", "vm", m.VM, "disk", m.Disk, "why", why, "record", rec)
		return ClearUnresolvedMove(dataDir, m.VM, m.Disk)
	}
	if vmRec == nil {
		return stale("the VM is gone")
	}
	row, err := diskRow(ctx, db, m)
	if err != nil {
		return err
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
	if dom.InactiveXML != nil {
		x, xerr = dom.InactiveXML()
	}
	names := ""
	if xerr == nil {
		names, xerr = movedDiskNames(x, m)
	}
	if xerr != nil {
		if dom.missing() {
			return refuse(m, false, "%s: a volume move of its disk %s did not finish, and %s has no domain %s to read its "+
				"persistent config from (%v); the disk row names %s and both files (%s, %s) are kept. A start rebuilds the "+
				"domain from the disk row, so it boots %s: if that is the file to keep, remove the record %s and retry",
				m.VM, m.Disk, host, m.VM, xerr, row.Path, m.Src, m.Dst, row.Path, rec)
		}
		return refuse(m, false, "%s: a volume move of its disk %s did not finish, and its persistent config could not be read or "+
			"names neither %s nor %s (%v); the disk row names %s and both files are kept. Operator: make the config "+
			"readable (virsh dumpxml --inactive %s) and name one of the two files in it, then retry; the disk row is "+
			"then pointed at that file (the record is %s)", m.VM, m.Disk, m.Src, m.Dst, xerr, row.Path, m.VM, rec)
	}
	path, typ, pool := m.Src, m.SrcType, m.SrcPool
	if names == m.Dst {
		if m.Live && !m.Pivoted {
			if dom.running() {
				return refuse(m, false, "%s: a live volume move of its disk %s did not finish: the persistent config names %s, "+
					"but the guest is writing %s with the block-copy mirror into %s still running; the disk row names %s and "+
					"both files are kept. Do not stop or restart the VM until this is resolved. Operator: either run "+
					"`virsh blockjob %s %s --pivot` and then retry `lv move-volume %s %s %s`, or point the disk's source in "+
					"the persistent config back at %s (virsh edit %s) and run `virsh blockjob %s %s --abort` (the record is %s)",
					m.VM, m.Disk, m.Dst, m.Src, m.Dst, row.Path, m.VM, devOr(m), m.VM, m.Disk, m.DstPool, m.Src, m.VM, m.VM, devOr(m), rec)
			}
			return refuse(m, false, "%s: a live volume move of its disk %s did not finish: the guest was writing %s while a "+
				"block-copy mirror kept %s current, and it stopped before a pivot, so %s may lack its last writes; the "+
				"persistent config names %s and the disk row %s; both files are kept. Operator: point the disk's source in "+
				"the persistent config back at %s (virsh edit %s) and retry. Only if the guest was pivoted onto %s before "+
				"it stopped is %s complete: then remove the record %s and retry",
				m.VM, m.Disk, m.Src, m.Dst, m.Dst, m.Dst, row.Path, m.Src, m.VM, m.Dst, m.Dst, rec)
		}
		path, typ, pool = m.Dst, m.DstType, m.DstPool
	} else if m.Pivoted {
		return refuse(m, false, "%s: a live volume move of its disk %s did not finish: the guest was pivoted onto %s, but the "+
			"persistent config names %s, which lacks the writes made since; the disk row names %s and both files are "+
			"kept. Operator: point the disk's source in the persistent config at %s (virsh edit %s) and retry (the "+
			"record is %s)", m.VM, m.Disk, m.Dst, m.Src, row.Path, m.Dst, m.VM, rec)
	}
	if err := pointRow(ctx, db, m, row, host, path, typ, pool); err != nil {
		return err
	}
	return ClearUnresolvedMove(dataDir, m.VM, m.Disk)
}

// resolveRemoteMove honours a record another host holds (origin).
func resolveRemoteMove(ctx context.Context, db *corrosion.Client, host, origin string, m UnresolvedMove) error {
	vmRec, err := corrosion.GetVM(ctx, db, m.VM)
	if err != nil {
		return refuse(m, true, "%s: read the VM to honour the volume move %s recorded of its disk %s: %v", m.VM, origin, m.Disk, err)
	}
	row, err := diskRow(ctx, db, m)
	if err != nil {
		return err
	}
	if vmRec == nil || row == nil || (row.Path != m.Src && row.Path != m.Dst) {
		return nil // the condition no longer describes the disk; its host resolves it
	}
	complete, typ, pool := m.Src, m.SrcType, m.SrcPool
	switch {
	case !m.Live:
		return nil // an offline move: the two files hold the same data
	case m.Pivoted:
		complete, typ, pool = m.Dst, m.DstType, m.DstPool
	}
	if row.Path == complete {
		return nil
	}
	if row.HostName == host && vmRec.HostName == host {
		if _, serr := os.Stat(complete); serr == nil {
			slog.Warn("move-volume condition: the disk row named a file that may lack the guest's last writes; pointed it at the one that holds them",
				"vm", m.VM, "disk", m.Disk, "origin", origin, "row_was", row.Path, "row_now", complete)
			return pointRow(ctx, db, m, row, host, complete, typ, pool)
		}
	}
	return refuse(m, false, "%s: a live volume move of its disk %s on %s did not finish, and the disk row names %s, which may "+
		"lack the guest's last writes; %s holds them. The move's record is on %s: start the VM or retry `lv move-volume "+
		"%s %s %s` there to settle it", m.VM, m.Disk, origin, row.Path, complete, origin, m.VM, m.Disk, m.DstPool)
}

func diskRow(ctx context.Context, db *corrosion.Client, m UnresolvedMove) (*corrosion.DiskRecord, error) {
	disks, err := corrosion.GetVMDisks(ctx, db, m.VM)
	if err != nil {
		return nil, refuse(m, true, "%s: read the disk rows to settle the volume move of disk %s: %v", m.VM, m.Disk, err)
	}
	for i := range disks {
		if disks[i].DiskName == m.Disk {
			return &disks[i], nil
		}
	}
	return nil, nil
}

func pointRow(ctx context.Context, db *corrosion.Client, m UnresolvedMove, row *corrosion.DiskRecord, host, path, typ, pool string) error {
	if row.Path == path {
		return nil
	}
	if err := corrosion.UpdateDiskPlacement(ctx, db, m.VM, m.Disk, host, path, typ, pool); err != nil {
		return refuse(m, true, "%s: point the disk row of %s at %s: %v", m.VM, m.Disk, path, err)
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
	return nil
}

func devOr(m UnresolvedMove) string {
	if m.TargetDev != "" {
		return m.TargetDev
	}
	return m.Src
}

// domainRunningNow reports whether libvirt reads name as running.
func domainRunningNow(v interface {
	DomainState(string) (string, error)
}, name string) bool {
	st, err := v.DomainState(name)
	return err == nil && st == "running"
}

// MoveConditionCovers reports whether vm's replicated condition records an
// unresolved move of disk (on any host). A read error counts as covering it.
func MoveConditionCovers(ctx context.Context, db *corrosion.Client, vm, disk string) bool {
	_, ev, open, err := openMoveCondition(ctx, db, vm)
	if err != nil {
		return true
	}
	if !open {
		return false
	}
	for _, m := range ev.Moves {
		if m.Disk == disk {
			return true
		}
	}
	return false
}
