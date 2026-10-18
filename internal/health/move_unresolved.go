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

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/secretfile"
	"github.com/litevirt/litevirt/internal/storage"
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
	Pivoted bool `json:"pivoted,omitempty"`
	// CatchUp: the config already named Dst before this move (an earlier move's
	// pivot, or a define), so Dst may hold writes Src lacks.
	CatchUp bool   `json:"catch_up,omitempty"`
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

// MoveInFlight reports whether this process is moving vm's disk.
func MoveInFlight(vm, disk string) bool { return moveInFlight(vm, disk) }

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

// MovedDiskNames reports which of m's two files the domain definition names
// for the disk, by the rule the move's own cutover uses.
func MovedDiskNames(domXML string, m UnresolvedMove) (string, error) {
	return movedDiskNames(domXML, m)
}

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

// MoveUnresolvedError is the refusal of a start, a copy or a move because of
// an unresolved volume move. Retryable marks a transient one (a move still in
// flight, a read that failed); the rest need the operator.
type MoveUnresolvedError struct {
	VM, Disk  string
	Retryable bool
	Detail    string
}

// MoveUnresolvedReason is the google.rpc.ErrorInfo reason the refusal carries
// over gRPC, so a caller recognises it through any wrapping of its text.
const MoveUnresolvedReason = "MOVE_UNRESOLVED"

const moveUnresolvedDomain = "litevirt.dev"

func (e *MoveUnresolvedError) Error() string { return "move-unresolved: " + e.Detail }

// GRPCStatus maps the refusal to FailedPrecondition, or Unavailable when it
// is transient, with an ErrorInfo detail naming it.
func (e *MoveUnresolvedError) GRPCStatus() *status.Status {
	code := codes.FailedPrecondition
	if e.Retryable {
		code = codes.Unavailable
	}
	st := status.New(code, e.Error())
	retry := "false"
	if e.Retryable {
		retry = "true"
	}
	if d, err := st.WithDetails(&errdetails.ErrorInfo{Reason: MoveUnresolvedReason, Domain: moveUnresolvedDomain,
		Metadata: map[string]string{"vm": e.VM, "disk": e.Disk, "retryable": retry}}); err == nil {
		return d
	}
	return st
}

func moveUnresolvedInfo(err error) (*errdetails.ErrorInfo, bool) {
	st, ok := status.FromError(err)
	if !ok || st == nil {
		return nil, false
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == MoveUnresolvedReason && info.GetDomain() == moveUnresolvedDomain {
			return info, true
		}
	}
	return nil, false
}

// IsMoveUnresolved reports whether err is a MoveUnresolvedError, in process
// (however wrapped) or received over gRPC.
func IsMoveUnresolved(err error) bool {
	var e *MoveUnresolvedError
	if errors.As(err, &e) {
		return true
	}
	_, ok := moveUnresolvedInfo(err)
	return ok
}

// MoveUnresolvedRetryable reports whether err is a transient refusal.
func MoveUnresolvedRetryable(err error) bool {
	var e *MoveUnresolvedError
	if errors.As(err, &e) {
		return e.Retryable
	}
	info, ok := moveUnresolvedInfo(err)
	return ok && info.GetMetadata()["retryable"] == "true"
}

func refuse(m UnresolvedMove, retryable bool, format string, args ...any) error {
	return &MoveUnresolvedError{VM: m.VM, Disk: m.Disk, Retryable: retryable, Detail: fmt.Sprintf(format, args...)}
}

// resolveCmd is the operator's exit from a condition only a person can settle.
func resolveCmd(vm string) string {
	return fmt.Sprintf("lv health resolve %s vm/%s --reason \"…\"", MoveUnresolvedCode, vm)
}

// resolveAcceptCmd is resolveCmd naming the file to keep (path, or a
// placeholder when it is the operator's to choose).
func resolveAcceptCmd(vm, path string) string {
	if path == "" {
		path = "<file to keep>"
	}
	return fmt.Sprintf("lv health resolve %s vm/%s --accept %s --reason \"…\"", MoveUnresolvedCode, vm, path)
}

// provedOffText says what proves a holder powered off for a hand resolution
// from another host.
func provedOffText(host string) string {
	return fmt.Sprintf("proven powered off (an IPMI fence, or `lv host fence-confirm %s`)", host)
}

// chooseText says how an operator tells which of a live move's files holds
// the guest's last writes when no pivot was recorded: nothing in the cluster
// knows.
func chooseText(holder string, m UnresolvedMove) string {
	return fmt.Sprintf("Nothing in the cluster records which of %s and %s holds the guest's last writes: judge it from "+
		"%s's persistent config (virsh dumpxml --inactive %s there, if it boots) or from the two files themselves "+
		"(the later modification time, `qemu-img compare %s %s`); `lv health` lists the move", m.Src, m.Dst, holder, m.VM, m.Src, m.Dst)
}

// The replicated twin of the host-local records: one health condition per VM
// whose evidence lists the host that holds the records and the records, so a
// host that does not hold them (a failover onto shared storage) honours them
// too. Raised and updated only by the host holding the records; resolved by
// it, by the VM's owner once every move is proven settled, by an admin
// (`lv health resolve`: on the holding host, or from another once the holding
// host is proven powered off, naming with --accept the file to keep of every
// move not proven settled), and for every host when the VM is deleted or a
// new VM takes its name.
const (
	MoveUnresolvedEvaluator = "move_volume"
	MoveUnresolvedCode      = "vm.move_unresolved"
	moveUnresolvedKind      = "vm"
)

// MoveUnresolvedEvidence is the condition's evidence.
type MoveUnresolvedEvidence struct {
	Host  string           `json:"host"`
	Moves []UnresolvedMove `json:"moves"`
	// Hand marks a condition an admin resolved by hand (`lv health resolve`):
	// a record of one of its moves that the holder still keeps (it was away)
	// is settled by that decision, not raised again.
	Hand bool `json:"hand,omitempty"`
}

// handSettled drops the records among moves that a hand resolution of vm's
// condition (row, resolved) settled while this host was away: the same disk,
// files and record time, no move of the disk in flight here, and the VM owned
// by another host (or gone). It returns the rest: on the VM's owner a record
// is kept for its own settle, which makes its persistent config and the disk
// row agree before its domain boots.
func handSettled(ctx context.Context, db *corrosion.Client, host string, row corrosion.HealthCondition, dataDir, vm string, moves []UnresolvedMove) []UnresolvedMove {
	if row.Lifecycle != corrosion.ConditionResolved || len(moves) == 0 {
		return moves
	}
	var ev MoveUnresolvedEvidence
	if json.Unmarshal([]byte(row.Evidence), &ev) != nil || !ev.Hand {
		return moves
	}
	if rec, err := corrosion.GetVM(ctx, db, vm); err != nil || (rec != nil && rec.HostName == host) {
		return moves
	}
	out := moves[:0:0]
	for _, m := range moves {
		decided := false
		for _, e := range ev.Moves {
			if e.Disk == m.Disk && e.Src == m.Src && e.Dst == m.Dst && e.At == m.At {
				decided = true
			}
		}
		if !decided || moveInFlight(vm, m.Disk) {
			out = append(out, m)
			continue
		}
		if err := ClearUnresolvedMove(dataDir, vm, m.Disk); err != nil {
			slog.Warn("move-volume record: dropping a record an admin resolved by hand failed", "vm", vm, "disk", m.Disk, "error", err)
			out = append(out, m)
			continue
		}
		slog.Info("move-volume record: an admin resolved this move by hand while this host was away; record dropped",
			"vm", vm, "disk", m.Disk, "src", m.Src, "dst", m.Dst)
	}
	return out
}

// OpenMoveCondition reads vm's open condition. A condition whose evidence
// cannot be read is returned open with an error.
func OpenMoveCondition(ctx context.Context, db *corrosion.Client, vm string) (corrosion.HealthCondition, MoveUnresolvedEvidence, bool, error) {
	var ev MoveUnresolvedEvidence
	if db == nil {
		return corrosion.HealthCondition{}, ev, false, nil
	}
	row, found, err := corrosion.GetHealthCondition(ctx, db, MoveUnresolvedEvaluator, MoveUnresolvedCode, moveUnresolvedKind, vm)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return row, ev, false, err
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.Host == "" {
		return row, ev, true, fmt.Errorf("unreadable %s evidence: %v", MoveUnresolvedCode, err)
	}
	return row, ev, true, nil
}

// unreadableEvidence is the refusal for a condition whose evidence cannot be
// read: a defect, not a transient state.
func unreadableEvidence(vm string, err error) error {
	return &MoveUnresolvedError{VM: vm, Detail: fmt.Sprintf("%s: the %s condition cannot be read (%v); this is a defect. "+
		"Operator: check which file holds the VM's disk data, then `%s`", vm, MoveUnresolvedCode, err, resolveCmd(vm))}
}

// complete is the file of m that holds every acknowledged write, and whether
// that is proven: dst after a pivot or a catch-up; src before a pivot (not
// proven: a pivot may not have been recorded yet); either after an offline
// move (proven: the two hold the same data), reported as "".
func complete(m UnresolvedMove) (path string, proven bool) {
	switch {
	case m.Pivoted || m.CatchUp:
		return m.Dst, true
	case m.Live:
		return m.Src, false
	default:
		return "", true
	}
}

// MoveCompleteFile is complete for another package: the file of m that holds
// every acknowledged write, and whether that is proven ("" and proven: both).
func MoveCompleteFile(m UnresolvedMove) (string, bool) { return complete(m) }

// entrySettled reports whether a recorded move no longer needs honouring:
// its VM, its disk row or both its files are gone from the row, or the row
// names the file proven to hold every acknowledged write.
func entrySettled(ctx context.Context, db *corrosion.Client, m UnresolvedMove) (bool, error) {
	vmRec, err := corrosion.GetVM(ctx, db, m.VM)
	if err != nil {
		return false, err
	}
	if vmRec == nil {
		return true, nil
	}
	row, err := diskRow(ctx, db, m)
	if err != nil {
		return false, err
	}
	if row == nil || (row.Path != m.Src && row.Path != m.Dst) {
		return true, nil
	}
	path, proven := complete(m)
	return proven && (path == "" || row.Path == path), nil
}

// PublishUnresolvedMoves brings vm's condition in line with this host's
// records of it. Entries of the condition this host holds with no record here
// are kept unless the caller settled them (settled) or they are proven settled
// (entrySettled): a lost data dir, or a record cleared as stale because the
// VM's row names another host, never resolves what that host has not healed.
// A condition another host holds is never overwritten: publishing a record
// against one is refused.
func PublishUnresolvedMoves(ctx context.Context, db *corrosion.Client, dataDir, host, vm string, settled ...string) error {
	if db == nil {
		return nil
	}
	moves, err := UnresolvedMovesOf(dataDir, vm)
	if err != nil {
		return err
	}
	row, ev, open, err := OpenMoveCondition(ctx, db, vm)
	if err != nil {
		if open {
			return unreadableEvidence(vm, err)
		}
		return err
	}
	if !open {
		moves = handSettled(ctx, db, host, row, dataDir, vm, moves)
	}
	if open && ev.Host != host {
		if len(moves) == 0 {
			return nil
		}
		return &MoveUnresolvedError{VM: vm, Detail: fmt.Sprintf("%s: %s holds an unresolved volume move of this VM "+
			"(%s); it is settled there, by a start of the VM on its new owner, or by `%s` run against %s (LV_HOST=%s), "+
			"or from another host once %s is %s",
			vm, ev.Host, MoveUnresolvedCode, resolveAcceptCmd(vm, ""), ev.Host, ev.Host, ev.Host, provedOffText(ev.Host))}
	}
	keep := append([]UnresolvedMove(nil), moves...)
	if open {
		have := map[string]bool{}
		for _, m := range moves {
			have[m.Disk] = true
		}
		for _, d := range settled {
			have[d] = true
		}
		for _, m := range ev.Moves {
			if have[m.Disk] {
				continue
			}
			done, serr := entrySettled(ctx, db, m)
			if serr != nil {
				return serr
			}
			if !done {
				keep = append(keep, m)
			}
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	if len(keep) == 0 {
		if !open {
			return nil
		}
		return resolveMoveCondition(ctx, db, row, host)
	}
	b, _ := json.Marshal(MoveUnresolvedEvidence{Host: host, Moves: keep})
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
// condition whichever host raised it: the VM is deleted, a new VM takes its
// name, or an admin resolved it by hand.
func ForgetUnresolvedMoves(ctx context.Context, db *corrosion.Client, dataDir, vm string) error {
	if err := ClearUnresolvedMovesOf(dataDir, vm); err != nil {
		return err
	}
	if db == nil {
		return nil
	}
	row, found, err := corrosion.GetHealthCondition(ctx, db, MoveUnresolvedEvaluator, MoveUnresolvedCode, moveUnresolvedKind, vm)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
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
// started on this host, or its disk rows are read for a copy or a move.
//
// For each record this host holds, the disk row is pointed at the file the
// persistent config names and the record is removed. A record whose VM, disk
// row or files no longer match is removed as stale. The operation is refused,
// naming both files and what the operator does, when the config cannot be read
// or names neither file; when the guest wrote the source under a mirror and
// was not pivoted, but the config names the copy (the copy may lack the guest's
// last writes); and when the guest was pivoted onto the copy, or the copy was
// already named before the move, but the config names the source.
//
// Moves the VM's condition lists that this host holds no record of — another
// host's, or this host's with its record lost — are honoured by
// resolveRemoteMove.
func ResolveUnresolvedMoves(ctx context.Context, db *corrosion.Client, dataDir, host, vm string, dom MoveDomain) error {
	moves, err := UnresolvedMovesOf(dataDir, vm)
	if err != nil {
		return &MoveUnresolvedError{VM: vm, Detail: fmt.Sprintf("%s: read this host's unresolved volume moves: %v", vm, err)}
	}
	if row, _, open, cerr := OpenMoveCondition(ctx, db, vm); cerr == nil && !open {
		moves = handSettled(ctx, db, host, row, dataDir, vm, moves)
	}
	// Disks settled here, or still recorded here, are this host's to honour;
	// a record dropped only because the VM's row names another host is
	// honoured by the remote rule below.
	local := map[string]bool{}
	var settled []string
	for _, m := range moves {
		done, err := resolveUnresolvedMove(ctx, db, dataDir, host, m, dom)
		if done {
			settled = append(settled, m.Disk)
		}
		if err != nil {
			if !IsMoveUnresolved(err) {
				return err
			}
			_ = PublishUnresolvedMoves(ctx, db, dataDir, host, vm, settled...)
			return err
		}
	}
	for _, d := range settled {
		local[d] = true
	}
	if still, err := UnresolvedMovesOf(dataDir, vm); err == nil {
		for _, m := range still {
			local[m.Disk] = true
		}
	}
	_, ev, open, cerr := OpenMoveCondition(ctx, db, vm)
	if cerr != nil {
		if open {
			return unreadableEvidence(vm, cerr)
		}
		return &MoveUnresolvedError{VM: vm, Retryable: true, Detail: fmt.Sprintf("%s: read the %s condition: %v", vm, MoveUnresolvedCode, cerr)}
	}
	if open {
		for _, m := range ev.Moves {
			if local[m.Disk] {
				continue
			}
			if err := resolveRemoteMove(ctx, db, dataDir, host, ev.Host, m); err != nil {
				return err
			}
		}
	}
	switch {
	case open && ev.Host == host, !open && len(moves) > 0:
		if err := PublishUnresolvedMoves(ctx, db, dataDir, host, vm, settled...); err != nil {
			slog.Warn("move-volume record: publishing the settled state failed", "vm", vm, "error", err)
		}
	case open:
		ownerResolve(ctx, db, host, vm, ev)
	}
	return nil
}

// ownerResolve resolves another host's condition once this host owns the VM
// and every move it lists is proven settled.
func ownerResolve(ctx context.Context, db *corrosion.Client, host, vm string, ev MoveUnresolvedEvidence) {
	vmRec, err := corrosion.GetVM(ctx, db, vm)
	if err != nil || vmRec == nil || vmRec.HostName != host {
		return
	}
	for _, m := range ev.Moves {
		if done, err := entrySettled(ctx, db, m); err != nil || !done {
			return
		}
	}
	row, _, open, err := OpenMoveCondition(ctx, db, vm)
	if err != nil || !open {
		return
	}
	if err := resolveMoveCondition(ctx, db, row, host); err != nil {
		slog.Warn("move-volume condition: resolving a settled condition failed", "vm", vm, "error", err)
		return
	}
	slog.Info("move-volume condition: every move it listed is settled on the VM's owner; resolved", "vm", vm, "holder", ev.Host)
}

// resolveUnresolvedMove settles one record this host holds. done reports
// whether the record is settled (removed because the row now matches the
// config or no longer describes the disk), as opposed to removed only
// because the VM's row names another host.
func resolveUnresolvedMove(ctx context.Context, db *corrosion.Client, dataDir, host string, m UnresolvedMove, dom MoveDomain) (done bool, err error) {
	if moveInFlight(m.VM, m.Disk) {
		return false, refuse(m, true, "%s: a volume move of its disk %s is in progress on %s", m.VM, m.Disk, host)
	}
	vmRec, err := corrosion.GetVM(ctx, db, m.VM)
	if err != nil {
		return false, refuse(m, true, "%s: read the VM to settle the volume move of its disk %s: %v", m.VM, m.Disk, err)
	}
	rec := UnresolvedMoveFile(dataDir, m.VM, m.Disk)
	stale := func(why string, settles bool) (bool, error) {
		slog.Info("move-volume record no longer describes the disk here; removing it", "vm", m.VM, "disk", m.Disk, "why", why, "record", rec)
		return settles, ClearUnresolvedMove(dataDir, m.VM, m.Disk)
	}
	if vmRec == nil {
		return stale("the VM is gone", true)
	}
	row, err := diskRow(ctx, db, m)
	if err != nil {
		return false, err
	}
	switch {
	case row == nil:
		return stale("the disk row is gone", true)
	case row.Path != m.Src && row.Path != m.Dst:
		return stale("the disk row names "+row.Path, true)
	case row.HostName != host:
		// The VM's row names another host: that host honours the move through
		// the condition, which stays until it is settled there.
		return stale("the disk row names host "+row.HostName, false)
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
			return false, refuse(m, false, "%s: a volume move of its disk %s did not finish, and %s has no domain %s to read its "+
				"persistent config from (%v); the disk row names %s and both files (%s, %s) are kept. A start rebuilds the "+
				"domain from the disk row, so it boots %s. Operator: name the file that holds the guest's last writes, "+
				"`%s` (on %s), and retry",
				m.VM, m.Disk, host, m.VM, xerr, row.Path, m.Src, m.Dst, row.Path, resolveAcceptCmd(m.VM, ""), host)
		}
		return false, refuse(m, false, "%s: a volume move of its disk %s did not finish, and its persistent config could not be read or "+
			"names neither %s nor %s (%v); the disk row names %s and both files are kept. Operator: make the config "+
			"readable (virsh dumpxml --inactive %s) and name one of the two files in it, then retry; the disk row is "+
			"then pointed at that file", m.VM, m.Disk, m.Src, m.Dst, xerr, row.Path, m.VM)
	}
	path, typ, pool := m.Src, m.SrcType, m.SrcPool
	if names == m.Dst {
		if m.Live && !m.Pivoted && !m.CatchUp {
			if dom.running() {
				return false, refuse(m, false, "%s: a live volume move of its disk %s did not finish: the persistent config names %s, "+
					"but the guest is writing %s with the block-copy mirror into %s still running; the disk row names %s and "+
					"both files are kept. Do not stop or restart the VM until this is resolved. Operator: either run "+
					"`virsh blockjob %s %s --pivot` and then retry `lv move-volume %s %s %s`, or point the disk's source in "+
					"the persistent config back at %s (virsh edit %s) and run `virsh blockjob %s %s --abort`",
					m.VM, m.Disk, m.Dst, m.Src, m.Dst, row.Path, m.VM, devOr(m), m.VM, m.Disk, m.DstPool, m.Src, m.VM, m.VM, devOr(m))
			}
			return false, refuse(m, false, "%s: a live volume move of its disk %s did not finish: the guest was writing %s while a "+
				"block-copy mirror kept %s current, and it stopped before a pivot, so %s may lack its last writes; the "+
				"persistent config names %s and the disk row %s; both files are kept. Operator: point the disk's source in "+
				"the persistent config back at %s (virsh edit %s) and retry. Only if the guest was pivoted onto %s before "+
				"it stopped is %s complete: then `%s` (on %s) and retry",
				m.VM, m.Disk, m.Src, m.Dst, m.Dst, m.Dst, row.Path, m.Src, m.VM, m.Dst, m.Dst, resolveAcceptCmd(m.VM, m.Dst), host)
		}
		path, typ, pool = m.Dst, m.DstType, m.DstPool
	} else if m.Pivoted || m.CatchUp {
		return false, refuse(m, false, "%s: a volume move of its disk %s did not finish: the guest was moved onto %s, or the "+
			"config named it before the move, but the persistent config names %s, which lacks the writes made since; the "+
			"disk row names %s and both files are kept. Operator: point the disk's source in the persistent config at %s "+
			"(virsh edit %s) and retry", m.VM, m.Disk, m.Dst, m.Src, row.Path, m.Dst, m.VM)
	}
	if err := pointRow(ctx, db, m, row, host, path, typ, pool); err != nil {
		return false, err
	}
	return true, ClearUnresolvedMove(dataDir, m.VM, m.Disk)
}

// resolveRemoteMove honours a move this host holds no record of (origin's,
// seen through the condition). Only a direction that is proven is taken: a
// pivoted (or catch-up) move's copy holds every write, so a row on the source
// is pointed at the copy when this host owns the VM and the copy is on a
// shared pool both hosts define alike, and refused otherwise. A live move with
// no pivot recorded may still have committed and pivoted on origin (the
// record and the row both lag the pivot), so it is refused whatever the row
// names. An offline move's two files hold the same data.
func resolveRemoteMove(ctx context.Context, db *corrosion.Client, dataDir, host, origin string, m UnresolvedMove) error {
	vmRec, err := corrosion.GetVM(ctx, db, m.VM)
	if err != nil {
		return refuse(m, true, "%s: read the VM to honour the volume move %s recorded of its disk %s: %v", m.VM, origin, m.Disk, err)
	}
	row, err := diskRow(ctx, db, m)
	if err != nil {
		return err
	}
	if vmRec == nil || row == nil || (row.Path != m.Src && row.Path != m.Dst) {
		return nil
	}
	// exit names the file to keep when it is proven (keep), and how to
	// choose it when it is not.
	exit := func(keep string) string {
		x := fmt.Sprintf("Operator: settle it on %s (start the VM or retry `lv move-volume %s %s %s` there, or run `%s` against "+
			"it, LV_HOST=%s, also once it has rejoined after the VM failed over), or, once %s is %s, run `%s` here",
			origin, m.VM, m.Disk, m.DstPool, resolveAcceptCmd(m.VM, keep), origin, origin, provedOffText(origin),
			resolveAcceptCmd(m.VM, keep))
		if keep == "" {
			x += ". " + chooseText(origin, m)
		}
		return x
	}
	switch {
	case m.Pivoted || m.CatchUp:
		if row.Path == m.Dst {
			return nil
		}
		if row.HostName == host && vmRec.HostName == host && SharedPoolHolds(ctx, db, dataDir, host, origin, m.DstPool, m.DstType, m.Dst) {
			slog.Warn("move-volume condition: the disk row named the source, which lacks the writes made on the copy; pointed it at the copy",
				"vm", m.VM, "disk", m.Disk, "origin", origin, "row_was", row.Path, "row_now", m.Dst)
			return pointRow(ctx, db, m, row, host, m.Dst, m.DstType, m.DstPool)
		}
		return refuse(m, false, "%s: a volume move of its disk %s on %s did not finish: the guest was moved onto %s, but the "+
			"disk row names %s, which lacks the writes made since, and %s is not on a shared pool %s mounts. %s",
			m.VM, m.Disk, origin, m.Dst, row.Path, m.Dst, host, exit(m.Dst))
	case m.Live:
		// Whatever the row names: the commit is a local write that replicates
		// later and the pivot follows it, so a row on the source proves no
		// more than a row on the copy. Only the holder can tell, from its own
		// persistent config.
		return refuse(m, false, "%s: a live volume move of its disk %s on %s did not finish, and the disk row names %s; "+
			"whether the guest was pivoted onto %s before %s stopped is not known here, so either %s or %s may hold its "+
			"last writes. %s", m.VM, m.Disk, origin, row.Path, m.Dst, origin, m.Src, m.Dst, exit(""))
	default:
		return nil
	}
}

// SharedPoolHolds reports whether path, a file origin wrote in its pool
// (of driver typ), is the same file on this host: typ is a shared driver;
// origin's pool and this host's pool of that name are both shared, name the
// same export (Source) and are mounted at the same directory, so a path below
// it is the same file of that export on both; the path lies below that
// directory; the directory holds the export now (an nfs pool: the path is on
// an NFS mount of that export, at the same place below it; another driver:
// the directory is a mount point), not an empty mount point; and the path is a
// regular file, not a symlink.
func SharedPoolHolds(ctx context.Context, db *corrosion.Client, dataDir, host, origin, pool, typ, path string) bool {
	if pool == "" || !corrosion.DiskIsShared(corrosion.DiskRecord{StorageType: typ}) {
		return false
	}
	p, ok, err := corrosion.GetStoragePool(ctx, db, host, pool)
	if err != nil || !ok || !corrosion.DiskIsShared(corrosion.DiskRecord{StorageType: p.Driver}) {
		return false
	}
	dir := sharedPoolDir(dataDir, p)
	if origin != host {
		o, ok, err := corrosion.GetStoragePool(ctx, db, origin, pool)
		if err != nil || !ok || !corrosion.DiskIsShared(corrosion.DiskRecord{StorageType: o.Driver}) {
			return false
		}
		if o.Source != p.Source || sharedPoolDir(dataDir, o) != dir {
			return false
		}
	}
	clean := filepath.Clean(path)
	if dir == "" || !strings.HasPrefix(clean, dir+string(filepath.Separator)) {
		return false
	}
	if !sharedPoolMounted(p, dir, clean) {
		return false
	}
	fi, serr := os.Lstat(clean)
	return serr == nil && fi.Mode().IsRegular()
}

// sharedPoolDir is the directory a shared pool's files are under: its
// Target, or the mount an nfs pool with none is given under the data dir.
func sharedPoolDir(dataDir string, p corrosion.StoragePoolRecord) string {
	switch {
	case p.Target != "":
		return filepath.Clean(p.Target)
	case p.Source != "":
		return filepath.Join(dataDir, "mounts", storage.NFSMountName(p.Source))
	}
	return ""
}

// sharedPoolMounted reports whether dir holds pool p's storage now, as seen
// for path below it: for nfs, path is on an NFS mount of p's export at the
// same place below the export as below dir; otherwise dir is a mount point. A
// directory nothing is mounted on (its files are the local disk's) does not.
func sharedPoolMounted(p corrosion.StoragePoolRecord, dir, path string) bool {
	t, err := storage.ReadMountTable()
	if err != nil {
		return false
	}
	if !strings.EqualFold(p.Driver, "nfs") {
		return storage.IsMountPoint(dir)
	}
	want, err := storage.ParseNFSExport(p.Source)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	want.Path = filepath.Clean(filepath.Join(want.Path, rel))
	b, err := t.NFSBackingOf(path)
	return err == nil && b != nil && b.Export == want
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
	slog.Warn("move-volume record: pointed the disk row at the file holding the guest's writes",
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
	_, ev, open, err := OpenMoveCondition(ctx, db, vm)
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
