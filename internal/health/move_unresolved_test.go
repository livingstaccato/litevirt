package health

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// moveDomainXML is a stopped domain whose disk vda names path.
func moveDomainXML(name, path string) string {
	return `<domain type="kvm"><name>` + name + `</name><devices><disk type="file" device="disk">` +
		`<source file="` + path + `"/><target dev="vda" bus="virtio"/></disk></devices></domain>`
}

// seedMovedVM inserts VM mv on node-a whose disk row names src, with both
// files present and the persistent config (in a fresh fake) naming configNames,
// and records an unresolved move of the disk to dst.
func seedMovedVM(t *testing.T, db *corrosion.Client, dataDir, configNames string, live, pivoted bool) (fake *libvirtfake.Fake, src, dst string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	src, dst = filepath.Join(dir, "hot", "mv-root.qcow2"), filepath.Join(dir, "warm", "mv-root.qcow2")
	for _, p := range []string{src, dst} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if configNames == "src" {
		configNames = src
	} else {
		configNames = dst
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "mv", HostName: "node-a", Spec: `{"name":"mv","cpu":1,"memory_mib":512}`, State: "running", CPUActual: 1, MemActual: 512},
		nil,
		[]corrosion.DiskRecord{{VMName: "mv", DiskName: "root", HostName: "node-a", Path: src, StorageType: "local",
			StorageVolume: "hot", SizeBytes: 1 << 30, TargetDev: "vda"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake = libvirtfake.New()
	if err := fake.DefineDomain(moveDomainXML("mv", configNames)); err != nil {
		t.Fatal(err)
	}
	if err := RecordUnresolvedMove(dataDir, UnresolvedMove{VM: "mv", Disk: "root", TargetDev: "vda",
		Src: src, SrcType: "local", SrcPool: "hot", Dst: dst, DstType: "local", DstPool: "warm",
		Live: live, Pivoted: pivoted}); err != nil {
		t.Fatal(err)
	}
	return fake, src, dst
}

func movedRowPath(t *testing.T, db *corrosion.Client) string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), db, "mv")
	if err != nil || len(disks) != 1 {
		t.Fatalf("disk rows: %+v %v", disks, err)
	}
	return disks[0].Path
}

// The reconciler's start (an HA restart, onboot, a self-heal) settles an
// unresolved move before it rebuilds the domain from the rows: the row is
// pointed at the file the persistent config names, so the rebuilt domain boots
// that file; or the start is refused when the copy may lack the guest's last
// writes.
func TestStartPendingVM_HonoursAnUnresolvedMove(t *testing.T) {
	t.Run("offline: the row follows the config", func(t *testing.T) {
		db := testReconcilerDB(t)
		r, _, _ := sharedDiskReconciler(t, db)
		fake, _, dst := seedMovedVM(t, db, r.dataDir, "dst", false, false)
		r.virt = fake
		fresh, _ := corrosion.GetVM(context.Background(), db, "mv")
		r.startPendingVM(context.Background(), *fresh)
		if got := movedRowPath(t, db); got != dst {
			t.Fatalf("disk row names %s, want the copy %s the config named", got, dst)
		}
		if x := fake.DefinedXML("mv"); !strings.Contains(x, dst) {
			t.Fatalf("the rebuilt domain does not boot the copy:\n%s", x)
		}
		if ms, _ := UnresolvedMovesOf(r.dataDir, "mv"); len(ms) != 0 {
			t.Fatalf("record kept after its resolution: %+v", ms)
		}
	})
	t.Run("live before the pivot, config names the copy: refused", func(t *testing.T) {
		db := testReconcilerDB(t)
		r, _, _ := sharedDiskReconciler(t, db)
		fake, src, dst := seedMovedVM(t, db, r.dataDir, "dst", true, false)
		r.virt = fake
		fresh, _ := corrosion.GetVM(context.Background(), db, "mv")
		r.startPendingVM(context.Background(), *fresh)
		if got := movedRowPath(t, db); got != src {
			t.Fatalf("disk row names %s, want it left on %s", got, src)
		}
		if st, _ := fake.DomainState("mv"); st == "running" {
			t.Fatal("the domain was started")
		}
		vm, _ := corrosion.GetVM(context.Background(), db, "mv")
		if vm.State != "error" || !strings.Contains(vm.StateDetail, dst) || !strings.Contains(vm.StateDetail, "stopped before a pivot") {
			t.Fatalf("VM state %q (%s), want error naming the copy", vm.State, vm.StateDetail)
		}
		if ms, _ := UnresolvedMovesOf(r.dataDir, "mv"); len(ms) != 1 {
			t.Fatalf("record dropped by a refused start: %+v", ms)
		}
	})
}

// The health check's restart honours the record too.
func TestStartGuarded_HonoursAnUnresolvedMove(t *testing.T) {
	db := testReconcilerDB(t)
	dataDir := t.TempDir()
	fake, src, dst := seedMovedVM(t, db, dataDir, "src", true, true)
	v := NewVMChecker("node-a", dataDir, db, nil)
	v.virt = fake
	err := v.startGuarded(context.Background(), "mv")
	if err == nil || !strings.Contains(err.Error(), dst) || !strings.Contains(err.Error(), src) || !strings.Contains(err.Error(), "was moved onto") {
		t.Fatalf("want the restart refused naming both files (the guest was pivoted, the config names the source), got %v", err)
	}
	if st, _ := fake.DomainState("mv"); st == "running" {
		t.Fatal("the domain was started")
	}

	// The operator points the config at the copy: the restart settles the row.
	if err := fake.DefineDomain(moveDomainXML("mv", dst)); err != nil {
		t.Fatal(err)
	}
	if err := v.startGuarded(context.Background(), "mv"); err != nil {
		t.Fatalf("startGuarded: %v", err)
	}
	if got := movedRowPath(t, db); got != dst {
		t.Fatalf("disk row names %s, want %s", got, dst)
	}
}

// An unreadable record refuses the VM's start rather than be ignored.
func TestResolveUnresolvedMoves_UnreadableRecordRefuses(t *testing.T) {
	db := testReconcilerDB(t)
	dataDir := t.TempDir()
	if err := RecordUnresolvedMove(dataDir, UnresolvedMove{VM: "mv", Disk: "root", Src: "/a", Dst: "/b"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(UnresolvedMoveFile(dataDir, "mv", "root"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ResolveUnresolvedMoves(context.Background(), db, dataDir, "node-a", "mv", MoveDomain{InactiveXML: func() (string, error) { return "", nil }})
	if err == nil {
		t.Fatal("an unreadable record was ignored")
	}
}

// m-2: a move still in flight refuses the reconciler's start as transient: the
// VM is not parked in error, and a later pass starts it.
func TestStartPendingVM_InFlightMoveIsRetried(t *testing.T) {
	db := testReconcilerDB(t)
	r, _, _ := sharedDiskReconciler(t, db)
	fake, _, _ := seedMovedVM(t, db, r.dataDir, "dst", false, false)
	r.virt = fake
	end := MarkMoveInFlight("mv", "root")
	fresh, _ := corrosion.GetVM(context.Background(), db, "mv")
	r.startPendingVM(context.Background(), *fresh)
	end()
	vm, _ := corrosion.GetVM(context.Background(), db, "mv")
	if vm.State == "error" {
		t.Fatalf("a move in flight parked the VM in error: %s", vm.StateDetail)
	}
	if st, _ := fake.DomainState("mv"); st == "running" {
		t.Fatal("the domain was started while the move ran")
	}
	if ms, _ := UnresolvedMovesOf(r.dataDir, "mv"); len(ms) != 1 {
		t.Fatalf("record: %+v", ms)
	}
}

// m-4, N-1, N-3, N2-1, N2-5: a host that does not hold the record honours it
// through the VM's condition, taking only a direction it can prove. A
// recorded pivot (or a catch-up) makes the copy complete: a start of a VM
// failed over here points a row on the source at the copy, but only when the
// copy is a regular file on a shared pool this host and the holder define
// alike. With no pivot recorded the commit and the pivot may both have
// happened and not replicated before the holder lost power: refused whatever
// the row names. The owner resolves the condition once every move is proven
// settled.
func TestResolveUnresolvedMoves_AnotherHostsRecord(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name                   string
		pivoted, catchUp       bool
		moveErr                string
		rowOnDst               bool
		rowHost                string
		hereDriver, originDrv  string
		symlink, originOther   bool
		wantErr                bool
		wantRowOnDst, resolved bool
	}{
		{name: "crash after the pivot, before it replicated: row on the copy, no pivot recorded: refused",
			rowOnDst: true, rowHost: "node-b", hereDriver: "nfs", originDrv: "nfs", wantErr: true, wantRowOnDst: true},
		{name: "power loss after the commit and the pivot, neither replicated: row on the source, no error: refused",
			rowHost: "node-b", hereDriver: "nfs", originDrv: "nfs", wantErr: true},
		{name: "no pivot recorded, row on the copy, row elsewhere: refused", rowOnDst: true, rowHost: "node-c", wantErr: true, wantRowOnDst: true},
		{name: "no pivot recorded, row on the source, the move recorded an error: refused", moveErr: "redefine failed", rowHost: "node-b", wantErr: true},
		{name: "pivoted, row on the source, failed over here, copy on a shared pool both define: row to the copy, resolved",
			pivoted: true, rowHost: "node-b", hereDriver: "nfs", originDrv: "nfs", wantRowOnDst: true, resolved: true},
		{name: "pivoted, row on the source, copy on a local pool here: refused",
			pivoted: true, rowHost: "node-b", hereDriver: "local", originDrv: "nfs", wantErr: true},
		{name: "pivoted, row on the source, the holder's pool of that name is local: refused",
			pivoted: true, rowHost: "node-b", hereDriver: "nfs", originDrv: "local", wantErr: true},
		{name: "pivoted, row on the source, the holder's pool of that name is another export: refused",
			pivoted: true, rowHost: "node-b", hereDriver: "nfs", originDrv: "nfs", originOther: true, wantErr: true},
		{name: "pivoted, row on the source, the copy is a symlink: refused",
			pivoted: true, rowHost: "node-b", hereDriver: "nfs", originDrv: "nfs", symlink: true, wantErr: true},
		{name: "catch-up, row on the source, failed over here, copy on a shared pool: row to the copy",
			catchUp: true, rowHost: "node-b", hereDriver: "nfs", originDrv: "nfs", wantRowOnDst: true, resolved: true},
		{name: "pivoted, row on the copy, owner here: passes and resolved", pivoted: true, rowOnDst: true, rowHost: "node-b", wantRowOnDst: true, resolved: true},
		{name: "pivoted, row on the copy, owner elsewhere: passes, left open", pivoted: true, rowOnDst: true, rowHost: "node-c", wantRowOnDst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			originDir := t.TempDir()
			_, src, dst := seedMovedVM(t, db, originDir, "dst", true, tc.pivoted)
			if tc.symlink {
				real := dst + ".real"
				if err := os.Rename(dst, real); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(real, dst); err != nil {
					t.Fatal(err)
				}
			}
			ms, _ := UnresolvedMovesOf(originDir, "mv")
			ms[0].CatchUp, ms[0].Error = tc.catchUp, tc.moveErr
			if tc.catchUp {
				ms[0].Live = false
			}
			if tc.originDrv != "" {
				ms[0].DstType = tc.originDrv
			}
			if err := RecordUnresolvedMove(originDir, ms[0]); err != nil {
				t.Fatal(err)
			}
			if err := PublishUnresolvedMoves(ctx, db, originDir, "node-a", "mv"); err != nil {
				t.Fatal(err)
			}
			for host, drv := range map[string]string{"node-b": tc.hereDriver, "node-a": tc.originDrv} {
				if drv == "" {
					continue
				}
				target := filepath.Dir(dst)
				if host == "node-a" && tc.originOther {
					target = "/srv/other-export"
				}
				if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: host, Name: "warm",
					Driver: drv, Target: target}); err != nil {
					t.Fatal(err)
				}
			}
			row := src
			if tc.rowOnDst {
				row = dst
			}
			if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", tc.rowHost, row, "local", "hot"); err != nil {
				t.Fatal(err)
			}
			if err := db.Execute(ctx, `UPDATE vms SET host_name = ? WHERE name = 'mv'`, tc.rowHost); err != nil {
				t.Fatal(err)
			}
			err := ResolveUnresolvedMoves(ctx, db, t.TempDir(), "node-b", "mv", MoveDomain{})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want refused=%v", err, tc.wantErr)
			}
			if err != nil && (!IsMoveUnresolved(err) || !strings.Contains(err.Error(), "node-a") ||
				!strings.Contains(err.Error(), "lv health resolve "+MoveUnresolvedCode+" vm/mv")) {
				t.Fatalf("refusal does not name the holder and the operator exit: %v", err)
			}
			want := src
			if tc.wantRowOnDst {
				want = dst
			}
			if got := movedRowPath(t, db); got != want {
				t.Fatalf("row names %s, want %s", got, want)
			}
			if got := !MoveConditionCovers(ctx, db, "mv", "root"); got != tc.resolved {
				t.Fatalf("condition resolved = %v, want %v", got, tc.resolved)
			}
		})
	}
}

// N2-6: a host that does not hold the VM's condition cannot publish over it:
// a move of another disk there is refused, and the holder and its entries stay.
func TestPublishUnresolvedMoves_NeverOverwritesAnotherHolder(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	aDir, bDir := t.TempDir(), t.TempDir()
	if err := RecordUnresolvedMove(aDir, UnresolvedMove{VM: "mv", Disk: "root", Src: "/a/root", Dst: "/b/root", Live: true}); err != nil {
		t.Fatal(err)
	}
	if err := PublishUnresolvedMoves(ctx, db, aDir, "node-a", "mv"); err != nil {
		t.Fatal(err)
	}
	if err := RecordUnresolvedMove(bDir, UnresolvedMove{VM: "mv", Disk: "data", Src: "/a/data", Dst: "/b/data", Live: true}); err != nil {
		t.Fatal(err)
	}
	err := PublishUnresolvedMoves(ctx, db, bDir, "node-b", "mv")
	if !IsMoveUnresolved(err) || !strings.Contains(err.Error(), "node-a holds") {
		t.Fatalf("want the publish refused, got %v", err)
	}
	_, ev, open, rerr := OpenMoveCondition(ctx, db, "mv")
	if rerr != nil || !open || ev.Host != "node-a" || len(ev.Moves) != 1 || ev.Moves[0].Disk != "root" {
		t.Fatalf("the holder's condition changed: %+v open=%v %v", ev, open, rerr)
	}
}

// N-2: the holder that comes back while the VM's row names another host and
// the move is not proven settled drops its record but keeps the condition.
func TestPublishUnresolvedMoves_HolderKeepsAnUnsettledEntry(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	_, _, dst := seedMovedVM(t, db, dir, "dst", true, false)
	if err := PublishUnresolvedMoves(ctx, db, dir, "node-a", "mv"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", "node-b", dst, "local", "warm"); err != nil {
		t.Fatal(err)
	}
	err := ResolveUnresolvedMoves(ctx, db, dir, "node-a", "mv", MoveDomain{})
	if err == nil || !IsMoveUnresolved(err) {
		t.Fatalf("want the holder's own remote rule to refuse, got %v", err)
	}
	if ms, _ := UnresolvedMovesOf(dir, "mv"); len(ms) != 0 {
		t.Fatalf("the stale record was kept: %+v", ms)
	}
	if !MoveConditionCovers(ctx, db, "mv", "root") {
		t.Fatal("the holder resolved a condition its new owner has not settled")
	}
	// Publishing with no record left here (as a later move of another disk
	// does) keeps the entry too.
	if err := PublishUnresolvedMoves(ctx, db, dir, "node-a", "mv"); err != nil {
		t.Fatal(err)
	}
	if !MoveConditionCovers(ctx, db, "mv", "root") {
		t.Fatal("publishing without the record dropped an unsettled entry")
	}
}

// N-5: a holder whose records are gone (a lost data dir) honours its own
// condition by the remote rule instead of resolving it.
func TestResolveUnresolvedMoves_LostRecordsKeepTheCondition(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	_, _, dst := seedMovedVM(t, db, dir, "dst", true, false)
	if err := PublishUnresolvedMoves(ctx, db, dir, "node-a", "mv"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", "node-a", dst, "local", "warm"); err != nil {
		t.Fatal(err)
	}
	if err := ClearUnresolvedMovesOf(dir, "mv"); err != nil {
		t.Fatal(err)
	}
	if err := ResolveUnresolvedMoves(ctx, db, dir, "node-a", "mv", MoveDomain{}); err == nil {
		t.Fatal("a lost record let the start boot a copy that may lack the guest's last writes")
	}
	if !MoveConditionCovers(ctx, db, "mv", "root") {
		t.Fatal("the condition was resolved")
	}
}

// N-6: the refusal is recognised through wrapping and over the wire, and an
// unreadable condition refuses as a defect, not as a transient state.
func TestMoveUnresolvedError_Recognition(t *testing.T) {
	base := &MoveUnresolvedError{VM: "mv", Disk: "root", Detail: "x"}
	wrapped := fmt.Errorf("migrate mv/root: %w", base)
	wire := status.FromProto(status.Convert(wrapped).Proto()).Err()
	for _, err := range []error{base, wrapped, wire} {
		if !IsMoveUnresolved(err) || MoveUnresolvedRetryable(err) {
			t.Fatalf("not recognised: %v", err)
		}
	}
	if !MoveUnresolvedRetryable(status.FromProto(status.Convert(fmt.Errorf("w: %w", &MoveUnresolvedError{Retryable: true})).Proto()).Err()) {
		t.Fatal("retryable lost on the wire")
	}
	if IsMoveUnresolved(status.Error(codes.FailedPrecondition, "move-unresolved: forged text")) {
		t.Fatal("recognised by its text")
	}

	ctx := context.Background()
	db := testReconcilerDB(t)
	if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{Evaluator: MoveUnresolvedEvaluator,
		Code: MoveUnresolvedCode, SubjectKind: "vm", SubjectID: "mv", Lifecycle: corrosion.ConditionConfirmed, Evidence: "{"}); err != nil {
		t.Fatal(err)
	}
	err := ResolveUnresolvedMoves(ctx, db, t.TempDir(), "node-a", "mv", MoveDomain{})
	if !IsMoveUnresolved(err) || MoveUnresolvedRetryable(err) || !strings.Contains(err.Error(), "lv health resolve") {
		t.Fatalf("want a non-transient refusal naming the exit, got %v", err)
	}
}

// ForgetUnresolvedMoves (delete, rebuild, and a new VM taking the name) drops
// the records here and resolves the condition whichever host raised it.
func TestForgetUnresolvedMoves_ClearsRecordsAndCondition(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	seedMovedVM(t, db, dir, "dst", true, false)
	if err := PublishUnresolvedMoves(ctx, db, dir, "node-a", "mv"); err != nil {
		t.Fatal(err)
	}
	if !MoveConditionCovers(ctx, db, "mv", "root") {
		t.Fatal("not published")
	}
	if err := ForgetUnresolvedMoves(ctx, db, t.TempDir(), "mv"); err != nil {
		t.Fatal(err)
	}
	if MoveConditionCovers(ctx, db, "mv", "root") {
		t.Fatal("condition left open")
	}
	if err := ForgetUnresolvedMoves(ctx, db, dir, "mv"); err != nil {
		t.Fatal(err)
	}
	if ms, _ := UnresolvedMovesOf(dir, "mv"); len(ms) != 0 {
		t.Fatalf("records left: %+v", ms)
	}
}
