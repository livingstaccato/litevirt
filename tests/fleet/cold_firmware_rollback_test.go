// Fleet scenarios for the rollback of a cold firmware migration that fails
// after the target has defined the VM's domain and before the ownership
// handoff commits.
//
// The target defines the domain (EnsureFirmwareState) before the handoff. A
// request cancelled in between used to leave that domain defined there, and
// the retry was refused over "already-defined domain". The target now records
// the domain it defines under the source's attempt id, and the source rolls
// back only that attempt's domain (RollbackFirmwareState). A domain the target
// held before the attempt is never taken.
//
// internal/grpcapi pins the same contract with two Servers joined in process
// (migrate_firmware_rollback_test.go). These run it over real gRPC between two
// daemons, where the cancellation is the client's own, carried from the CLI's
// stream to the source and from the source's call to the target.

package fleet

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// migrateColdCtx is migrateCold on the caller's context.
func (sc *coldStoppedScenario) migrateColdCtx(ctx context.Context) error {
	st, err := sc.c.SelfClient(sc.src).MigrateVM(ctx, &pb.MigrateVMRequest{
		VmName: "os1", TargetHost: sc.dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); errors.Is(rerr, io.EOF) {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}

// waitReturned waits for the source's MigrateVM handler to return, so what
// it does after the client went away (the rollback) has happened.
func waitReturned(t *testing.T, w *StreamWatch) {
	t.Helper()
	select {
	case <-w.Returned:
	case <-time.After(30 * time.Second):
		t.Fatal("the source's MigrateVM handler did not return")
	}
}

// assertSourceKeepsFirmwareVM: os1 is still the source's, stopped, with its
// domain, its vars and its disk.
func (sc *coldStoppedScenario) assertSourceKeepsFirmwareVM(t *testing.T, vars []byte) {
	t.Helper()
	if vm := sc.vm(t); vm.HostName != sc.src.Name {
		t.Errorf("os1 row names %s after a failed attempt, want the source %s", vm.HostName, sc.src.Name)
	}
	if !sc.src.Virt.DomainExists("os1") {
		t.Errorf("os1's domain is gone from the source %s", sc.src.Name)
	}
	if got, err := os.ReadFile(sc.nvram(sc.src)); err != nil || string(got) != string(vars) {
		t.Errorf("os1's UEFI vars on the source = %q (err %v), want them intact", got, err)
	}
	if got, err := os.ReadFile(sc.file(sc.src, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("os1's disk on the source is not intact (err %v)", err)
	}
}

// The client cancels a cold migration of a stopped Secure Boot VM after the
// target has defined its domain, and the target's answer is lost to the
// cancellation. The target's domain and the vars this attempt wrote there are
// taken back, the VM stays on the source, and the retry migrates it.
//
// Mutation: abandonFirmwareTarget returns the cause without asking the target
// to roll back — the domain stays defined on the target, and the retry is
// refused over "already-defined domain".
func TestFleet_CancelledColdFirmwareMigrationIsRolledBackAndRetried(t *testing.T) {
	sc := newColdStoppedScenario(t)
	vars := sc.makeSecureBoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var definedThere atomic.Bool
	sc.dst.HookUnary("EnsureFirmwareState", func(hctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(hctx, req)
		definedThere.Store(err == nil && sc.dst.Virt.DomainExists("os1"))
		// The client goes away now. Hold the answer until the cancellation
		// has reached this call, so the source never receives it.
		cancel()
		select {
		case <-hctx.Done():
		case <-time.After(10 * time.Second):
			t.Error("the client's cancellation never reached the target's EnsureFirmwareState")
		}
		return resp, err
	})
	watch := sc.src.WatchStream("MigrateVM")

	if err := sc.migrateColdCtx(ctx); err == nil {
		t.Fatal("a migration cancelled before its handoff reported success")
	}
	waitReturned(t, watch)
	if !definedThere.Load() {
		t.Fatal("the target did not define os1's domain before the cancellation; the scenario did not reach the rollback")
	}
	if sc.dst.Virt.DomainExists("os1") {
		t.Errorf("the target %s still defines os1's domain after the cancelled attempt", sc.dst.Name)
	}
	if _, err := os.Stat(sc.nvram(sc.dst)); !os.IsNotExist(err) {
		t.Errorf("the target %s still holds the vars this attempt wrote (stat: %v)", sc.dst.Name, err)
	}
	sc.assertSourceKeepsFirmwareVM(t, vars)

	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("retry after the cancelled attempt: %v", err)
	}
	sc.assertFirmwareVMMoved(t, vars)
}

// A domain named os1 is defined on the target, with its own vars, after the
// disk copy and before EnsureFirmwareState runs — by hand, or by anything else
// on the target. (One defined before the attempt is refused earlier, by the
// disk copy, before anything is defined.) EnsureFirmwareState refuses to
// define over it, the attempt fails, and the source's rollback leaves the
// target's domain and vars exactly as they were: this attempt did not create
// them.
//
// Mutation: RollbackFirmwareState skips its ownership check (the old
// undefine-whatever-is-there rollback) — the target's own domain is removed.
func TestFleet_FailedColdFirmwareMigrationLeavesATargetDomainItDidNotCreate(t *testing.T) {
	sc := newColdStoppedScenario(t)
	vars := sc.makeSecureBoot(t)

	const theirs = `<domain type='kvm'><name>os1</name><uuid>` + fwUUID + `</uuid><description>theirs</description></domain>`
	targetVars := []byte("the target's own vars")
	var ensureReached, rollbackReached atomic.Bool
	sc.dst.HookUnary("EnsureFirmwareState", func(hctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		ensureReached.Store(true)
		if err := sc.dst.Virt.DefineDomain(theirs); err != nil {
			t.Errorf("define the target's own os1: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(sc.nvram(sc.dst)), 0o755); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(sc.nvram(sc.dst), targetVars, 0o600); err != nil {
			t.Error(err)
		}
		return handler(hctx, req)
	})
	sc.dst.HookUnary("RollbackFirmwareState", func(hctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		rollbackReached.Store(true)
		return handler(hctx, req)
	})
	watch := sc.src.WatchStream("MigrateVM")

	err := sc.migrateColdCtx(context.Background())
	if err == nil {
		t.Fatal("migrating onto a target that defines os1 reported success")
	}
	waitReturned(t, watch)
	if !ensureReached.Load() || !rollbackReached.Load() {
		t.Fatalf("EnsureFirmwareState reached=%v, RollbackFirmwareState reached=%v (err %v); the scenario did not exercise the rollback",
			ensureReached.Load(), rollbackReached.Load(), err)
	}
	if x, err := sc.dst.Virt.DumpXML("os1"); err != nil || !strings.Contains(x, "theirs") {
		t.Errorf("the target's own os1 domain was removed or replaced (err %v): %s", err, x)
	}
	if got, err := os.ReadFile(sc.nvram(sc.dst)); err != nil || string(got) != string(targetVars) {
		t.Errorf("the target's own vars = %q (err %v), want them untouched", got, err)
	}
	sc.assertSourceKeepsFirmwareVM(t, vars)
}
