// Fleet scenarios for a migrate --with-storage that is aborted part-way.
//
// Before the copy the source has the target pre-create what libvirt checks for:
// the disk stubs the block mirror writes into (EnsureDisks) and the guest's
// cloud-init ISO (EnsureCloudInit), and it holds a capacity lease on the target
// and the VM's lock on itself. However the attempt ends short of a cutover —
// the client goes away, the migrate timeout fires, the copy fails at either
// end — the guest never left the source, so every one of those has to be
// undone: the row back to `running` on the source, the target's stubs and ISO
// gone (only the ones it created), the lease released, the lock free.
//
// Multi-node by construction: the stubs and the ISO are on the target, made by
// its RPCs, and removed by a cleanup the source sends it over real gRPC.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// storageAbort is a two-node cluster with pp1 running on src and one
// host-local disk, ready to be migrated --with-storage to dst.
type storageAbort struct {
	c        *Cluster
	src, dst *Node
	// stub is the disk path the copy needs on dst. Host-local disks keep the
	// same path on every host; it is under dst's disks dir, the root EnsureDisks
	// may create in, and nothing is there until EnsureDisks makes the stub.
	stub string
	// iso is pp1's cloud-init ISO on dst; operatorISO what it held before the
	// migration (nil when dst had none, so the one there is the migration's).
	iso         string
	operatorISO []byte
	// migrate watches the source's MigrateVM handler, armed by start.
	migrate *StreamWatch
}

func newStorageAbort(t *testing.T, policy *pb.MigrationPolicy, targetHasISO bool) *storageAbort {
	t.Helper()
	// EnsureCloudInit shells out to genisoimage; the libvirt fake never reads
	// the ISO, so the stand-in's empty file is all it needs.
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	f := &storageAbort{c: c, src: c.Nodes[0], dst: c.Nodes[1]}
	f.stub = filepath.Join(c.tmpRoot, f.dst.Name, "data", "disks", "pp1-root.qcow2")
	f.iso = filepath.Join(c.tmpRoot, f.dst.Name, "data", "cloudinit", "pp1.iso")

	// The source's own ISO: without it the source asks the target for none.
	srcISO := filepath.Join(c.tmpRoot, f.src.Name, "data", "cloudinit", "pp1.iso")
	if err := os.MkdirAll(filepath.Dir(srcISO), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcISO, []byte("source iso"), 0o644); err != nil {
		t.Fatal(err)
	}
	if targetHasISO {
		f.operatorISO = []byte("an ISO the target already had")
		if err := os.MkdirAll(filepath.Dir(f.iso), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.iso, f.operatorISO, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	spec, err := json.Marshal(&pb.VMSpec{Name: "pp1", Cpu: 1, MemoryMib: 256, Migrate: policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), f.src.DB, corrosion.VMRecord{
		Name: "pp1", HostName: f.src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{
		VMName: "pp1", DiskName: "root", HostName: f.src.Name, Path: f.stub,
		SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	f.src.Virt.SetState("pp1", "running")
	f.src.Server.SetAllowUnencryptedStorageMigration(true)
	return f
}

// start begins the storage migration under ctx and returns where its end — the
// error the client sees — arrives.
func (f *storageAbort) start(t *testing.T, ctx context.Context) <-chan error {
	t.Helper()
	f.migrate = f.src.WatchStream("MigrateVM")
	st, err := f.c.SelfClient(f.src).MigrateVM(ctx, &pb.MigrateVMRequest{
		VmName: "pp1", TargetHost: f.dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE, WithStorage: true,
	})
	if err != nil {
		t.Fatalf("MigrateVM: %v", err)
	}
	end := make(chan error, 1)
	go func() {
		for {
			if _, rerr := st.Recv(); rerr == io.EOF {
				end <- nil
				return
			} else if rerr != nil {
				end <- rerr
				return
			}
		}
	}()
	return end
}

// holdCopy makes the source's libvirt migration block once it has started —
// the disks are being copied — until the returned func ends it with err.
func (f *storageAbort) holdCopy() (copying <-chan struct{}, end func(error)) {
	started := make(chan struct{})
	result := make(chan error, 1)
	f.src.Virt.FailMigrateToTarget = func(string, string) error {
		close(started)
		return <-result
	}
	return started, func(err error) { result <- err }
}

// awaitAbort fails the test if ch does not deliver within the bound.
func awaitAbort[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

// requireTargetPrepared fails unless the target holds what the copy needs —
// so a scenario that aborts "mid-copy" really aborts with something to undo.
func (f *storageAbort) requireTargetPrepared(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(f.stub); err != nil {
		t.Fatalf("the target holds no disk stub during the copy (%v); the scenario has nothing to undo", err)
	}
	if f.operatorISO == nil {
		if _, err := os.Stat(f.iso); err != nil {
			t.Fatalf("the target holds no cloud-init ISO during the copy (%v); the scenario has nothing to undo", err)
		}
	}
}

// requireLockFree waits for pp1's per-VM lock on the source to be free and
// fails if it never is. It doubles as the barrier for an adopted migration,
// whose background finish releases the lock last.
//
// The probe is a migration to a host that does not exist: it takes the lock
// first and is refused straight after, touching nothing. A lock still held
// leaves it blocked until its deadline.
func (f *storageAbort) requireLockFree(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := f.c.SelfClient(f.src).MigrateVM(ctx, &pb.MigrateVMRequest{
		VmName: "pp1", TargetHost: "no-such-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE, WithStorage: true,
	})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
	}
	if status.Code(err) == codes.DeadlineExceeded {
		t.Fatal("pp1's lock on the source is still held after the aborted migration; " +
			"every later stop, delete, snapshot or migrate of it blocks")
	}
	if err == nil || err == io.EOF {
		t.Fatal("a migration to a host that does not exist succeeded; the lock probe proves nothing")
	}
}

// requireUndone asserts the attempt left nothing behind: the guest on the
// source and its row saying so, the target's stub and ISO gone unless the
// target already had them, and the target's capacity lease released.
func (f *storageAbort) requireUndone(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	vm, err := corrosion.GetVM(ctx, f.src.DB, "pp1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	if vm.State != "running" || vm.HostName != f.src.Name {
		t.Errorf("after the abort pp1 is %q on %q, want running on %s — the guest never left, and "+
			"nothing heals `migrating`", vm.State, vm.HostName, f.src.Name)
	}
	if st, _ := f.src.Virt.DomainState("pp1"); st != "running" {
		t.Errorf("the guest is %q on the source, want running", st)
	}
	if f.dst.Virt.DomainExists("pp1") {
		t.Error("the target has a pp1 domain after a migration that never cut over")
	}
	if _, err := os.Stat(f.stub); !os.IsNotExist(err) {
		t.Errorf("the disk stub this migration created on the target is still there (stat: %v)", err)
	}
	got, err := os.ReadFile(f.iso)
	switch {
	case f.operatorISO != nil && err != nil:
		t.Errorf("the cloud-init ISO the target already had is gone after the abort: %v", err)
	case f.operatorISO != nil && !bytes.Equal(got, f.operatorISO):
		t.Errorf("the cloud-init ISO the target already had was replaced: %q", got)
	case f.operatorISO == nil && !os.IsNotExist(err):
		t.Errorf("the cloud-init ISO this migration created on the target is still there (read: %v)", err)
	}
	if cpu, mem, err := corrosion.HostReserved(ctx, f.dst.DB, f.dst.Name); err != nil || cpu != 0 || mem != 0 {
		t.Errorf("the target still reserves cpu=%d mem=%d MiB for the aborted migration (err %v)", cpu, mem, err)
	}
}

// Each way a storage migration can end short of a cutover, once the target
// has been prepared, leaves the VM as it was and the target as it was.
//
// Mutations: drop the cleanup in the watched failure branch — "copy fails at
// the source" and "copy fails at the target" go red with the stub and ISO
// left. Drop it in the adopted failure branch — "client goes away mid-copy"
// and "migrate timeout mid-copy" go red. Drop the adopter's unlock — the lock
// probe goes red. Never find the domain running in the adopted branch, or in
// the watched one — the row is `error` and those points go red. Leave the
// target's capacity lease unreleased — every point goes red. Remove the ISO
// whoever made it — the "target already had an ISO" variants go red.
func TestFleet_AbortedStorageMigrationLeavesNothingBehind(t *testing.T) {
	type abortPoint struct {
		name   string
		policy *pb.MigrationPolicy
		// abort ends the held copy, given the client's cancel and the copy's end.
		abort func(t *testing.T, f *storageAbort, cancel context.CancelFunc, endCopy func(error))
	}
	points := []abortPoint{
		{
			// libvirt reports the copy failing on the source side.
			name: "copy fails at the source",
			abort: func(_ *testing.T, _ *storageAbort, _ context.CancelFunc, endCopy func(error)) {
				endCopy(errors.New("operation failed: migration of disk vda failed: Input/output error"))
			},
		},
		{
			// The target's end of the block mirror gives up — its disk filled.
			name: "copy fails at the target",
			abort: func(_ *testing.T, _ *storageAbort, _ context.CancelFunc, endCopy func(error)) {
				endCopy(errors.New("internal error: unable to execute QEMU command 'block-job-complete': " +
					"Could not write to the NBD export on the destination: No space left on device"))
			},
		},
		{
			// A Ctrl-C mid-copy: the migration is adopted and allowed to finish,
			// and here it then fails, which the adopter has to undo on its own.
			name: "client goes away mid-copy",
			abort: func(t *testing.T, f *storageAbort, cancel context.CancelFunc, endCopy func(error)) {
				cancel()
				awaitAbort(t, f.migrate.Returned, "the source's MigrateVM handler to return after the client went away")
				endCopy(errors.New("operation failed: migration job: unexpectedly failed"))
			},
		},
		{
			// timeout_sec is a policy on the operation: past it the job is
			// aborted, and libvirt's migration returns the abort.
			name:   "migrate timeout mid-copy",
			policy: &pb.MigrationPolicy{TimeoutSec: 1},
			abort: func(t *testing.T, f *storageAbort, _ context.CancelFunc, endCopy func(error)) {
				awaitAbort(t, f.migrate.Returned, "the migrate timeout to end the source's wait")
				if n := f.src.Virt.AbortedMigrations("pp1"); n != 1 {
					t.Fatalf("the migrate timeout aborted the libvirt job %d time(s), want 1", n)
				}
			},
		},
	}
	for _, p := range points {
		for _, targetHasISO := range []bool{false, true} {
			name := p.name
			if targetHasISO {
				name += ", target already had an ISO"
			}
			t.Run(name, func(t *testing.T) {
				f := newStorageAbort(t, p.policy, targetHasISO)
				copying, endCopy := f.holdCopy()
				f.src.Virt.OnAbortMigration = func(string) {
					endCopy(errors.New("operation aborted: migration job: canceled by client"))
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				end := f.start(t, ctx)

				awaitAbort(t, copying, "the copy to start")
				f.requireTargetPrepared(t)
				p.abort(t, f, cancel, endCopy)
				if err := awaitAbort(t, end, "the client's migration to end"); err == nil {
					t.Fatal("the migration succeeded; the scenario needs it to end short of a cutover")
				}

				f.requireLockFree(t)
				f.requireUndone(t)
			})
		}
	}
}

// A target that goes away mid-copy cannot be cleaned up by the source: the
// guest stays on the source and its row and lock are restored, but the stub
// stays on the target, which nothing retries removing. What keeps that from
// costing more than disk space is that the target recognises the stub as its
// own, so a retry once it is back reuses it instead of refusing it.
//
// Mutation: forget the target's record of the stub in EnsureDisks's reuse
// check (treat every existing file as foreign) — the retry is refused.
func TestFleet_StorageMigrationToATargetThatWentAwayMidCopy(t *testing.T) {
	f := newStorageAbort(t, nil, false)
	copying, endCopy := f.holdCopy()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	end := f.start(t, ctx)

	awaitAbort(t, copying, "the copy to start")
	f.requireTargetPrepared(t)
	f.c.SetLinkFault(f.src, f.dst, LinkFault{BlockAll: true})
	endCopy(errors.New("operation failed: migration job: Unable to read from socket: Connection reset by peer"))
	if err := awaitAbort(t, end, "the client's migration to end"); err == nil {
		t.Fatal("the migration succeeded; the scenario needs it to fail")
	}
	f.requireLockFree(t)

	vm, err := corrosion.GetVM(context.Background(), f.src.DB, "pp1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	if vm.State != "running" || vm.HostName != f.src.Name {
		t.Fatalf("pp1 is %q on %q, want running on %s", vm.State, vm.HostName, f.src.Name)
	}
	if st, _ := f.src.Virt.DomainState("pp1"); st != "running" {
		t.Fatalf("the guest is %q on the source, want running", st)
	}
	if _, err := os.Stat(f.stub); err != nil {
		t.Fatalf("the stub on the unreachable target is gone (%v); the scenario expected it left", err)
	}

	// The target is back; a retry reuses its own stub.
	f.c.SetLinkFault(f.src, f.dst, LinkFault{})
	f.src.Virt.FailMigrateToTarget = nil
	retry := f.start(t, context.Background())
	if err := awaitAbort(t, retry, "the retried migration"); err != nil {
		t.Fatalf("the retry after the target came back failed: %v", err)
	}
}
