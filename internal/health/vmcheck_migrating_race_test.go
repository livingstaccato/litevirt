package health

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// raceBackend is a libvirt fake whose DestroyDomain first runs onDestroy:
// the write of another actor that lands between the checker's read of the
// row and its destroy.
type raceBackend struct {
	*libvirtfake.Fake
	onDestroy func()
}

func (b *raceBackend) DestroyDomain(name string) error {
	if b.onDestroy != nil {
		b.onDestroy()
	}
	return b.Fake.DestroyDomain(name)
}

// destroys is how many destroys of name the fake recorded.
func destroys(f *libvirtfake.Fake, name string) int {
	n := 0
	for _, e := range f.EventLog() {
		if e.Op == "destroy" && e.Domain == name {
			n++
		}
	}
	return n
}

// migratingRefusal is what the start guard answers for a row recorded
// migrating (grpcapi.movingVMStartRefusal).
func migratingRefusal(context.Context, *corrosion.VMRecord) (func(), error) {
	return func() {}, status.Error(codes.FailedPrecondition, `start "web" refused: its record says migrating`)
}

// runningWebChecker is a checker on node1 with web recorded running there,
// its domain defined and running in the fake, and a restart health action.
func runningWebChecker(t *testing.T) (*VMChecker, *libvirtfake.Fake, *corrosion.Client, *pb.HealthCheckSpec) {
	t.Helper()
	db := testCheckVMDB(t)
	hspec := &pb.HealthCheckSpec{Type: "exec", Action: "restart"}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Healthcheck: hspec})
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name: "web", HostName: "node1", State: "running", Spec: string(spec),
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	if err := fake.DefineDomain(`<domain type='kvm'><name>web</name><uuid>44444444-4444-4555-8666-777777777777</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	fake.SetState("web", libvirtfake.StateRunning)
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	v.SetBackend(fake)
	return v, fake, db, hspec
}

func rowOf(t *testing.T, db *corrosion.Client, name string) *corrosion.VMRecord {
	t.Helper()
	row, err := corrosion.GetVM(context.Background(), db, name)
	if err != nil || row == nil {
		t.Fatalf("GetVM %s: %+v %v", name, row, err)
	}
	return row
}

// A move starts between the checker's read of a running row and its
// destroy: the row says migrating by the time the start guard refuses the
// restart. The refusal must not be recorded over the move's state — an
// `error` row is startable, and the guard would no longer protect it.
//
// Mutation: the error write made unconditional — the row reads error, red.
func TestTakeAction_RestartDoesNotOverwriteARowThatWentMigrating(t *testing.T) {
	v, fake, db, hspec := runningWebChecker(t)
	v.SetBackend(&raceBackend{Fake: fake, onDestroy: func() {
		if err := corrosion.UpdateVMState(context.Background(), db, "web", "migrating", "→ node2"); err != nil {
			t.Error(err)
		}
	}})
	v.SetHardwareStartPreparer(migratingRefusal)
	v.takeAction(context.Background(), corrosion.VMRecord{Name: "web", HostName: "node1", State: "running"}, hspec)
	if row := rowOf(t, db, "web"); row.State != "migrating" {
		t.Fatalf("web after the refused restart = %s (%s); want the move's migrating left alone", row.State, row.StateDetail)
	}
}

// The checker's restart runs under the VM's lock — the lock a move, a start
// or a stop of the VM holds through the API — and reads the row again under
// it. A move that took the lock first and recorded migrating is seen there:
// nothing is destroyed and nothing is written. A lock another operation
// holds is not waited for: the restart is skipped this pass.
//
// Mutations: the lock not taken, or the row not read again under it — the
// domain is destroyed, red.
func TestTakeAction_RestartReadsTheRowUnderTheVMLock(t *testing.T) {
	t.Run("a move recorded migrating under the lock", func(t *testing.T) {
		v, fake, db, hspec := runningWebChecker(t)
		locked := false
		v.SetVMLocker(func(name string) (func(), bool) {
			locked = true
			if err := corrosion.UpdateVMState(context.Background(), db, "web", "migrating", "→ node2"); err != nil {
				t.Error(err)
			}
			return func() {}, true
		})
		v.SetHardwareStartPreparer(migratingRefusal)
		v.takeAction(context.Background(), corrosion.VMRecord{Name: "web", HostName: "node1", State: "running"}, hspec)
		if !locked {
			t.Fatal("the restart did not take the VM's lock")
		}
		if n := destroys(fake, "web"); n != 0 {
			t.Fatalf("web destroyed %d time(s) under a row that went migrating", n)
		}
		if row := rowOf(t, db, "web"); row.State != "migrating" {
			t.Fatalf("web = %s; want migrating", row.State)
		}
	})
	t.Run("the lock held by another operation", func(t *testing.T) {
		v, fake, db, hspec := runningWebChecker(t)
		v.SetVMLocker(func(string) (func(), bool) { return nil, false })
		v.takeAction(context.Background(), corrosion.VMRecord{Name: "web", HostName: "node1", State: "running"}, hspec)
		if n := destroys(fake, "web"); n != 0 {
			t.Fatalf("web destroyed %d time(s) while another operation holds its lock", n)
		}
		if row := rowOf(t, db, "web"); row.State != "running" {
			t.Fatalf("web = %s; want running, untouched", row.State)
		}
	})
}

// The restart policy's start, the same way: a cold move that handed the VM
// to another host between the checker's read and its destroy leaves a row
// that is no longer this host's, and the refused start is not recorded over
// it; one that took the lock first is seen under it, and nothing is
// destroyed.
//
// Mutations: the error write made unconditional — the other host's row reads
// error, red. The lock not taken, or the row not read again under it — the
// domain is destroyed, red.
func TestMaybeRestartVM_DoesNotActOnARowAnotherHostTookMeanwhile(t *testing.T) {
	crashed := func(t *testing.T) (*VMChecker, *libvirtfake.Fake, *corrosion.Client) {
		db := testStartDB(t)
		seedRestartPolicyVM(t, db, "web", "node1")
		fake := libvirtfake.New()
		if err := fake.DefineDomain(`<domain type='kvm'><name>web</name><uuid>44444444-4444-4555-8666-777777777777</uuid></domain>`); err != nil {
			t.Fatal(err)
		}
		v := NewVMChecker("node1", t.TempDir(), db, nil)
		v.SetBackend(fake)
		return v, fake, db
	}
	handedOff := func(db *corrosion.Client) {
		if err := corrosion.UpdateVMHost(context.Background(), db, "web", "node2", "stopped"); err != nil {
			panic(err)
		}
	}
	t.Run("handed off between the read and the destroy", func(t *testing.T) {
		v, fake, db := crashed(t)
		v.SetBackend(&raceBackend{Fake: fake, onDestroy: func() { handedOff(db) }})
		v.SetHardwareStartPreparer(func(context.Context, *corrosion.VMRecord) (func(), error) {
			return func() {}, errors.New("test: refused")
		})
		v.maybeRestartVM(context.Background(), *rowOf(t, db, "web"), time.Now())
		if row := rowOf(t, db, "web"); row.State != "stopped" || row.HostName != "node2" {
			t.Fatalf("web = %s on %s; want node2's stopped row left alone", row.State, row.HostName)
		}
	})
	t.Run("handed off under the lock", func(t *testing.T) {
		v, fake, db := crashed(t)
		v.SetVMLocker(func(string) (func(), bool) { handedOff(db); return func() {}, true })
		v.maybeRestartVM(context.Background(), *rowOf(t, db, "web"), time.Now())
		if n := destroys(fake, "web"); n != 0 {
			t.Fatalf("web destroyed %d time(s) after another host took it", n)
		}
		if row := rowOf(t, db, "web"); row.State != "stopped" || row.HostName != "node2" {
			t.Fatalf("web = %s on %s; want node2's stopped row left alone", row.State, row.HostName)
		}
	})
}
