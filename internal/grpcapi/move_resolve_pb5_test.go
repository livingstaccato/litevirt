package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// m9-1: migrateOwnedVM's choice of how a held VM's forked history binds it.
// A running domain migrated live without storage carries the files it has
// open and passes the hold (the condition stays open); with storage, or with
// the domain shut off, it is held.
func TestMigrateOwnedVM_ForkedHistoryHoldByMode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		withStorage bool
		running     bool
		held        bool
	}{
		{name: "running, without storage", running: true},
		{name: "running, with storage", running: true, withStorage: true, held: true},
		{name: "shut off, without storage", held: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, dst := forkedMoveServer(t, "node-a", 3, 4, "dst", tc.running)
			ctx, cancel := context.WithTimeout(adminCtx(), 30*time.Second)
			defer cancel()
			if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dst, "nfs", "warm"); err != nil {
				t.Fatal(err)
			}
			vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
			adopted := false
			err := s.migrateOwnedVM(ctx, &pb.MigrateVMRequest{VmName: "vm1", TargetHost: "other", WithStorage: tc.withStorage}, vm,
				func(pb.MigratePhase, float32, float32) error { return nil }, func() {}, &adopted, ownedMigrateOpts{})
			if health.IsMoveUnresolved(err) != tc.held {
				t.Fatalf("err = %v, want held=%v", err, tc.held)
			}
			if !health.MoveConditionCovers(context.Background(), s.db, "vm1", "root") {
				t.Fatal("the condition was closed")
			}
		})
	}
}

// m9-2: on a forked history, keeping the copy discards what was written to
// the source since the VM changed hands. With the source the later file,
// `--accept <copy>` is refused unless --force, which is audited.
func TestResolveHealthCondition_AcceptOfTheCopyWithTheSourceLater(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		force bool
		ok    bool
	}{
		{name: "refused without --force"},
		{name: "--force", force: true, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, src, dst := forkedMoveServer(t, "node-a", 3, 4, "", false) // the source is the later file
			rctx := acceptCtx(dst)
			if tc.force {
				rctx = forceCtx(dst)
			}
			_, err := s.ResolveHealthCondition(rctx, moveResolveReq("keep the holder's writes"))
			if !tc.ok {
				mustRefuse(t, s, err, src, "--force", "modified", "lv events vm1")
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if r := diskRowOf(t, s, "root"); r.Path != dst {
				t.Fatalf("row = %+v, want the copy", r)
			}
			rows, qerr := s.db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.hand_diverged'`)
			if qerr != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "--force") {
				t.Fatalf("divergence audit = %+v %v, want the forced keep of the copy", rows, qerr)
			}
		})
	}
}

// m9-4: with the domain running, the file kept is the one the running guest
// has open, whatever its persistent config and the row name.
func TestResolveHealthCondition_RunningDomainKeepsOnlyItsLiveDisk(t *testing.T) {
	ctx := context.Background()
	s, src, dst := forkedMoveServer(t, "node-a", 3, 4, "src", true)
	fakeOf(t, s).SetActiveXML("vm1", fakeDomainXML("vm1", "vda", dst))
	_, err := s.ResolveHealthCondition(acceptCtx(src), moveResolveReq("x"))
	mustRefuse(t, s, err, src, "lv stop vm1", dst)
	if !health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
		t.Fatal("the condition was closed")
	}
}

// m9-3: a promotion's start leaves the vm.starting event too.
func TestPromoteReplica_StartRecordsTheStartEvent(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.virt = libvirtfake.New()
	ctx := adminCtx()
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}}})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	seedReplica(t, poolDir, "", "vm1", "root", "20260101-000000", "raw", 1<<20)
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-promoted", TargetPool: "replica-pool", NoLocalize: true,
	}, stream); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, "vm1-promoted", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Type == health.StartingEventType && e.HostName == "test-host" {
			return
		}
	}
	t.Fatalf("no %s event for the promoted VM: %+v", health.StartingEventType, evs)
}
