// Fleet scenario: a replica held by a witness.
//
// A replication schedule accepts any host as its target, a witness included,
// and after the owner is lost the witness may hold the only copy of a VM's
// disk. Promoting there takes the VM over without starting it (a witness runs
// no workloads), and the VM then leaves by the way out of a witness: a cold
// migration to a worker, after which it starts. An AUTOMATIC promotion never
// lands there: the failover coordinator holds the VM down, loudly.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

type witnessReplica struct {
	c       *Cluster
	a, w, b *Node
	root    string // the disk's recorded path
	payload []byte
}

// newWitnessReplica is db on a with a host-local disk, replicated to the
// witness w; a is then lost (fenced by a fence that proves nothing).
func newWitnessReplica(t *testing.T) *witnessReplica {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	c.openClusterPolicyGate()
	t.Cleanup(c.Stop)
	latchPITOverlay(t, c)
	a, w, b := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		n.Server.SetHostDiskRootForTest(filepath.Join(c.tmpRoot, "fs-"+n.Name))
	}
	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: w.Name, Role: "witness"}); err != nil {
		t.Fatalf("make %s a witness: %v", w.Name, err)
	}
	pool := filepath.Join(c.tmpRoot, "dr")
	disks := filepath.Join(c.tmpRoot, "disks")
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{w, b} {
		if err := corrosion.UpsertStoragePool(ctx, n.DB, corrosion.StoragePoolRecord{
			HostName: n.Name, Name: "dr", Driver: "dir", Target: pool, State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	wr := &witnessReplica{c: c, a: a, w: w, b: b, root: filepath.Join(disks, "db-root.qcow2")}
	// A qcow2 whose bytes are checkable end to end after every copy.
	fsRoot := filepath.Join(c.tmpRoot, "fs-"+a.Name, wr.root)
	if err := os.MkdirAll(filepath.Dir(fsRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(fsRoot, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	var rerr error
	if wr.payload, rerr = os.ReadFile(fsRoot); rerr != nil {
		t.Fatal(rerr)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "db", Cpu: 1, MemoryMib: 256, Onboot: true, OnHostFailure: "restart-any",
		Labels: map[string]string{corrosion.LabelAutoPromoteNotPointInTime: "true"}})
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "db", HostName: a.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "db", DiskName: "root", HostName: a.Name, Path: wr.root, SizeBytes: int64(len(wr.payload)), StorageType: "local", TargetDev: "vda", Bus: "virtio"},
	}); err != nil {
		t.Fatal(err)
	}
	a.Virt.SetState("db", libvirtfake.StateRunning)
	sched := corrosion.BackupScheduleRecord{VMName: "db", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: w.Name, KeepReplicas: 1, AutoPromote: true}
	if err := corrosion.UpsertBackupSchedule(ctx, a.DB, sched); err != nil {
		t.Fatal(err)
	}
	if err := a.Server.RunReplication(ctx, sched, time.Now().Add(-10*time.Minute)); err != nil {
		t.Fatalf("replicate db to the witness: %v", err)
	}
	return wr
}

// loseOwner fences a by a fence that proves nothing.
func (wr *witnessReplica) loseOwner(t *testing.T) {
	t.Helper()
	if err := corrosion.RecordFenceWithState(context.Background(), wr.a.DB, corrosion.FenceLogRecord{ID: "ssh-" + wr.a.Name, HostName: wr.a.Name,
		Method: "ssh", Result: "fenced", Detail: "poweroff sent"}, "fenced"); err != nil {
		t.Fatal(err)
	}
	wr.c.WaitConverged(t, convergeTimeout)
}

func (wr *witnessReplica) promote(t *testing.T) (string, error) {
	t.Helper()
	return wr.promoteVia(t, wr.w, "")
}

// promoteVia sends the operator's promote to entry, which relays it to the
// witness when entry is not the witness.
func (wr *witnessReplica) promoteVia(t *testing.T, entry *Node, newName string) (string, error) {
	t.Helper()
	st, err := wr.c.SelfClient(entry).PromoteReplica(context.Background(), &pb.PromoteReplicaRequest{
		VmName: "db", TargetHost: wr.w.Name, TargetPool: "dr", Force: true, AcceptNotPointInTime: true, NewName: newName,
	})
	if err != nil {
		return "", err
	}
	last := ""
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			return last, nil
		}
		if rerr != nil {
			return last, rerr
		}
		last = p.GetStatus()
	}
}

// The recovery: the promote takes db over on the witness, defined and stopped
// (the VM is never started there), and says how to move it; the cold migration
// off the witness and the start on the worker then work, with the disk intact.
//
// Red on f04bc6725: the promote on the witness is refused local_not_active_worker
// (the execution gate), so the only copy of the disk could not be recovered.
//
// Mutations: start the domain in witnessPromote mode - the not-active check
// goes red; drop the witnessPromote gate swap (execGateForAction back) - the
// promote is refused; drop the evacuating-witness branch - the move off is
// refused.
func TestFleet_AReplicaOnAWitnessIsPromotedStoppedAndMovedToAWorker(t *testing.T) {
	wr := newWitnessReplica(t)
	ctx := context.Background()
	enforceGateWithWitness(t, wr.c, wr.w)
	wr.loseOwner(t)

	done, err := wr.promote(t)
	if err != nil {
		t.Fatalf("operator promote on the witness: %v", err)
	}
	for _, want := range []string{"NOT started", wr.w.Name, "lv migrate db " + wr.b.Name + " --cold", "lv start db"} {
		if !strings.Contains(done, want) {
			t.Errorf("the promote's final status %q does not say %q", done, want)
		}
	}
	vm, _ := corrosion.GetVM(ctx, wr.b.DB, "db")
	if vm == nil || vm.HostName != wr.w.Name || vm.State != "stopped" {
		t.Fatalf("db after the promote = %+v, want it stopped on %s", vm, wr.w.Name)
	}
	if !wr.w.Virt.DomainExists("db") {
		t.Fatalf("db is not defined on the witness")
	}
	if active, _ := wr.w.Virt.DomainIsActive("db"); active {
		t.Fatalf("db was started on the witness")
	}
	disks, _ := corrosion.GetVMDisks(ctx, wr.b.DB, "db")
	if len(disks) != 1 || disks[0].HostName != wr.w.Name {
		t.Fatalf("db's disk rows = %+v, want one on %s", disks, wr.w.Name)
	}
	diskPath := disks[0].Path
	// The promoted disk's pool is a disk-artifact root on the worker too.
	for _, n := range []*Node{wr.w, wr.b} {
		n.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"dr": {Driver: "dir", Target: filepath.Dir(diskPath)}})
	}

	// The harness maps a disk's recorded path under each node's own root
	// (SetHostDiskRootForTest) for a migration but not for a pool's files, so
	// the promoted file is put where the witness's migration reads it.
	mapped := filepath.Join(wr.c.tmpRoot, "fs-"+wr.w.Name, diskPath)
	if err := os.MkdirAll(filepath.Dir(mapped), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(diskPath, mapped); err != nil {
		t.Fatal(err)
	}
	// It starts nowhere on the witness...
	if _, err := wr.c.SelfClient(wr.w).StartVM(ctx, &pb.StartVMRequest{Name: "db"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start on the witness: got %v, want it refused", err)
	}
	// ...and leaves it for a worker.
	st, err := wr.c.SelfClient(wr.w).MigrateVM(ctx, &pb.MigrateVMRequest{VmName: "db", TargetHost: wr.b.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD})
	if err != nil {
		t.Fatalf("migrate off the witness: %v", err)
	}
	for {
		if _, rerr := st.Recv(); rerr == io.EOF {
			break
		} else if rerr != nil {
			t.Fatalf("migrate off the witness: %v", rerr)
		}
	}
	vm, _ = corrosion.GetVM(ctx, wr.b.DB, "db")
	if vm == nil || vm.HostName != wr.b.Name || vm.State != "stopped" {
		t.Fatalf("db after the move = %+v, want it stopped on %s", vm, wr.b.Name)
	}
	got, rerr := os.ReadFile(filepath.Join(wr.c.tmpRoot, "fs-"+wr.b.Name, diskPath))
	if rerr != nil || len(got) == 0 {
		t.Fatalf("the disk did not arrive on the worker (err %v, %d bytes)", rerr, len(got))
	}
	if _, err := wr.c.SelfClient(wr.b).StartVM(ctx, &pb.StartVMRequest{Name: "db"}); err != nil {
		t.Fatalf("start on the worker: %v", err)
	}
	if active, _ := wr.b.Virt.DomainIsActive("db"); !active {
		t.Errorf("db is not running on %s", wr.b.Name)
	}
}

// An automatic promotion whose replica is on a witness is held: it returns the
// held error the coordinator recognises (it keeps the VM down and audits the
// skip rather than rescheduling it onto a host without the disk), records an
// event naming the steps, and touches nothing.
//
// Mutation: drop the automated branch in promoteResolvedIn - the promote goes
// ahead on the witness and this goes red.
func TestFleet_AnAutomaticPromotionOntoAWitnessIsHeld(t *testing.T) {
	wr := newWitnessReplica(t)
	ctx := context.Background()
	wr.loseOwner(t)
	err := wr.b.Server.AutoPromoteReplica(ctx, "db", "", 0)
	if err == nil || !errors.Is(err, corrosion.ErrPromoteHeld) {
		t.Fatalf("auto-promote with the replica on a witness: got %v, want an ErrPromoteHeld hold", err)
	}
	for _, want := range []string{wr.w.Name, "witness", "lv migrate db", "--cold"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the hold %q does not say %q", err, want)
		}
	}
	if wr.w.Virt.DomainExists("db") {
		t.Errorf("a domain was defined on the witness by the held promotion")
	}
	if vm, _ := corrosion.GetVM(ctx, wr.b.DB, "db"); vm == nil || vm.HostName != wr.a.Name {
		t.Errorf("the held promotion moved the VM row: %+v", vm)
	}
}
