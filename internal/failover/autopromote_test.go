package failover

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// fenceQuorum drives the health table so the coordinator fences `target`.
func fenceQuorum(t *testing.T, ctx context.Context, db *corrosion.Client, observers []string, target string) {
	t.Helper()
	for _, observer := range observers {
		ensureVoter(t, db, observer)
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			observer, target, offlineThreshold,
		); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}
}

func TestCoordinator_AutoPromote_SkipsReschedule(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// An auto_promote replication schedule for vm1.
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "good", KeepReplicas: 3,
		Incremental: true, AutoPromote: true,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}

	fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")

	prom := &dbPromoter{db: db, target: "promoted-host"}
	c := newTestCoordinator("coordinator", db)
	c.Promoter = prom
	c.run(ctx)

	if len(prom.promoted) != 1 || prom.promoted[0] != "vm1" {
		t.Fatalf("expected vm1 auto-promoted, got %v", prom.promoted)
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.HostName != "promoted-host" {
		t.Errorf("expected vm1 re-homed by promotion to 'promoted-host', got %+v", vm)
	}
}

// TestCoordinator_AutoPromote_FiresWithNonePolicy guards the ordering bug found
// in live f3 e2e: a `lv run` VM has no on_host_failure policy (defaults to
// "none"), and auto-promotion must still fire — it's an explicit DR opt-in that
// precedes the policy gate.
func TestCoordinator_AutoPromote_FiresWithNonePolicy(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	// Spec with NO on_host_failure (the lv run default) → policy "none".
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "good", AutoPromote: true,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}

	fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")

	prom := &dbPromoter{db: db, target: "promoted-host"}
	c := newTestCoordinator("coordinator", db)
	c.Promoter = prom
	c.run(ctx)

	if len(prom.promoted) != 1 || prom.promoted[0] != "vm1" {
		t.Fatalf("auto-promote must fire despite on_host_failure=none; got %v", prom.promoted)
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.HostName != "promoted-host" {
		t.Errorf("expected vm1 promoted to 'promoted-host', got %+v", vm)
	}
}

func TestCoordinator_AutoPromote_FiresForBackingUpVM(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	// backing-up blocks ordinary destructive operations while the host is
	// healthy, but once the host is fenced the in-flight backup is no longer a
	// reason to strand the workload. DR promotion is an explicit recovery path.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "backing-up",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "good", AutoPromote: true,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}

	fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")

	prom := &dbPromoter{db: db, target: "promoted-host"}
	c := newTestCoordinator("coordinator", db)
	c.Promoter = prom
	c.run(ctx)

	if len(prom.promoted) != 1 || prom.promoted[0] != "vm1" {
		t.Fatalf("backing-up VM should still be promoted after fencing, got %v", prom.promoted)
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.HostName != "promoted-host" {
		t.Errorf("expected backing-up VM promoted to 'promoted-host', got %+v", vm)
	}
}

func TestCoordinator_AutoPromote_FallsBackOnError(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "good", AutoPromote: true,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}

	fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")

	prom := &dbPromoter{db: db, fail: true}
	c := newTestCoordinator("coordinator", db)
	c.Promoter = prom
	c.run(ctx)

	// Promotion was attempted but failed → coordinator falls back to a bare
	// reschedule onto the healthy host.
	if len(prom.promoted) != 1 {
		t.Fatalf("expected one promotion attempt, got %v", prom.promoted)
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.HostName != "good" {
		t.Errorf("expected fallback reschedule to 'good', got %+v", vm)
	}
}

func TestCoordinator_NoAutoPromote_NormalReschedule(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Replication schedule WITHOUT auto_promote.
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "good", AutoPromote: false,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}

	fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")

	prom := &dbPromoter{db: db}
	c := newTestCoordinator("coordinator", db)
	c.Promoter = prom
	c.run(ctx)

	if len(prom.promoted) != 0 {
		t.Errorf("auto-promote should not fire without the flag, got %v", prom.promoted)
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.HostName != "good" {
		t.Errorf("expected normal reschedule to 'good', got %+v", vm)
	}
}

// dbPromoter is a test ReplicaPromoter that re-homes the VM record (mimicking a
// real promotion) unless fail is set.
type dbPromoter struct {
	db              *corrosion.Client
	target          string
	fail            bool
	failUnavailable bool // return a retryable grpc Unavailable (fence_epoch row not yet replicated)
	promoted        []string
	fenceEpochs     []string // fence_epoch passed for each promote (bind-to-fence assertion)
}

func (p *dbPromoter) AutoPromoteReplica(ctx context.Context, vmName, fenceEpoch string, leaseTerm int64) error {
	p.promoted = append(p.promoted, vmName)
	p.fenceEpochs = append(p.fenceEpochs, fenceEpoch)
	if p.failUnavailable {
		return status.Error(codes.Unavailable, "fence_epoch row not yet replicated")
	}
	if p.fail {
		return context.DeadlineExceeded
	}
	t := p.target
	if t == "" {
		t = "promoted-host"
	}
	return corrosion.UpdateVMHost(ctx, p.db, vmName, t, "running")
}

// TestCoordinator_AutoPromote_SkipsAStoppedVM: auto-promotion defines and
// starts the replica, so a stopped VM enrolled in it is not promoted — the
// stop is checked before auto-promote, and the VM stays on its failed host,
// stopped. A running VM enrolled the same way, on the same host, is promoted,
// so the test cannot pass because the coordinator never reached the loop.
//
// Mutation: remove the stopped check at the top of recoverWorkloads — the
// stopped VM is promoted (the write guard does not cover promotion) and the
// test goes red.
func TestCoordinator_AutoPromote_SkipsAStoppedVM(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	for name, state := range map[string]string{"stopped-vm": "stopped", "running-vm": "running"} {
		// A host-local disk, so the stopped VM is not one failover moves
		// still stopped (its disks would all have to be shared).
		disks := []corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: "bad",
			Path: "/var/lib/litevirt/disks/" + name + "-root", StorageType: "local"}}
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: name, HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: state,
			StateDetail: map[bool]string{true: "operator-stop"}[state == "stopped"],
		}, nil, disks); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
		if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
			VMName: name, Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
			Type: "replication", TargetPool: "dr", TargetHost: "good", AutoPromote: true,
		}); err != nil {
			t.Fatalf("UpsertBackupSchedule %s: %v", name, err)
		}
	}

	fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")

	prom := &dbPromoter{db: db, target: "promoted-host"}
	c := newTestCoordinator("coordinator", db)
	c.Promoter = prom
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if len(prom.promoted) != 1 || prom.promoted[0] != "running-vm" {
		t.Fatalf("promoted %v, want only running-vm", prom.promoted)
	}
	vm, _ := corrosion.GetVM(ctx, db, "stopped-vm")
	if vm == nil || vm.HostName != "bad" || vm.State != "stopped" || vm.PendingActionID != "" {
		t.Fatalf("stopped-vm = %+v, want it stopped on bad", vm)
	}
	if got := fm.vm[foKey(ActionReschedule, ResultSkipped, ErrStopped)]; got != 1 {
		t.Errorf("skipped-stopped VM metric = %d, want 1", got)
	}
	rows, err := db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'failover.skip' AND target = 'stopped-vm'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("failover.skip audit rows for stopped-vm = %d (err %v), want 1", len(rows), err)
	}
}
