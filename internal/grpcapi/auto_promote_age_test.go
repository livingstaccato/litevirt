package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedReplicaOfAge gives vmName a root disk, a replication schedule into a local
// "dr" pool, and one replica in that pool stamped `age` ago.
func seedReplicaOfAge(t *testing.T, s *Server, vmName string, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	src := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(src, []byte("live disk"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: vmName, HostName: "dead-host", State: "running", Spec: `{}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: vmName, HostName: "dead-host", DiskName: "root", Path: src, StorageType: "dir",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{
		VMName: vmName, Repo: "dr", Type: "replication", TargetPool: "dr",
		TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 3,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}
	dir := replicaPoolDir(t, s, "dr")
	ts := time.Now().Add(-age).UTC().Format("20060102-150405")
	name := vmName + "-root-" + ts + ".qcow2"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("replica"), 0o600); err != nil {
		t.Fatalf("write replica: %v", err)
	}
}

// Automatic promotion refuses a replica older than the bound.
//
// With no bound, a schedule that had been failing for days left a replica that
// was exactly as promotable as one from ten minutes ago. Failover would then
// replace a VM that was running on current data with a disk from last week and
// call it a recovery. The coordinator falls back to a plain reschedule on any
// promote error, so refusing here costs nothing that having no replica would
// not also cost.
func TestAutoPromote_RefusesAStaleReplica(t *testing.T) {
	s := testServer(t)
	seedReplicaOfAge(t, s, "db-1", 5*24*time.Hour)

	err := s.AutoPromoteReplica(context.Background(), "db-1", "")

	if !errors.Is(err, errReplicaTooOld) {
		t.Errorf("AutoPromoteReplica with a 5-day-old replica returned %v, want errReplicaTooOld", err)
	}
}

// A fresh replica is not refused by the age gate. It may still fail further on —
// there is no libvirt here — but not for being old. Without this, refusing
// every automatic promotion would pass the test above.
func TestAutoPromote_DoesNotRefuseAFreshReplicaForAge(t *testing.T) {
	s := testServer(t)
	seedReplicaOfAge(t, s, "db-2", 10*time.Minute)

	err := s.AutoPromoteReplica(context.Background(), "db-2", "")

	if errors.Is(err, errReplicaTooOld) {
		t.Errorf("a 10-minute-old replica was refused as too old: %v", err)
	}
}

// An operator can still promote an old replica deliberately. The bound is on
// AUTOMATIC promotion; a human who has looked at the replica's age and decided
// it is the best available is making a different decision.
func TestManualPromote_IsNotAgeBounded(t *testing.T) {
	s := testServer(t)
	seedReplicaOfAge(t, s, "db-3", 5*24*time.Hour)
	vm, err := corrosion.GetVM(context.Background(), s.db, "db-3")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}

	err = s.promoteResolved(context.Background(), &pb.PromoteReplicaRequest{VmName: "db-3", Force: true},
		vm, false /*automated*/, func(*pb.PromoteReplicaProgress) error { return nil })

	if errors.Is(err, errReplicaTooOld) {
		t.Errorf("a manual promotion was refused by the automatic age bound: %v", err)
	}
}

// A replica name whose stamp cannot be read is refused for automatic promotion:
// its age cannot be shown to be within the bound, and the check fails closed.
func TestReplicaTimestamp_ParsesFromTheEndAndFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		wantOK  bool
		wantErr bool
	}{
		// VM and disk names with dashes: the stamp must come from the end.
		{"web-prod-1-data-disk-20260923-110000.qcow2", true, false},
		{"web-1-root-20260923-110000.raw", true, false},
		{"web-1-root-20260920-110000.qcow2", true, true}, // 3 days old
		{"web-1-root-notatimestamp.qcow2", false, true},
		{"short.qcow2", false, true},
	}
	for _, c := range cases {
		_, ok := replicaTimestamp(c.name)
		if ok != c.wantOK {
			t.Errorf("replicaTimestamp(%q) ok=%v, want %v", c.name, ok, c.wantOK)
		}
		err := checkAutoPromoteReplicaAge(c.name, now)
		if (err != nil) != c.wantErr {
			t.Errorf("checkAutoPromoteReplicaAge(%q) err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
		// An unreadable stamp is refused BY NAME, not by the accident that a
		// zero time.Time is ancient. A later change that returned `now` on a
		// parse failure would otherwise open the hole with every test green.
		if !c.wantOK && (err == nil || !strings.Contains(err.Error(), "cannot read a timestamp")) {
			t.Errorf("checkAutoPromoteReplicaAge(%q) = %v; an unreadable stamp must be refused as unreadable", c.name, err)
		}
	}
}
